package rbacgo

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"io"
	"sync"
	"testing"
)

// mockStep scripts one Query or Exec call on the mock driver. Query calls
// consume cols/rows/val/queryErr/stepErr; Exec calls consume execErr.
type mockStep struct {
	cols     int
	rows     int
	val      driver.Value
	execErr  error
	queryErr error
	stepErr  error
}

// mockDriver is a scripted database/sql driver used to force error paths the
// real SQLite driver cannot produce (Scan column-count mismatches, row
// iteration errors, query and transaction failures) in the SQL store's
// defensive branches.
type mockDriver struct {
	mu       sync.Mutex
	steps    []mockStep
	beginErr error
}

func (d *mockDriver) Open(string) (driver.Conn, error) { return &mockConn{d: d}, nil }

func (d *mockDriver) next() mockStep {
	d.mu.Lock()
	defer d.mu.Unlock()
	if len(d.steps) == 0 {
		return mockStep{cols: 1}
	}
	s := d.steps[0]
	if len(d.steps) > 1 {
		d.steps = d.steps[1:]
	}
	return s
}

var (
	registerMockOnce sync.Once
	sharedMock       = &mockDriver{}
)

// mockDB returns a *sql.DB backed by the scripted mock driver. Steps are
// consumed in order by successive Query/Exec calls. An empty *sql.DB{} is
// unusable (no driver connector), so the driver is opened for real.
func mockDB(steps ...mockStep) *sql.DB {
	registerMockOnce.Do(func() { sql.Register("rbacgo_mock", sharedMock) })
	sharedMock.mu.Lock()
	sharedMock.steps = append([]mockStep(nil), steps...)
	sharedMock.mu.Unlock()
	db, err := sql.Open("rbacgo_mock", "mock")
	if err != nil {
		panic(err)
	}
	return db
}

type mockConn struct{ d *mockDriver }

func (c *mockConn) Prepare(string) (driver.Stmt, error) { return &mockStmt{d: c.d}, nil }
func (c *mockConn) Close() error                        { return nil }
func (c *mockConn) Begin() (driver.Tx, error)           { return mockTx{}, c.d.beginErr }

type mockStmt struct{ d *mockDriver }

func (s *mockStmt) Close() error  { return nil }
func (s *mockStmt) NumInput() int { return -1 }
func (s *mockStmt) Exec([]driver.Value) (driver.Result, error) {
	if s.d.next().execErr != nil {
		return nil, errTest
	}
	return driver.RowsAffected(0), nil
}
func (s *mockStmt) Query([]driver.Value) (driver.Rows, error) {
	step := s.d.next()
	if step.queryErr != nil {
		return nil, step.queryErr
	}
	row := make([]driver.Value, step.cols)
	for i := range row {
		row[i] = step.val
	}
	return &mockRows{step: step, row: row}, nil
}

type mockTx struct{}

func (mockTx) Commit() error   { return nil }
func (mockTx) Rollback() error { return nil }

type mockRows struct {
	step mockStep
	row  []driver.Value
	n    int
}

func (r *mockRows) Columns() []string {
	cols := make([]string, r.step.cols)
	for i := range cols {
		cols[i] = "c"
	}
	return cols
}

func (r *mockRows) Close() error { return nil }

func (r *mockRows) Next(dest []driver.Value) error {
	if r.step.stepErr != nil {
		return r.step.stepErr
	}
	if r.n >= r.step.rows {
		return io.EOF
	}
	r.n++
	copy(dest, r.row)
	return nil
}

func newMockSQLStore(steps ...mockStep) *sqlStore {
	return &sqlStore{
		db:  mockDB(steps...),
		ph:  dialectSQLite.param,
		sql: buildQueries(dialectSQLite, ""),
	}
}

func TestSQLStoreScanErrors(t *testing.T) {
	ctx := context.Background()

	t.Run("GetRole perms scan error", func(t *testing.T) {
		s := newMockSQLStore(
			mockStep{cols: 1, rows: 1, val: int64(1)},
			mockStep{cols: 3, rows: 1, val: "x"},
		)
		if _, _, err := s.GetRole(ctx, "r"); err == nil {
			t.Error("expected scan error on permissions")
		}
	})

	t.Run("GetRole parents scan error", func(t *testing.T) {
		s := newMockSQLStore(
			mockStep{cols: 1, rows: 1, val: int64(1)},
			mockStep{cols: 2, rows: 0},
			mockStep{cols: 3, rows: 1, val: "x"},
		)
		if _, _, err := s.GetRole(ctx, "r"); err == nil {
			t.Error("expected scan error on parents")
		}
	})

	t.Run("GetRoles scan error", func(t *testing.T) {
		s := newMockSQLStore(mockStep{cols: 3, rows: 1, val: "x"})
		if _, err := s.GetRoles(ctx, "u"); err == nil {
			t.Error("expected scan error on user roles")
		}
	})
}

func TestSQLStoreRowsErr(t *testing.T) {
	ctx := context.Background()
	s := newMockSQLStore(
		mockStep{cols: 1, rows: 1, val: int64(1)},
		mockStep{cols: 2, rows: 1, stepErr: errTest},
	)
	if _, _, err := s.GetRole(ctx, "r"); !errors.Is(err, errTest) {
		t.Fatalf("GetRole = %v, want rows iteration error", err)
	}
}

func TestCheckCyclesMockErrors(t *testing.T) {
	ctx := context.Background()

	t.Run("scan error", func(t *testing.T) {
		s := &sqlStore{sql: buildQueries(dialectSQLite, "")}
		db := mockDB(mockStep{cols: 3, rows: 1, val: "x"})
		if err := s.checkCycles(ctx, db, "a"); err == nil {
			t.Error("expected scan error")
		}
	})

	t.Run("rows iteration error", func(t *testing.T) {
		s := &sqlStore{sql: buildQueries(dialectSQLite, "")}
		db := mockDB(mockStep{cols: 1, rows: 1, stepErr: errTest})
		if err := s.checkCycles(ctx, db, "a"); !errors.Is(err, errTest) {
			t.Fatalf("checkCycles = %v, want rows iteration error", err)
		}
	})
}

func TestSQLStoreAddRoleMockErrorPaths(t *testing.T) {
	ctx := context.Background()

	t.Run("parent roleExists error", func(t *testing.T) {
		s := newMockSQLStore(
			mockStep{cols: 1, rows: 1, val: int64(0)},
			mockStep{},
			mockStep{cols: 3, rows: 1, val: "x"},
		)
		if err := s.AddRole(ctx, Role{Name: "child", Parents: []string{"parent"}}); err == nil {
			t.Error("expected error checking parent existence")
		}
	})

	t.Run("checkCycles error", func(t *testing.T) {
		s := newMockSQLStore(
			mockStep{cols: 1, rows: 1, val: int64(0)},
			mockStep{},
			mockStep{},
			mockStep{cols: 1, rows: 1, val: int64(1)},
			mockStep{},
			mockStep{cols: 1, rows: 1, stepErr: errTest},
		)
		err := s.AddRole(ctx, Role{
			Name:        "child",
			Parents:     []string{"parent"},
			Permissions: []Permission{{Resource: "r", Action: "a"}},
		})
		if !errors.Is(err, errTest) {
			t.Fatalf("AddRole = %v, want checkCycles error", err)
		}
	})

	t.Run("BeginTx error", func(t *testing.T) {
		sharedMock.beginErr = errTest
		defer func() { sharedMock.beginErr = nil }()
		s := newMockSQLStore()
		if err := s.AddRole(ctx, Role{Name: "child"}); !errors.Is(err, errTest) {
			t.Fatalf("AddRole = %v, want BeginTx error", err)
		}
	})

	t.Run("roleExists in-tx error", func(t *testing.T) {
		s := newMockSQLStore(mockStep{queryErr: errTest})
		if err := s.AddRole(ctx, Role{Name: "child"}); !errors.Is(err, errTest) {
			t.Fatalf("AddRole = %v, want roleExists error inside transaction", err)
		}
	})

	t.Run("invalid role", func(t *testing.T) {
		s := newMockSQLStore()
		if err := s.AddRole(ctx, Role{Name: ""}); !errors.Is(err, ErrInvalidRole) {
			t.Fatalf("AddRole = %v, want ErrInvalidRole", err)
		}
	})
}

func TestSQLStoreGetRoleParentsQueryError(t *testing.T) {
	ctx := context.Background()
	s := newMockSQLStore(
		mockStep{cols: 1, rows: 1, val: int64(1)},
		mockStep{cols: 2, rows: 0},
		mockStep{queryErr: errTest},
	)
	if _, _, err := s.GetRole(ctx, "r"); !errors.Is(err, errTest) {
		t.Fatalf("GetRole = %v, want roleParents query error", err)
	}
}

func TestSQLStoreCheckCyclesDetectsCycle(t *testing.T) {
	ctx := context.Background()
	s := &sqlStore{sql: buildQueries(dialectSQLite, "")}
	// a -> b -> a forms a cycle: the inner visit of "a" observes it already
	// being visited, so its parent query is never issued.
	db := mockDB(
		mockStep{cols: 1, rows: 1, val: "b"},
		mockStep{cols: 1, rows: 1, val: "a"},
	)
	if err := s.checkCycles(ctx, db, "a"); !errors.Is(err, ErrCycleDetected) {
		t.Fatalf("checkCycles = %v, want ErrCycleDetected", err)
	}
}
