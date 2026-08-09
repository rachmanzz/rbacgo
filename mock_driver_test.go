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

func TestSQLStoreListRolesMockErrors(t *testing.T) {
	ctx := context.Background()

	t.Run("list query error", func(t *testing.T) {
		s := newMockSQLStore(mockStep{queryErr: errTest})
		if _, err := s.ListRoles(ctx); !errors.Is(err, errTest) {
			t.Fatalf("ListRoles = %v, want query error", err)
		}
	})

	t.Run("name scan error", func(t *testing.T) {
		s := newMockSQLStore(mockStep{cols: 3, rows: 1, val: "x"})
		if _, err := s.ListRoles(ctx); err == nil {
			t.Error("expected scan error")
		}
	})

	t.Run("rows iteration error", func(t *testing.T) {
		s := newMockSQLStore(mockStep{cols: 1, rows: 1, stepErr: errTest})
		if _, err := s.ListRoles(ctx); !errors.Is(err, errTest) {
			t.Fatalf("ListRoles = %v, want rows iteration error", err)
		}
	})

	t.Run("perms query error", func(t *testing.T) {
		s := newMockSQLStore(
			mockStep{cols: 1, rows: 1, val: "r"},
			mockStep{queryErr: errTest},
		)
		if _, err := s.ListRoles(ctx); !errors.Is(err, errTest) {
			t.Fatalf("ListRoles = %v, want perms query error", err)
		}
	})

	t.Run("perms scan error", func(t *testing.T) {
		s := newMockSQLStore(
			mockStep{cols: 1, rows: 1, val: "r"},
			mockStep{cols: 2, rows: 1, val: "x"},
		)
		if _, err := s.ListRoles(ctx); err == nil {
			t.Error("expected perms scan error")
		}
	})

	t.Run("perms iteration error", func(t *testing.T) {
		s := newMockSQLStore(
			mockStep{cols: 1, rows: 1, val: "r"},
			mockStep{cols: 3, rows: 1, stepErr: errTest},
		)
		if _, err := s.ListRoles(ctx); !errors.Is(err, errTest) {
			t.Fatalf("ListRoles = %v, want perms iteration error", err)
		}
	})

	t.Run("parents query error", func(t *testing.T) {
		s := newMockSQLStore(
			mockStep{cols: 1, rows: 1, val: "r"},
			mockStep{cols: 3, rows: 0},
			mockStep{queryErr: errTest},
		)
		if _, err := s.ListRoles(ctx); !errors.Is(err, errTest) {
			t.Fatalf("ListRoles = %v, want parents query error", err)
		}
	})

	t.Run("parents scan error", func(t *testing.T) {
		s := newMockSQLStore(
			mockStep{cols: 1, rows: 1, val: "r"},
			mockStep{cols: 3, rows: 0},
			mockStep{cols: 3, rows: 1, val: "x"},
		)
		if _, err := s.ListRoles(ctx); err == nil {
			t.Error("expected parents scan error")
		}
	})

	t.Run("parents iteration error", func(t *testing.T) {
		s := newMockSQLStore(
			mockStep{cols: 1, rows: 1, val: "r"},
			mockStep{cols: 3, rows: 0},
			mockStep{cols: 2, rows: 1, stepErr: errTest},
		)
		if _, err := s.ListRoles(ctx); !errors.Is(err, errTest) {
			t.Fatalf("ListRoles = %v, want parents iteration error", err)
		}
	})

	t.Run("role without perms or parents", func(t *testing.T) {
		s := newMockSQLStore(
			mockStep{cols: 1, rows: 1, val: "r"},
			mockStep{cols: 3, rows: 0},
			mockStep{cols: 2, rows: 0},
		)
		roles, err := s.ListRoles(ctx)
		if err != nil || len(roles) != 1 || roles[0].Name != "r" {
			t.Fatalf("ListRoles = %v, %v; want [r]", roles, err)
		}
		if len(roles[0].Permissions) != 0 || len(roles[0].Parents) != 0 {
			t.Fatalf("role must stay empty: %+v", roles[0])
		}
	})
}

func TestSQLStoreUpdateRoleMockErrorPaths(t *testing.T) {
	ctx := context.Background()
	role := Role{Name: "r", Permissions: []Permission{{Resource: "x", Action: "y"}}, Parents: []string{"p"}}

	t.Run("invalid role", func(t *testing.T) {
		s := newMockSQLStore()
		if err := s.UpdateRole(ctx, Role{Name: ""}); !errors.Is(err, ErrInvalidRole) {
			t.Fatalf("UpdateRole = %v, want ErrInvalidRole", err)
		}
	})

	t.Run("BeginTx error", func(t *testing.T) {
		sharedMock.beginErr = errTest
		defer func() { sharedMock.beginErr = nil }()
		s := newMockSQLStore()
		if err := s.UpdateRole(ctx, role); !errors.Is(err, errTest) {
			t.Fatalf("UpdateRole = %v, want BeginTx error", err)
		}
	})

	t.Run("roleExists in-tx error", func(t *testing.T) {
		s := newMockSQLStore(mockStep{queryErr: errTest})
		if err := s.UpdateRole(ctx, role); !errors.Is(err, errTest) {
			t.Fatalf("UpdateRole = %v, want roleExists error", err)
		}
	})

	t.Run("role not found", func(t *testing.T) {
		s := newMockSQLStore(mockStep{cols: 1, rows: 1, val: int64(0)})
		if err := s.UpdateRole(ctx, role); !errors.Is(err, ErrRoleNotFound) {
			t.Fatalf("UpdateRole = %v, want ErrRoleNotFound", err)
		}
	})

	t.Run("deleteRoleParents exec error", func(t *testing.T) {
		s := newMockSQLStore(
			mockStep{cols: 1, rows: 1, val: int64(1)},
			mockStep{},
			mockStep{execErr: errTest},
		)
		if err := s.UpdateRole(ctx, role); !errors.Is(err, errTest) {
			t.Fatalf("UpdateRole = %v, want deleteRoleParents error", err)
		}
	})

	t.Run("insertPerm exec error", func(t *testing.T) {
		s := newMockSQLStore(
			mockStep{cols: 1, rows: 1, val: int64(1)},
			mockStep{},
			mockStep{},
			mockStep{execErr: errTest},
		)
		if err := s.UpdateRole(ctx, role); !errors.Is(err, errTest) {
			t.Fatalf("UpdateRole = %v, want insertPerm error", err)
		}
	})

	t.Run("parent roleExists error", func(t *testing.T) {
		s := newMockSQLStore(
			mockStep{cols: 1, rows: 1, val: int64(1)},
			mockStep{},
			mockStep{},
			mockStep{},
			mockStep{queryErr: errTest},
		)
		if err := s.UpdateRole(ctx, role); !errors.Is(err, errTest) {
			t.Fatalf("UpdateRole = %v, want parent existence error", err)
		}
	})

	t.Run("parent not found", func(t *testing.T) {
		s := newMockSQLStore(
			mockStep{cols: 1, rows: 1, val: int64(1)},
			mockStep{},
			mockStep{},
			mockStep{},
			mockStep{cols: 1, rows: 1, val: int64(0)},
		)
		if err := s.UpdateRole(ctx, role); !errors.Is(err, ErrParentNotFound) {
			t.Fatalf("UpdateRole = %v, want ErrParentNotFound", err)
		}
	})

	t.Run("insertParent exec error", func(t *testing.T) {
		s := newMockSQLStore(
			mockStep{cols: 1, rows: 1, val: int64(1)},
			mockStep{},
			mockStep{},
			mockStep{},
			mockStep{cols: 1, rows: 1, val: int64(1)},
			mockStep{execErr: errTest},
		)
		if err := s.UpdateRole(ctx, role); !errors.Is(err, errTest) {
			t.Fatalf("UpdateRole = %v, want insertParent error", err)
		}
	})

	t.Run("checkCycles error", func(t *testing.T) {
		s := newMockSQLStore(
			mockStep{cols: 1, rows: 1, val: int64(1)},
			mockStep{},
			mockStep{},
			mockStep{},
			mockStep{cols: 1, rows: 1, val: int64(1)},
			mockStep{},
			mockStep{queryErr: errTest},
		)
		if err := s.UpdateRole(ctx, role); !errors.Is(err, errTest) {
			t.Fatalf("UpdateRole = %v, want checkCycles error", err)
		}
	})
}

func TestSQLStoreCheckCyclesDetectsCycle(t *testing.T) {
	ctx := context.Background()
	s := &sqlStore{sql: buildQueries(dialectSQLite, "")}
	// The recursive CTE resolves the whole parent graph in one query and
	// reports the count of ancestors equal to the role itself: count 1 means
	// "a is reachable from a" (cycle).
	db := mockDB(
		mockStep{cols: 1, rows: 1, val: int64(1)},
	)
	if err := s.checkCycles(ctx, db, "a"); !errors.Is(err, ErrCycleDetected) {
		t.Fatalf("checkCycles = %v, want ErrCycleDetected", err)
	}
	// count 0 means acyclic.
	db = mockDB(
		mockStep{cols: 1, rows: 1, val: int64(0)},
	)
	if err := s.checkCycles(ctx, db, "a"); err != nil {
		t.Fatalf("checkCycles = %v, want nil", err)
	}
}
