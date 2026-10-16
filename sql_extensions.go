package rbacgo

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

type SQLDialect string

const (
	SQLDialectSQLite   SQLDialect = "sqlite"
	SQLDialectPostgres SQLDialect = "postgres"
	SQLDialectMySQL    SQLDialect = "mysql"
)

// WithSQLDialect explicitly selects SQL syntax. MySQL 8+ requires this option;
// SQLite/PostgreSQL retain automatic detection. MySQL uses InnoDB and exact
// VARBINARY keys up to 768 bytes to fit composite index limits.
func WithSQLDialect(d SQLDialect) SQLStoreOption {
	return func(s *sqlStore) error {
		switch d {
		case SQLDialectSQLite:
			s.dialect = dialectSQLite
		case SQLDialectPostgres:
			s.dialect = dialectPostgres
		case SQLDialectMySQL:
			s.dialect = dialectMySQL
		default:
			return fmt.Errorf("rbacgo: unsupported SQL dialect %q", d)
		}
		return nil
	}
}

func (s *sqlStore) executor() querrer {
	if s.tx != nil {
		return s.tx
	}
	return s.db
}

func (s *sqlStore) beginWrite(ctx context.Context) (*sql.Tx, bool, error) {
	if s.tx != nil {
		return s.tx, false, nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, false, err
	}
	// Serialize writers across pools/processes sharing these tables. Locking
	// only the edited role cannot protect cycle checks across disjoint roles,
	// or a role's sidecar data against concurrent deletion. SQLite already
	// serializes writers (conflicting snapshots fail rather than commit).
	if s.dialect != dialectSQLite {
		key := "key"
		upsert := " ON CONFLICT DO NOTHING"
		if s.dialect == dialectMySQL {
			key = "`key`"
			upsert = " ON DUPLICATE KEY UPDATE value = value"
		}
		table := s.tablePrefix + "meta"
		_, err = tx.ExecContext(ctx, "INSERT INTO "+table+" ("+key+", value) VALUES ('mutation_lock', 1)"+upsert)
		if err == nil {
			var value uint64
			err = tx.QueryRowContext(ctx, "SELECT value FROM "+table+" WHERE "+key+" = 'mutation_lock' FOR UPDATE").Scan(&value)
		}
		if err != nil {
			_ = tx.Rollback()
			return nil, false, err
		}
	}
	return tx, true, nil
}
func rollbackOwned(tx *sql.Tx, owned bool) {
	if owned {
		_ = tx.Rollback()
	}
}
func commitOwned(tx *sql.Tx, owned bool) error {
	if owned {
		return tx.Commit()
	}
	return nil
}

func (s *sqlStore) ApplyPolicyBatch(ctx context.Context, batch PolicyBatch) error {
	if err := validateBatch(batch); err != nil {
		return err
	}
	tx, owned, err := s.beginWrite(ctx)
	if err != nil {
		return err
	}
	defer rollbackOwned(tx, owned)
	work := *s
	work.tx = tx
	if err := applyBatch(ctx, &work, batch); err != nil {
		return err
	}
	return commitOwned(tx, owned)
}

func (s *sqlStore) setRoleDetail(ctx context.Context, kind, name string, value any) error {
	payload, err := json.Marshal(value)
	if err != nil {
		return err
	}
	tx, owned, err := s.beginWrite(ctx)
	if err != nil {
		return err
	}
	defer rollbackOwned(tx, owned)
	exists, err := s.roleExists(ctx, tx, name)
	if err != nil {
		return err
	}
	if !exists {
		return ErrRoleNotFound
	}
	table := s.tablePrefix + kind
	query := "INSERT INTO " + table + " (role_name, payload) VALUES (" + s.ph(1) + ", " + s.ph(2) + ") ON CONFLICT(role_name) DO UPDATE SET payload = excluded.payload"
	if s.dialect == dialectMySQL {
		query = "INSERT INTO " + table + " (role_name, payload) VALUES (?, ?) ON DUPLICATE KEY UPDATE payload = ?"
		_, err = tx.ExecContext(ctx, query, name, string(payload), string(payload))
	} else {
		_, err = tx.ExecContext(ctx, query, name, string(payload))
	}
	if err != nil {
		return err
	}
	return commitOwned(tx, owned)
}

func (s *sqlStore) roleDetail(ctx context.Context, kind, name string, out any) error {
	exists, err := s.roleExists(ctx, s.executor(), name)
	if err != nil {
		return err
	}
	if !exists {
		return ErrRoleNotFound
	}
	var payload string
	err = s.executor().QueryRowContext(ctx, "SELECT payload FROM "+s.tablePrefix+kind+" WHERE role_name = "+s.ph(1), name).Scan(&payload)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	decoder := json.NewDecoder(strings.NewReader(payload))
	decoder.UseNumber()
	return decoder.Decode(out)
}

func (s *sqlStore) SetRoleRules(ctx context.Context, name string, rules []PolicyRule) error {
	if err := validateRules(rules); err != nil {
		return err
	}
	return s.setRoleDetail(ctx, "role_rules", name, rules)
}
func (s *sqlStore) GetRoleRules(ctx context.Context, name string) ([]PolicyRule, error) {
	var rules []PolicyRule
	if err := s.roleDetail(ctx, "role_rules", name, &rules); err != nil {
		return nil, err
	}
	if err := validateRules(rules); err != nil {
		return nil, err
	}
	return rules, nil
}
func (s *sqlStore) SetRoleMetadata(ctx context.Context, name string, metadata map[string]string) error {
	return s.setRoleDetail(ctx, "role_metadata", name, metadata)
}
func (s *sqlStore) GetRoleMetadata(ctx context.Context, name string) (map[string]string, error) {
	metadata := make(map[string]string)
	err := s.roleDetail(ctx, "role_metadata", name, &metadata)
	if metadata == nil {
		metadata = make(map[string]string)
	}
	return metadata, err
}
