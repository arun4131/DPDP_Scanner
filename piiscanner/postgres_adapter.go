package piiscanner

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	"github.com/klouddb/dpdpa_pii_db_scanner/pkg/postgresdb"
	"github.com/klouddb/dpdpa_pii_db_scanner/pkg/utils"
)

// PostgresAdapter implements DBAdapter for PostgreSQL. It owns the *sql.DB
// connection privately — nothing outside this file touches database/sql
// for Postgres anymore.
type PostgresAdapter struct {
	cfg    postgresdb.Postgres
	schema string
	db     *sql.DB
}

func NewPostgresAdapter(cfg postgresdb.Postgres, schema string) *PostgresAdapter {
	if schema == "" {
		schema = "public"
	}
	return &PostgresAdapter{cfg: cfg, schema: schema}
}

// NewPostgresAdapterFromDB wraps an already-open connection — e.g. one opened
// directly from a postgres:// URI, where OpenURI intentionally connects with
// the raw URI string as-is rather than rebuilding it from discrete fields —
// instead of dialing a fresh one in Connect.
func NewPostgresAdapterFromDB(db *sql.DB, schema string) *PostgresAdapter {
	if schema == "" {
		schema = "public"
	}
	return &PostgresAdapter{db: db, schema: schema}
}

func (a *PostgresAdapter) Schema() string {
	return a.schema
}

func (a *PostgresAdapter) Connect(ctx context.Context) error {
	if a.db != nil {
		return nil
	}
	db, _, err := postgresdb.Open(a.cfg)
	if err != nil {
		return err
	}
	a.db = db
	return nil
}

func (a *PostgresAdapter) Close() error {
	if a.db == nil {
		return nil
	}
	return a.db.Close()
}

func (a *PostgresAdapter) ListTables(ctx context.Context) ([]TableRef, error) {
	exists, err := utils.SchemaExists(ctx, a.db, a.schema)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, fmt.Errorf("schema %s does not exist", a.schema)
	}

	names, err := utils.GetListFromQuery(ctx, a.db,
		"SELECT table_name FROM information_schema.tables WHERE table_type='BASE TABLE' AND table_schema = '"+a.schema+"'")
	if err != nil {
		return nil, err
	}

	tables := make([]TableRef, len(names))
	for i, name := range names {
		tables[i] = TableRef{Schema: a.schema, Name: name}
	}
	return tables, nil
}

func (a *PostgresAdapter) quotedName(table TableRef) string {
	return fmt.Sprintf("%q.%q", table.Schema, table.Name)
}

func (a *PostgresAdapter) ListColumns(ctx context.Context, table TableRef) ([]string, error) {
	stmt, err := a.db.PrepareContext(ctx, fmt.Sprintf(`SELECT * FROM %s LIMIT 0`, a.quotedName(table)))
	if err != nil {
		return nil, fmt.Errorf("error preparing statement: %v", err)
	}
	defer stmt.Close()

	rows, err := stmt.QueryContext(ctx)
	if err != nil {
		return nil, fmt.Errorf("error executing query: %v", err)
	}
	defer rows.Close()

	columns, err := rows.Columns()
	if err != nil {
		return nil, fmt.Errorf("error getting columns: %v", err)
	}
	return columns, nil
}

func (a *PostgresAdapter) RowCount(ctx context.Context, table TableRef) (int, error) {
	return utils.TableRowCount(ctx, a.db, a.quotedName(table))
}

func (a *PostgresAdapter) StreamValues(ctx context.Context, table TableRef, columns []string, opts SampleOptions, onRowScanned func(), cb RowCallback) error {
	quotedTable := a.quotedName(table)

	query := fmt.Sprintf(`SELECT "%s" FROM %s`, strings.Join(columns, `","`), quotedTable)
	if opts.Mode == SampleMode_Limited {
		query = fmt.Sprintf(`SELECT "%s" FROM %s TABLESAMPLE BERNOULLI (10) REPEATABLE (%d) LIMIT %d`,
			strings.Join(columns, `","`), quotedTable, opts.Seed, opts.Size)
	}

	stmt, err := a.db.PrepareContext(ctx, query)
	if err != nil {
		return fmt.Errorf("error preparing statement: %v query:(%s)", err, query)
	}
	defer stmt.Close()

	rows, err := stmt.QueryContext(ctx)
	if err != nil {
		return fmt.Errorf("error executing query: %v", err)
	}
	defer rows.Close()

	count := len(columns)

	for rows.Next() {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if onRowScanned != nil {
			onRowScanned()
		}

		values := make([]interface{}, count)
		scanArgs := make([]interface{}, count)
		for i := range values {
			scanArgs[i] = &values[i]
		}

		if err := rows.Scan(scanArgs...); err != nil {
			return fmt.Errorf("error scanning row: %v", err)
		}

		for i := range values {
			val := GetValuesString(values[i])
			if val == "" || val == "NULL" || val == "<nil>" {
				continue
			}
			if err := cb(columns[i], val); err != nil {
				return err
			}
		}
	}

	return rows.Err()
}
