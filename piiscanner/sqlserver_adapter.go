package piiscanner

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	"github.com/klouddb/dpdpa_pii_db_scanner/pkg/sqlserverdb"
	"github.com/klouddb/dpdpa_pii_db_scanner/pkg/utils"
)

type SQLServerAdapter struct {
	cfg    sqlserverdb.SQLServer
	schema string
	db     *sql.DB
}

func NewSQLServerAdapter(cfg sqlserverdb.SQLServer, schema string) *SQLServerAdapter {
	if schema == "" {
		schema = "dbo"
	}
	return &SQLServerAdapter{cfg: cfg, schema: schema}
}

func (a *SQLServerAdapter) Schema() string {
	return a.schema
}

func (a *SQLServerAdapter) Connect(ctx context.Context) error {
	db, err := sqlserverdb.Open(a.cfg)
	if err != nil {
		return err
	}
	a.db = db
	return nil
}

func (a *SQLServerAdapter) Close() error {
	if a.db == nil {
		return nil
	}
	return a.db.Close()
}

func (a *SQLServerAdapter) ListTables(ctx context.Context) ([]TableRef, error) {
	var schemaCount int
	err := a.db.QueryRowContext(ctx, fmt.Sprintf(
		"SELECT COUNT(*) FROM information_schema.schemata WHERE schema_name = '%s'", a.schema)).Scan(&schemaCount)
	if err != nil {
		return nil, err
	}
	if schemaCount == 0 {
		return nil, fmt.Errorf("schema %s does not exist", a.schema)
	}

	names, err := utils.GetListFromQuery(ctx, a.db, fmt.Sprintf(
		"SELECT table_name FROM information_schema.tables WHERE table_type = 'BASE TABLE' AND table_schema = '%s'",
		a.schema))
	if err != nil {
		return nil, err
	}

	tables := make([]TableRef, len(names))
	for i, name := range names {
		tables[i] = TableRef{Schema: a.schema, Name: name}
	}
	return tables, nil
}

func (a *SQLServerAdapter) quotedName(table TableRef) string {
	return fmt.Sprintf("[%s].[%s]", table.Schema, table.Name)
}

func (a *SQLServerAdapter) ListColumns(ctx context.Context, table TableRef) ([]string, error) {
	stmt, err := a.db.PrepareContext(ctx, fmt.Sprintf(`SELECT TOP 0 * FROM %s`, a.quotedName(table)))
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

func (a *SQLServerAdapter) RowCount(ctx context.Context, table TableRef) (int, error) {
	return utils.TableRowCount(ctx, a.db, a.quotedName(table))
}

func (a *SQLServerAdapter) StreamValues(ctx context.Context, table TableRef, columns []string, opts SampleOptions, onRowScanned func(), cb RowCallback) error {
	quotedTable := a.quotedName(table)
	quotedColumns := make([]string, len(columns))
	for i, c := range columns {
		quotedColumns[i] = fmt.Sprintf("[%s]", c)
	}
	columnList := strings.Join(quotedColumns, ",")

	query := fmt.Sprintf(`SELECT %s FROM %s`, columnList, quotedTable)
	if opts.Mode == SampleMode_Limited {
		query = fmt.Sprintf(`SELECT TOP %d %s FROM %s TABLESAMPLE (%d ROWS) REPEATABLE (%d)`,
			opts.Size, columnList, quotedTable, opts.Size, opts.Seed)
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