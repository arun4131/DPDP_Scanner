package piiscanner

import "context"

// TableRef identifies one scannable unit within a data source —
// a SQL table, a Mongo collection, a Redis keyspace, etc.
// Callers treat it as an opaque handle; only the adapter that produced it
// knows how to actually query it.
type TableRef struct {
	Schema string
	Name   string
}

func (t TableRef) DisplayName() string {
	if t.Schema == "" {
		return t.Name
	}
	return t.Schema + "." + t.Name
}

// SampleMode controls how much of a table an adapter reads.
type SampleMode int

const (
	SampleMode_Full    SampleMode = iota // DeepScan: read everything
	SampleMode_Limited                   // DataScan: read up to Size rows
)

type SampleOptions struct {
	Mode SampleMode
	Size int // used only when Mode == SampleMode_Limited
	Seed int // reproducible sampling, where the engine supports it
}

// RowCallback fires once per non-empty value found while scanning a table —
// this is exactly where piiTableScanner today calls tableScanManager.PushValue.
type RowCallback func(columnName string, value string) error

// DBAdapter is the contract every supported database engine must implement.
// TableScanManager, the Detectors, and the report generator never see this
// interface directly — only the table-scanning orchestrator talks to it.
type DBAdapter interface {
	Connect(ctx context.Context) error
	Close() error

	// Schema returns the resolved schema this adapter operates against
	// (e.g. "public" for Postgres, "dbo" for SQL Server, the database
	// name for MySQL). Engines without a schema concept (Mongo, Redis)
	// return "".
	Schema() string

	// ListTables enumerates scannable units: tables, collections, etc.
	ListTables(ctx context.Context) ([]TableRef, error)

	// ListColumns enumerates column/field names for one table.
	ListColumns(ctx context.Context, table TableRef) ([]string, error)

	// RowCount estimates size, used for the DataScan-vs-DeepScan
	// auto-detect threshold. An approximation is fine.
	RowCount(ctx context.Context, table TableRef) (int, error)

	// StreamValues reads the table per opts, invoking cb once per
	// non-empty cell in every requested column.
	StreamValues(ctx context.Context, table TableRef, columns []string, opts SampleOptions, onRowScanned func(), cb RowCallback) error
}