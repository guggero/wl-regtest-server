// Package store persists regtest protocol state in SQLite.
package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	_ "modernc.org/sqlite"
)

// Store holds an atomically replaced protocol snapshot. The small regtest
// workload favors a single transaction boundary over cross-table coordination.
// Callers serialize mutations and retain signed transcripts in the snapshot.
type Store struct {
	db *sql.DB
}

// Open creates or reopens the snapshot database at path. Newly created
// directories and files are private because the snapshot contains signing seed
// material. The caller owns Close; mutations must be serialized by the caller.
func Open(path string) (*Store, error) {
	// Create the file with restrictive permissions before SQLite opens it,
	// rather than relying on the process umask to protect signing material.
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, fmt.Errorf("create data directory: %w", err)
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, fmt.Errorf("open state file: %w", err)
	}
	if err := f.Close(); err != nil {
		return nil, err
	}

	// A single connection keeps connection-local SQLite settings
	// consistent. WAL with FULL synchronization makes an acknowledged
	// snapshot durable before the server exposes signatures or updates its
	// mailbox readers.
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	_, err = db.Exec(
		`PRAGMA journal_mode=WAL;
PRAGMA synchronous=FULL;
PRAGMA busy_timeout=5000;
CREATE TABLE IF NOT EXISTS protocol_state (
 id INTEGER PRIMARY KEY CHECK (id = 1),
 version INTEGER NOT NULL,
 payload BLOB NOT NULL
);`,
	)
	if err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("initialize state database: %w", err)
	}
	return &Store{db: db}, nil
}

// Load returns the last committed snapshot, or nil for a fresh database.
func (s *Store) Load(ctx context.Context) ([]byte, error) {
	var version int
	var payload []byte
	err := s.db.QueryRowContext(
		ctx, "SELECT version, payload FROM protocol_state WHERE id = 1",
	).Scan(&version, &payload)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	// Schema interpretation is part of recovery. Refuse an unknown version
	// instead of decoding signing transcripts under the wrong assumptions.
	if version != 1 {
		return nil, fmt.Errorf("unsupported state schema %d", version)
	}
	return payload, nil
}

// Save atomically commits a complete snapshot before any associated response
// or signing artifact may be released to a client.
func (s *Store) Save(ctx context.Context, payload []byte) error {
	_, err := s.db.ExecContext(
		ctx,
		`INSERT INTO protocol_state
 (id, version, payload) VALUES (1, 1, ?)
 ON CONFLICT(id) DO UPDATE SET payload = excluded.payload`,
		payload,
	)
	return err
}

// Close releases the database connection after its workers have stopped.
func (s *Store) Close() error {
	return s.db.Close()
}
