package pool

import (
	"context"
	"database/sql"
	"sync"
	"time"
)

type ConnectionPool struct {
	driver   string
	dsn      string
	db       *sql.DB
	maxConns int
	mu       sync.RWMutex
}

func NewConnectionPool(driver, dsn string, maxConns int) *ConnectionPool {
	db, err := sql.Open(driver, dsn)
	if err != nil {
		return nil
	}

	db.SetMaxOpenConns(maxConns)
	db.SetMaxIdleConns(maxConns / 2)
	db.SetConnMaxLifetime(5 * time.Minute)
	db.SetConnMaxIdleTime(30 * time.Second)

	return &ConnectionPool{
		driver:   driver,
		dsn:      dsn,
		db:       db,
		maxConns: maxConns,
	}
}

func (p *ConnectionPool) Get() (*sql.Conn, error) {
	ctx := context.Background()
	return p.db.Conn(ctx)
}

func (p *ConnectionPool) Close() error {
	return p.db.Close()
}

func (p *ConnectionPool) Stats() sql.DBStats {
	return p.db.Stats()
}

func (p *ConnectionPool) Ping() error {
	return p.db.Ping()
}