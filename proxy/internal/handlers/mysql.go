package handlers

import (
	"context"
	"database/sql"
	"fmt"
	"net"
	"sync"
	"sync/atomic"

	"github.com/articdbm/proxy/internal/auth"
	"github.com/articdbm/proxy/internal/config"
	"github.com/articdbm/proxy/internal/metrics"
	"github.com/articdbm/proxy/internal/pool"
	"github.com/articdbm/proxy/internal/security"
	"github.com/go-redis/redis/v8"
	_ "github.com/go-sql-driver/mysql"
	"go.uber.org/zap"
)

type MySQLHandler struct {
	cfg          *config.Config
	redis        *redis.Client
	logger       *zap.Logger
	pools        map[string]*pool.ConnectionPool
	poolMu       sync.RWMutex
	roundRobin   uint64
	authManager  *auth.Manager
	secChecker   *security.SQLChecker
}

func NewMySQLHandler(cfg *config.Config, redis *redis.Client, logger *zap.Logger) *MySQLHandler {
	return &MySQLHandler{
		cfg:         cfg,
		redis:       redis,
		logger:      logger,
		pools:       make(map[string]*pool.ConnectionPool),
		authManager: auth.NewManager(cfg, redis, logger),
		secChecker:  security.NewSQLChecker(cfg.SQLInjectionDetection),
	}
}

func (h *MySQLHandler) Start(ctx context.Context, listener net.Listener) {
	h.initPools()

	for {
		select {
		case <-ctx.Done():
			h.closePools()
			return
		default:
			conn, err := listener.Accept()
			if err != nil {
				select {
				case <-ctx.Done():
					return
				default:
					h.logger.Error("Failed to accept connection", zap.Error(err))
					continue
				}
			}

			go h.handleConnection(ctx, conn)
		}
	}
}

func (h *MySQLHandler) initPools() {
	h.poolMu.Lock()
	defer h.poolMu.Unlock()

	for _, backend := range h.cfg.MySQLBackends {
		dsn := fmt.Sprintf("%s:%s@tcp(%s:%d)/%s",
			backend.User, backend.Password, backend.Host, backend.Port, backend.Database)
		
		if backend.TLS {
			dsn += "?tls=true"
		}

		p := pool.NewConnectionPool("mysql", dsn, h.cfg.MaxConnections/len(h.cfg.MySQLBackends))
		key := fmt.Sprintf("%s:%d", backend.Host, backend.Port)
		h.pools[key] = p
	}
}

func (h *MySQLHandler) closePools() {
	h.poolMu.Lock()
	defer h.poolMu.Unlock()

	for _, p := range h.pools {
		p.Close()
	}
}

func (h *MySQLHandler) handleConnection(ctx context.Context, clientConn net.Conn) {
	defer clientConn.Close()

	metrics.IncConnection("mysql")
	defer metrics.DecConnection("mysql")

	username, database, err := h.performHandshake(clientConn)
	if err != nil {
		h.logger.Error("Handshake failed", zap.Error(err))
		return
	}

	if !h.authManager.Authenticate(ctx, username, database, "mysql") {
		h.logger.Warn("Authentication failed", 
			zap.String("user", username),
			zap.String("database", database))
		h.sendError(clientConn, "Access denied")
		return
	}

	backend := h.selectBackend(false)
	if backend == nil {
		h.logger.Error("No backend available")
		h.sendError(clientConn, "No backend available")
		return
	}

	backendConn, err := h.getBackendConnection(backend)
	if err != nil {
		h.logger.Error("Failed to connect to backend", zap.Error(err))
		h.sendError(clientConn, "Backend connection failed")
		return
	}
	defer backendConn.Close()

	h.proxyTraffic(ctx, clientConn, backendConn, username, database)
}

func (h *MySQLHandler) performHandshake(conn net.Conn) (string, string, error) {
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		return "", "", err
	}

	if n < 36 {
		return "", "", fmt.Errorf("invalid handshake packet")
	}

	username := ""
	database := ""
	
	pos := 36
	for pos < n && buf[pos] != 0 {
		username += string(buf[pos])
		pos++
	}
	pos++

	if pos < n {
		pos += 23
		for pos < n && buf[pos] != 0 {
			database += string(buf[pos])
			pos++
		}
	}

	greeting := []byte{
		0x0a, 0x35, 0x2e, 0x37, 0x2e, 0x33, 0x33, 0x00,
		0x01, 0x00, 0x00, 0x00, 0x41, 0x72, 0x74, 0x69,
		0x63, 0x44, 0x42, 0x4d, 0x00, 0x00, 0x00, 0x00,
	}
	conn.Write(greeting)

	return username, database, nil
}

func (h *MySQLHandler) sendError(conn net.Conn, message string) {
	errorPacket := []byte{
		0xff,
		0x48, 0x04,
		0x23, 0x48, 0x59, 0x30, 0x30, 0x30,
	}
	errorPacket = append(errorPacket, []byte(message)...)
	conn.Write(errorPacket)
}

func (h *MySQLHandler) selectBackend(isWrite bool) *config.Backend {
	var backends []config.Backend
	if isWrite {
		backends = h.cfg.GetWriteBackends("mysql")
	} else {
		backends = h.cfg.GetReadBackends("mysql")
	}

	if len(backends) == 0 {
		return nil
	}

	idx := atomic.AddUint64(&h.roundRobin, 1) % uint64(len(backends))
	return &backends[idx]
}

func (h *MySQLHandler) getBackendConnection(backend *config.Backend) (*sql.Conn, error) {
	key := fmt.Sprintf("%s:%d", backend.Host, backend.Port)
	
	h.poolMu.RLock()
	p, ok := h.pools[key]
	h.poolMu.RUnlock()

	if !ok {
		return nil, fmt.Errorf("pool not found for backend %s", key)
	}

	return p.Get()
}

func (h *MySQLHandler) proxyTraffic(ctx context.Context, client net.Conn, backend *sql.Conn, username, database string) {
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		buf := make([]byte, 32*1024)
		for {
			select {
			case <-ctx.Done():
				return
			default:
				n, err := client.Read(buf)
				if err != nil {
					return
				}

				query := string(buf[:n])
				if h.secChecker.IsSQLInjection(query) {
					h.logger.Warn("SQL injection detected",
						zap.String("user", username),
						zap.String("query", query))
					metrics.IncSQLInjection("mysql")
					h.sendError(client, "Query blocked by security policy")
					return
				}

				if !h.authManager.Authorize(ctx, username, database, "", h.isWriteQuery(query)) {
					h.logger.Warn("Unauthorized query",
						zap.String("user", username),
						zap.String("database", database))
					h.sendError(client, "Unauthorized")
					return
				}

				metrics.IncQuery("mysql", h.isWriteQuery(query))
			}
		}
	}()

	go func() {
		defer wg.Done()
	}()

	wg.Wait()
}

func (h *MySQLHandler) isWriteQuery(query string) bool {
	return security.IsWriteQuery(query)
}