package auth

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/articdbm/proxy/internal/config"
	"github.com/go-redis/redis/v8"
	"go.uber.org/zap"
)

type Manager struct {
	cfg    *config.Config
	redis  *redis.Client
	logger *zap.Logger
}

func NewManager(cfg *config.Config, redis *redis.Client, logger *zap.Logger) *Manager {
	return &Manager{
		cfg:    cfg,
		redis:  redis,
		logger: logger,
	}
}

func (m *Manager) Authenticate(ctx context.Context, username, database, dbType string) bool {
	cacheKey := fmt.Sprintf("articdbm:auth:%s:%s:%s", dbType, username, database)
	
	cached, err := m.redis.Get(ctx, cacheKey).Result()
	if err == nil {
		return cached == "allowed"
	}

	user, ok := m.cfg.GetUser(username)
	if !ok || !user.Enabled {
		m.cacheAuthResult(ctx, cacheKey, false)
		return false
	}

	perm, ok := m.cfg.GetPermission(username)
	if !ok {
		m.cacheAuthResult(ctx, cacheKey, false)
		return false
	}

	if perm.Database != "*" && perm.Database != database {
		m.cacheAuthResult(ctx, cacheKey, false)
		return false
	}

	m.cacheAuthResult(ctx, cacheKey, true)
	return true
}

func (m *Manager) Authorize(ctx context.Context, username, database, table string, isWrite bool) bool {
	cacheKey := fmt.Sprintf("articdbm:authz:%s:%s:%s:%t", username, database, table, isWrite)
	
	cached, err := m.redis.Get(ctx, cacheKey).Result()
	if err == nil {
		return cached == "allowed"
	}

	perm, ok := m.cfg.GetPermission(username)
	if !ok {
		m.cacheAuthResult(ctx, cacheKey, false)
		return false
	}

	if perm.Database != "*" && perm.Database != database {
		m.cacheAuthResult(ctx, cacheKey, false)
		return false
	}

	if table != "" && perm.Table != "*" && perm.Table != table {
		m.cacheAuthResult(ctx, cacheKey, false)
		return false
	}

	action := "read"
	if isWrite {
		action = "write"
	}

	for _, allowedAction := range perm.Actions {
		if allowedAction == action || allowedAction == "*" {
			m.cacheAuthResult(ctx, cacheKey, true)
			return true
		}
	}

	m.cacheAuthResult(ctx, cacheKey, false)
	return false
}

func (m *Manager) cacheAuthResult(ctx context.Context, key string, allowed bool) {
	value := "denied"
	if allowed {
		value = "allowed"
	}
	
	m.redis.Set(ctx, key, value, 5*time.Minute)
}

func (m *Manager) HashPassword(password string) string {
	hash := sha256.Sum256([]byte(password))
	return hex.EncodeToString(hash[:])
}

func (m *Manager) ValidatePassword(username, password string) bool {
	user, ok := m.cfg.GetUser(username)
	if !ok {
		return false
	}

	return user.PasswordHash == m.HashPassword(password)
}

func (m *Manager) SyncUsersFromManager(ctx context.Context) error {
	usersData, err := m.redis.Get(ctx, "articdbm:manager:users").Result()
	if err != nil {
		return err
	}

	var users map[string]*config.User
	if err := json.Unmarshal([]byte(usersData), &users); err != nil {
		return err
	}

	m.cfg.Users = users
	m.logger.Info("Synced users from manager", zap.Int("count", len(users)))
	
	return nil
}

func (m *Manager) SyncPermissionsFromManager(ctx context.Context) error {
	permsData, err := m.redis.Get(ctx, "articdbm:manager:permissions").Result()
	if err != nil {
		return err
	}

	var perms map[string]*config.Permission
	if err := json.Unmarshal([]byte(permsData), &perms); err != nil {
		return err
	}

	m.cfg.Permissions = perms
	m.logger.Info("Synced permissions from manager", zap.Int("count", len(perms)))
	
	return nil
}