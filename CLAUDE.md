# 🤖 CLAUDE.md - ArticDBM Context

This document provides context and information for Claude Code when working with the ArticDBM project.

## 📋 Project Overview

**ArticDBM (Arctic Database Manager)** is a comprehensive enterprise-grade database proxy solution that provides:

- **Multi-database support**: MySQL, PostgreSQL, MSSQL, MongoDB, Redis
- **Advanced Security**: SQL injection detection, threat intelligence integration, authentication, authorization  
- **Performance**: Optimized connection pooling, read/write splitting, load balancing, warmup
- **Enterprise Auth**: API keys, temporary access tokens, IP whitelisting, rate limiting, TLS enforcement
- **Threat Intelligence**: STIX/TAXII feeds, OpenIOC support, MISP integration, real-time blocking
- **Monitoring**: Prometheus metrics, comprehensive audit logging, usage tracking
- **High availability**: Cluster mode with shared configuration
- **MSP Ready**: Multi-tenant support, usage-based billing, white-label capabilities

## 🏗️ Project Structure

```
ArticDBM/
├── proxy/                    # Go-based database proxy
│   ├── main.go              # Main proxy application
│   ├── internal/            # Internal packages
│   │   ├── config/          # Configuration management
│   │   ├── handlers/        # Database protocol handlers
│   │   ├── security/        # SQL injection detection
│   │   ├── auth/            # Authentication/authorization
│   │   ├── metrics/         # Prometheus metrics
│   │   └── pool/            # Connection pooling
│   ├── Dockerfile           # Proxy container
│   └── go.mod              # Go dependencies
├── manager/                 # Python py4web manager
│   ├── app.py              # Main manager application
│   ├── requirements.txt    # Python dependencies
│   └── Dockerfile          # Manager container
├── docs/                   # Documentation
│   ├── index.md           # Documentation homepage (lowercase exception)
│   ├── USAGE.md           # Usage guide  
│   ├── ARCHITECTURE.md    # Architecture details
│   ├── THREAT-INTELLIGENCE.md  # Threat intelligence guide
│   ├── USER-MANAGEMENT.md # Enhanced user management
│   ├── API_REFERENCE.md   # API documentation
│   ├── RELEASE-NOTES.md   # Release notes
│   └── ...
├── website/               # Website for Cloudflare Pages
├── docker-compose.yml     # Development environment
├── README.md             # Project readme
├── .TODO                 # Project requirements (original)
└── CLAUDE.md            # This file
```

## 🔧 Technology Stack

### Proxy (Go)
- **Language**: Go 1.23.x (latest patch version)
- **Database Drivers**: 
  - MySQL: `github.com/go-sql-driver/mysql`
  - PostgreSQL: `github.com/lib/pq`
  - MSSQL: `github.com/denisenkom/go-mssqldb`
  - MongoDB: `go.mongodb.org/mongo-driver`
- **Redis**: `github.com/go-redis/redis/v8`
- **Config**: `github.com/spf13/viper`
- **Logging**: `go.uber.org/zap`
- **Metrics**: `github.com/prometheus/client_golang`

### Manager (Python)
- **Framework**: py4web
- **Database**: PyDAL with PostgreSQL backend
- **Cache**: Redis via `redis` and `aioredis`
- **API**: RESTful endpoints with JSON
- **Auth**: py4web built-in authentication

### Infrastructure
- **Containers**: Docker with multi-stage builds
- **Orchestration**: docker-compose for development
- **Cache/Config**: Redis
- **Database**: PostgreSQL for manager data

## 🚀 Development Workflow

### Building and Testing
```bash
# Start development environment
docker-compose up -d

# Build proxy separately
cd proxy && go build -o articdbm-proxy .

# Run manager separately  
cd manager && python -m py4web run /app

# Run tests (when implemented)
go test ./...
```

### Code Style
- **Go**: Standard Go formatting with `gofmt`
- **Python**: PEP 8 compliant
- **No comments** unless explicitly requested
- **Security-first**: Always validate inputs, use prepared statements

### Documentation Naming Convention
- **All docs**: Use UPPERCASE.md pattern (e.g., `USER-MANAGEMENT.md`, `THREAT-INTELLIGENCE.md`)
- **Exception**: `index.md` remains lowercase as the documentation homepage
- **Consistency**: This pattern applies to all `.md` files in `/docs/` directory

## 🔒 Enhanced Security Features

### SQL Injection Detection
- Pattern-based detection in `proxy/internal/security/checker.go`
- 40+ attack patterns including SQL injection, shell commands, and default resource blocking
- Real-time threat prevention with detailed analysis
- Configurable security rules via manager

### Threat Intelligence Integration
- **STIX/TAXII Feeds**: Industry-standard threat intelligence formats
- **OpenIOC Support**: XML-based indicators of compromise
- **MISP Integration**: Real-time threat intelligence platform integration
- **Per-Database Security Policies**: Configurable threat response per database
- **Advanced Threat Detection**: Pattern matching with confidence scoring
- **Threat Intelligence Bypass Rules**: Custom override capabilities

### Enhanced Authentication/Authorization
- **Multi-Factor Authentication**: Username/password + API keys + temporary tokens
- **API Key Management**: 32-byte cryptographically secure tokens for programmatic access
- **Temporary Access**: One-time tokens with automatic expiration and usage limits
- **Per-User Security Controls**: TLS enforcement, IP whitelisting, rate limiting
- **Account Expiration**: Time-limited access with automatic cleanup
- **Permission Granularity**: Database, table, and action-level permissions with time limits
- **Usage Tracking**: Query counts, connection monitoring, security event logging

### Advanced Access Control
- **IP Whitelisting**: CIDR and individual IP access control
- **TLS Per-User**: Force encrypted connections for sensitive accounts
- **Rate Limiting**: Configurable requests per second per user
- **Time-Limited Permissions**: Automatic permission expiration
- **Query Quotas**: Maximum queries per hour per database

## 📊 Monitoring & Metrics

### Prometheus Metrics
Available at `:9090/metrics`:
- `articdbm_active_connections` - Active connection count
- `articdbm_total_queries` - Total queries processed  
- `articdbm_query_duration_seconds` - Query execution time
- `articdbm_auth_failures_total` - Authentication failures
- `articdbm_sql_injection_attempts_total` - Blocked injections

### Audit Logging
- All queries logged to `audit_log` table
- User activity tracking
- IP address recording

## 🔄 Configuration Management

### Environment Variables (Proxy)
Key variables in `proxy/internal/config/config.go`:
- `REDIS_ADDR` - Redis connection
- `MYSQL_ENABLED`, `MYSQL_PORT` - MySQL proxy settings
- `SQL_INJECTION_DETECTION` - Enable security checks
- `MAX_CONNECTIONS` - Connection pool size
- `TLS_ENABLED`, `TLS_CERT`, `TLS_KEY` - TLS configuration

### Dynamic Configuration
- Configuration stored in PostgreSQL via manager
- Synced to Redis every 45-75 seconds
- No proxy restart required for most changes

## 🐛 Common Issues & Solutions

### Connection Issues
- Check port bindings in docker-compose
- Verify backend database connectivity
- Review firewall rules

### Performance Issues  
- Monitor connection pool utilization
- Check backend database performance
- Review query patterns in audit logs

### Security Issues
- Review SQL injection patterns
- Check user permissions
- Monitor authentication failures

## 📝 Testing Approach

### Unit Tests (To Be Implemented)
- Go tests for proxy components
- Python tests for manager API
- Mock database connections

### Integration Tests
- Full docker-compose stack testing
- Database protocol testing
- Security feature validation

### Performance Tests
- Load testing with `mysqlslap`, `pgbench`
- Connection pool testing
- Latency measurements

## ⚡ Performance Optimizations

### Enhanced Connection Pooling
- **Optimized Pool Settings**: 80% idle connections (vs 50%) for faster reuse
- **Connection Warmup**: Pre-establishes 30% of max connections on startup
- **Smart Lifecycle Management**: 3-minute connection lifetime, 60-second idle timeout
- **Context-Aware Timeouts**: 5-second connection timeout prevents hanging

### Load Balancing & Routing
- **Atomic Round-Robin**: Thread-safe backend selection with minimal overhead
- **Read/Write Splitting**: Automatic query routing based on operation type
- **Backend Health Monitoring**: Automatic failover with health checks
- **Connection Locality**: CPU-optimized connection distribution

### Hot Path Optimizations
- **String Optimization**: Replaced `fmt.Sprintf` with direct concatenation
- **Buffer Pool Reuse**: Recycled buffers for reduced GC pressure
- **Cache Efficiency**: Redis-based auth caching with 5-minute TTL
- **Reduced Allocations**: Minimized memory allocations in critical paths

## 🏢 MSP & Enterprise Capabilities

### Multi-Tenant Architecture
- **Customer Isolation**: Separate API keys, rate limits, and database permissions per tenant
- **Usage-Based Billing**: Query quotas and rate limits for tiered pricing models
- **White-Label Support**: Remove ArticDBM branding, embed in customer applications
- **Compliance Ready**: IP restrictions, TLS enforcement, audit trails for regulated industries

### Revenue Opportunities
- **Database-as-a-Service**: Offer secure managed databases at $50-200/month per customer
- **High Margins**: 70%+ profit margins with automated security and management
- **Premium Features**: Threat intelligence, advanced security, priority support
- **Scalable Business Model**: Multi-tenant SaaS with recurring revenue potential

### Operational Efficiency
- **Automated Provisioning**: API-driven user and database creation
- **Temporary Access**: One-time tokens for contractors and audits
- **Security Automation**: Threat intelligence feeds with automatic blocking
- **Usage Monitoring**: Comprehensive tracking for billing and compliance

## 🚀 Deployment Patterns

### Development
- docker-compose with all services
- Local PostgreSQL and Redis
- Test databases included

### Production
- Kubernetes deployment
- External managed databases (RDS, Cloud SQL)
- Redis cluster for HA
- Load balancer for proxy instances

## 🔮 Future Enhancements

### Planned Features
- Query caching layer
- Enhanced MongoDB support
- GraphQL API support
- Machine learning-based anomaly detection

### Technical Debt
- Add comprehensive unit tests
- Implement graceful shutdown
- Add configuration validation
- Improve error handling

## 💡 Development Tips

### When Working with Proxy
- Always check Redis connection first
- Use structured logging with zap
- Handle database disconnections gracefully
- Monitor connection pool stats

### When Working with Manager
- Use PyDAL for database operations
- Cache frequently accessed data in Redis
- Validate all API inputs
- Use py4web authentication

### When Adding New Database Support
1. Add protocol handler in `proxy/internal/handlers/`
2. Update configuration in `config.go`
3. Add Docker service for testing
4. Update documentation

## 🎯 Key Files to Know

### Critical Files
- `proxy/main.go` - Main proxy entry point
- `proxy/internal/config/config.go` - Configuration management
- `manager/app.py` - Manager API and UI
- `docker-compose.yml` - Development environment

### Configuration Files
- `proxy/go.mod` - Go dependencies
- `manager/requirements.txt` - Python dependencies
- `.TODO` - Original requirements (keep updated)

### Documentation
- `README.md` - Main project documentation
- `docs/` - Comprehensive documentation suite

## 🏃‍♂️ Quick Commands

```bash
# Full stack restart
docker-compose down && docker-compose up -d

# View logs
docker-compose logs -f proxy
docker-compose logs -f manager

# Connect to test databases
mysql -h localhost -P 3307 -u testuser -p  # Direct to test MySQL
mysql -h localhost -P 3306 -u testuser -p  # Through proxy

# Check proxy metrics
curl http://localhost:9090/metrics

# Access manager API
curl http://localhost:8000/api/health
```

---

*This document should be updated as the project evolves. Keep it current with any architectural changes or new features.*