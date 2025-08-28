# 📘 ArticDBM Usage Guide

This guide covers installation, configuration, and usage of ArticDBM.

## 📦 Installation

### Docker Compose (Recommended)

```bash
# Clone repository
git clone https://github.com/articdbm/articdbm.git
cd articdbm

# Start services
docker-compose up -d

# Check status
docker-compose ps
```

### Kubernetes

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: articdbm-proxy
spec:
  replicas: 3
  selector:
    matchLabels:
      app: articdbm-proxy
  template:
    metadata:
      labels:
        app: articdbm-proxy
    spec:
      containers:
      - name: proxy
        image: articdbm/proxy:latest
        env:
        - name: REDIS_ADDR
          value: "redis-service:6379"
        ports:
        - containerPort: 3306
        - containerPort: 5432
```

## ⚙️ Configuration

### Environment Variables

#### Proxy Configuration

| Variable | Description | Default |
|----------|-------------|---------|
| `REDIS_ADDR` | Redis connection string | `localhost:6379` |
| `MYSQL_ENABLED` | Enable MySQL proxy | `true` |
| `MYSQL_PORT` | MySQL proxy port | `3306` |
| `POSTGRESQL_ENABLED` | Enable PostgreSQL proxy | `true` |
| `POSTGRESQL_PORT` | PostgreSQL proxy port | `5432` |
| `SQL_INJECTION_DETECTION` | Enable SQL injection detection | `true` |
| `MAX_CONNECTIONS` | Maximum connections per backend | `1000` |
| `TLS_ENABLED` | Enable TLS support | `false` |
| `CLUSTER_MODE` | Enable cluster mode | `false` |

#### Manager Configuration

| Variable | Description | Default |
|----------|-------------|---------|
| `DATABASE_URL` | PostgreSQL connection string | `postgresql://articdbm:articdbm@postgres/articdbm` |
| `REDIS_HOST` | Redis host | `redis` |
| `REDIS_PORT` | Redis port | `6379` |
| `SESSION_SECRET` | Session encryption key | Auto-generated |

## 👥 User Management

### Creating Users

1. Access the manager UI: `http://localhost:8000`
2. Navigate to **Users** → **Add User**
3. Fill in user details:
   - Email (username)
   - Password
   - Enable/disable status

### Managing Permissions

Permissions control database and table access:

```json
{
  "user_id": "john@example.com",
  "database": "production_db",
  "table": "users",
  "actions": ["read", "write"]
}
```

#### Permission Levels

- **Database**: `*` for all databases or specific database name
- **Table**: `*` for all tables or specific table name
- **Actions**: 
  - `read`: SELECT queries
  - `write`: INSERT, UPDATE, DELETE
  - `*`: All operations

## 🗄️ Database Backend Configuration

### Adding Database Servers

Via API:
```bash
curl -X POST http://localhost:8000/api/servers \
  -H "Content-Type: application/json" \
  -d '{
    "name": "mysql-primary",
    "type": "mysql",
    "host": "192.168.1.10",
    "port": 3306,
    "username": "root",
    "password": "secret",
    "database": "myapp",
    "role": "write",
    "weight": 1,
    "tls_enabled": false
  }'
```

### Read/Write Splitting

Configure multiple backends with different roles:

```yaml
backends:
  - name: mysql-primary
    role: write
    host: primary.example.com
  - name: mysql-replica-1
    role: read
    host: replica1.example.com
    weight: 2
  - name: mysql-replica-2
    role: read
    host: replica2.example.com
    weight: 1
```

## 🔒 Security Configuration

### SQL Injection Detection

Enable pattern-based detection:

```bash
SQL_INJECTION_DETECTION=true
```

Add custom security rules via the manager:

```json
{
  "name": "block-drop-table",
  "pattern": "(?i)drop\\s+table",
  "action": "block",
  "severity": "critical"
}
```

### TLS Configuration

Enable TLS for proxy connections:

```bash
TLS_ENABLED=true
TLS_CERT=/path/to/cert.pem
TLS_KEY=/path/to/key.pem
```

## 📊 Monitoring

### Prometheus Metrics

Metrics available at `http://localhost:9090/metrics`:

- `articdbm_active_connections` - Active connection count
- `articdbm_total_queries` - Total queries processed
- `articdbm_query_duration_seconds` - Query execution time
- `articdbm_auth_failures_total` - Authentication failures
- `articdbm_sql_injection_attempts_total` - Blocked SQL injections

### Grafana Dashboard

Import the provided dashboard:

```json
{
  "dashboard": {
    "title": "ArticDBM Monitoring",
    "panels": [
      {
        "title": "Query Rate",
        "targets": [
          {
            "expr": "rate(articdbm_total_queries[5m])"
          }
        ]
      }
    ]
  }
}
```

## 🔄 High Availability

### Cluster Mode

Enable cluster mode for multiple proxy instances:

```bash
CLUSTER_MODE=true
CLUSTER_REDIS_ADDR=redis-cluster:6379
```

### Load Balancing

Use a network load balancer:

```nginx
upstream articdbm_mysql {
    server proxy1:3306;
    server proxy2:3306;
    server proxy3:3306;
}
```

## 🧪 Testing

### Connection Test

MySQL:
```bash
mysql -h localhost -P 3306 -u testuser -p
> SHOW DATABASES;
```

PostgreSQL:
```bash
psql -h localhost -p 5432 -U testuser -d testdb
\l
```

### Performance Test

```bash
# MySQL benchmark
mysqlslap --host=localhost --port=3306 \
  --user=testuser --password=testpass \
  --concurrency=50 --iterations=100 \
  --auto-generate-sql

# PostgreSQL benchmark
pgbench -h localhost -p 5432 -U testuser \
  -c 10 -j 2 -t 1000 testdb
```

## 🐛 Troubleshooting

### Common Issues

#### Connection Refused
- Check if proxy is running: `docker ps`
- Verify port bindings: `netstat -tlnp`
- Check firewall rules

#### Authentication Failed
- Verify user exists in manager
- Check permissions for database/table
- Review audit logs

#### Slow Queries
- Check backend server performance
- Review connection pool settings
- Enable query caching

### Debug Mode

Enable debug logging:

```bash
LOG_LEVEL=debug
```

View logs:
```bash
docker-compose logs -f proxy
docker-compose logs -f manager
```

## 📝 Examples

### Python Connection

```python
import pymysql

connection = pymysql.connect(
    host='localhost',
    port=3306,
    user='app_user',
    password='secret',
    database='myapp'
)

with connection.cursor() as cursor:
    cursor.execute("SELECT * FROM users")
    results = cursor.fetchall()
```

### Node.js Connection

```javascript
const mysql = require('mysql2');

const connection = mysql.createConnection({
  host: 'localhost',
  port: 3306,
  user: 'app_user',
  password: 'secret',
  database: 'myapp'
});

connection.query('SELECT * FROM users', (err, results) => {
  console.log(results);
});
```

### Go Connection

```go
import (
    "database/sql"
    _ "github.com/go-sql-driver/mysql"
)

db, err := sql.Open("mysql", "app_user:secret@tcp(localhost:3306)/myapp")
if err != nil {
    panic(err)
}
defer db.Close()

rows, err := db.Query("SELECT * FROM users")
```

---
*For more information, see the [Architecture Guide](architecture.md) or [API Reference](api.md).*