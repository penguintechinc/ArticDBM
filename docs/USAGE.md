
# 📖 ArticDBM Usage Guide

This comprehensive guide covers installation, configuration, and usage of ArticDBM in various environments.

## Table of Contents

- [📖 ArticDBM Usage Guide](#-articdbm-usage-guide)
  - [Table of Contents](#table-of-contents)
  - [🚀 Quick Start](#-quick-start)
  - [📦 Installation Methods](#-installation-methods)
  - [⚙️ Configuration](#️-configuration)
  - [🔧 Management Interface](#-management-interface)
  - [💻 Database Connections](#-database-connections)
  - [🔒 User Management](#-user-management)
  - [📊 Monitoring](#-monitoring)
  - [🧪 Examples](#-examples)
  - [🛠️ Troubleshooting](#️-troubleshooting)

## 🚀 Quick Start

The fastest way to get ArticDBM running is using Docker Compose:

```bash
# Clone the repository
git clone https://github.com/your-org/articdbm.git
cd articdbm

# Start all services
docker-compose up -d

# Check service status
docker-compose ps

# View logs
docker-compose logs -f
```

Access the management interface at [http://localhost:8000](http://localhost:8000)

## 📦 Installation Methods

### 🐳 Docker Compose (Recommended)

Docker Compose provides the easiest deployment with all dependencies included:

```yaml
# docker-compose.yml
version: '3.8'

services:
  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"
    volumes:
      - redis-data:/data

  postgres:
    image: postgres:15-alpine
    environment:
      POSTGRES_USER: articdbm
      POSTGRES_PASSWORD: articdbm
      POSTGRES_DB: articdbm
    volumes:
      - postgres-data:/var/lib/postgresql/data

  manager:
    image: articdbm/manager:latest
    ports:
      - "8000:8000"
    environment:
      DATABASE_URL: postgresql://articdbm:articdbm@postgres/articdbm
      REDIS_HOST: redis
    depends_on:
      - redis
      - postgres

  proxy:
    image: articdbm/proxy:latest
    ports:
      - "3306:3306"   # MySQL
      - "5432:5432"   # PostgreSQL
      - "1433:1433"   # MSSQL
      - "27017:27017" # MongoDB
      - "6380:6380"   # Redis
    environment:
      REDIS_ADDR: redis:6379
      MYSQL_ENABLED: "true"
      POSTGRESQL_ENABLED: "true"
    depends_on:
      - redis

volumes:
  redis-data:
  postgres-data:
```

### 🐳 Docker Standalone

Run individual components using Docker:

```bash
# Start Redis for configuration cache
docker run -d --name articdbm-redis \
  -p 6379:6379 \
  redis:7-alpine

# Start PostgreSQL for manager storage
docker run -d --name articdbm-postgres \
  -p 5433:5432 \
  -e POSTGRES_USER=articdbm \
  -e POSTGRES_PASSWORD=articdbm \
  -e POSTGRES_DB=articdbm \
  postgres:15-alpine

# Start ArticDBM Manager
docker run -d --name articdbm-manager \
  -p 8000:8000 \
  -e DATABASE_URL=postgresql://articdbm:articdbm@host.docker.internal:5433/articdbm \
  -e REDIS_HOST=host.docker.internal \
  articdbm/manager:latest

# Start ArticDBM Proxy
docker run -d --name articdbm-proxy \
  -p 3306:3306 -p 5432:5432 \
  -e REDIS_ADDR=host.docker.internal:6379 \
  -e MYSQL_ENABLED=true \
  -e POSTGRESQL_ENABLED=true \
  articdbm/proxy:latest
```

### ☸️ Kubernetes (Helm)

Deploy using Helm chart:

```bash
# Add ArticDBM Helm repository
helm repo add articdbm https://charts.articdbm.io
helm repo update

# Install with default values
helm install articdbm articdbm/articdbm

# Install with custom values
helm install articdbm articdbm/articdbm \
  --set manager.replicas=2 \
  --set proxy.mysql.enabled=true \
  --set proxy.postgresql.enabled=true
```

Example `values.yaml`:

```yaml
manager:
  image:
    repository: articdbm/manager
    tag: "1.0.0"
  replicas: 1
  service:
    type: LoadBalancer
    port: 8000

proxy:
  image:
    repository: articdbm/proxy
    tag: "1.0.0"
  replicas: 2
  mysql:
    enabled: true
    port: 3306
  postgresql:
    enabled: true
    port: 5432
  
redis:
  enabled: true
  persistence:
    enabled: true
    size: 8Gi

postgresql:
  enabled: true
  auth:
    database: articdbm
    username: articdbm
  primary:
    persistence:
      enabled: true
      size: 20Gi
```

### 🏗️ Terraform

Deploy infrastructure using Terraform:

```hcl
# main.tf
module "articdbm" {
  source = "./modules/articdbm"
  
  # AWS Configuration
  vpc_id            = var.vpc_id
  subnet_ids        = var.subnet_ids
  availability_zones = var.availability_zones
  
  # Database Configuration
  postgres_instance_class = "db.t3.medium"
  redis_node_type        = "cache.t3.medium"
  
  # Security
  allowed_cidr_blocks = ["10.0.0.0/8"]
  
  # Scaling
  manager_desired_count = 2
  proxy_desired_count   = 3
  
  tags = {
    Environment = "production"
    Project     = "articdbm"
  }
}
```

## ⚙️ Configuration

### Environment Variables

#### Manager Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `DATABASE_URL` | - | PostgreSQL connection string for manager storage |
| `REDIS_HOST` | `redis` | Redis hostname for configuration cache |
| `REDIS_PORT` | `6379` | Redis port |
| `REDIS_PASSWORD` | - | Redis authentication password |
| `SESSION_SECRET` | Auto-generated | Secret key for session management |

#### Proxy Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `REDIS_ADDR` | `redis:6379` | Redis connection address |
| `MYSQL_ENABLED` | `false` | Enable MySQL proxy |
| `MYSQL_PORT` | `3306` | MySQL proxy listening port |
| `POSTGRESQL_ENABLED` | `false` | Enable PostgreSQL proxy |
| `POSTGRESQL_PORT` | `5432` | PostgreSQL proxy listening port |
| `MSSQL_ENABLED` | `false` | Enable MSSQL proxy |
| `MSSQL_PORT` | `1433` | MSSQL proxy listening port |
| `MONGODB_ENABLED` | `false` | Enable MongoDB proxy |
| `MONGODB_PORT` | `27017` | MongoDB proxy listening port |
| `REDIS_PROXY_ENABLED` | `false` | Enable Redis proxy |
| `REDIS_PROXY_PORT` | `6380` | Redis proxy listening port |
| `SQL_INJECTION_DETECTION` | `true` | Enable SQL injection detection |
| `MAX_CONNECTIONS` | `1000` | Maximum concurrent connections |
| `METRICS_PORT` | `9090` | Prometheus metrics port |

### Configuration Files

#### Manager Configuration (`manager/config.yaml`)

```yaml
database:
  url: "postgresql://user:pass@localhost/articdbm"
  max_connections: 20
  migration: true

redis:
  host: "localhost"
  port: 6379
  password: ""
  db: 0

auth:
  session_secret: "your-secret-key"
  session_timeout: 3600

security:
  cors_origins: ["*"]
  rate_limiting:
    enabled: true
    requests_per_minute: 100

logging:
  level: "info"
  format: "json"
```

#### Proxy Configuration (`proxy/config.yaml`)

```yaml
redis:
  addr: "localhost:6379"
  password: ""
  db: 0

protocols:
  mysql:
    enabled: true
    port: 3306
    max_connections: 100
  postgresql:
    enabled: true
    port: 5432
    max_connections: 100
  mssql:
    enabled: false
    port: 1433
    max_connections: 50

security:
  sql_injection_detection: true
  query_timeout: 30s
  max_query_length: 10485760  # 10MB

metrics:
  enabled: true
  port: 9090
  path: "/metrics"

logging:
  level: "info"
  format: "json"
```

## 🔧 Management Interface

### Web Dashboard

Access the management interface at `http://localhost:8000` after startup.

#### Login Credentials

Default admin user is created on first startup:
- **Username**: `admin@articdbm.local`
- **Password**: Check container logs for generated password

```bash
# View generated admin password
docker-compose logs manager | grep "Admin password"
```

#### Dashboard Features

1. **🏠 Dashboard**: System overview and statistics
2. **🖥️ Servers**: Manage database backend servers
3. **👥 Users**: User management and authentication
4. **🔐 Permissions**: Configure user database permissions
5. **🛡️ Security**: Manage security rules and patterns
6. **📊 Monitoring**: View metrics and audit logs
7. **⚙️ Configuration**: System settings and preferences

### CLI Management

ArticDBM provides a CLI tool for management operations:

```bash
# Install CLI tool
pip install articdbm-cli

# Configure connection
articdbm config set --url http://localhost:8000 --token your-api-token

# List database servers
articdbm servers list

# Add a new database server
articdbm servers add \
  --name "production-mysql" \
  --type mysql \
  --host "prod-mysql.company.com" \
  --port 3306 \
  --username "app_user" \
  --password "secure_password" \
  --database "app_db"

# Create user and permissions
articdbm users create \
  --email "developer@company.com" \
  --password "temp_password"

articdbm permissions add \
  --user "developer@company.com" \
  --database "app_db" \
  --actions "read,write"
```

## 💻 Database Connections

### MySQL Applications

```python
# Python with MySQL Connector
import mysql.connector

connection = mysql.connector.connect(
    host='localhost',
    port=3306,  # ArticDBM MySQL proxy
    user='your_user',
    password='your_password',
    database='your_database'
)
```

```javascript
// Node.js with MySQL2
const mysql = require('mysql2/promise');

const connection = await mysql.createConnection({
  host: 'localhost',
  port: 3306,  // ArticDBM MySQL proxy
  user: 'your_user',
  password: 'your_password',
  database: 'your_database'
});
```

### PostgreSQL Applications

```python
# Python with psycopg2
import psycopg2

connection = psycopg2.connect(
    host="localhost",
    port=5432,  # ArticDBM PostgreSQL proxy
    user="your_user",
    password="your_password",
    database="your_database"
)
```

```go
// Go with pq driver
import (
    "database/sql"
    _ "github.com/lib/pq"
)

db, err := sql.Open("postgres", 
    "host=localhost port=5432 user=your_user password=your_password dbname=your_database sslmode=disable")
```

### MongoDB Applications

```python
# Python with PyMongo
from pymongo import MongoClient

client = MongoClient('mongodb://your_user:your_password@localhost:27017/your_database')
db = client.your_database
```

```javascript
// Node.js with MongoDB driver
const { MongoClient } = require('mongodb');

const client = new MongoClient('mongodb://your_user:your_password@localhost:27017/your_database');
await client.connect();
```

## 🔒 User Management

### Creating Users

#### Via Web Interface
1. Navigate to **Users** section
2. Click **Add User**
3. Fill in user details:
   - Email address (used as username)
   - Password
   - Role (Admin, Developer, Reporter)
4. Click **Create User**

#### Via API
```bash
curl -X POST http://localhost:8000/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@company.com",
    "password": "secure_password"
  }'
```

### Managing Permissions

#### Database Access Permissions
```bash
# Grant read access to specific database
curl -X POST http://localhost:8000/api/permissions \
  -H "Authorization: Bearer your-token" \
  -H "Content-Type: application/json" \
  -d '{
    "user_id": 1,
    "database_name": "app_database",
    "table_name": "*",
    "actions": ["read"]
  }'

# Grant write access to specific table
curl -X POST http://localhost:8000/api/permissions \
  -H "Authorization: Bearer your-token" \
  -H "Content-Type: application/json" \
  -d '{
    "user_id": 1,
    "database_name": "app_database",
    "table_name": "users",
    "actions": ["read", "write"]
  }'
```

### Role-Based Access Control (RBAC)

ArticDBM supports three built-in roles:

1. **👑 Administrator**
   - Full system access
   - Can manage all users and permissions
   - Can configure database servers
   - Can view all audit logs

2. **👨‍💻 Developer** 
   - Can manage their own database connections
   - Can view their own queries in audit logs
   - Cannot modify other users' permissions

3. **📊 Reporter**
   - Read-only access to assigned databases
   - Cannot modify data or structure
   - Limited audit log visibility

## 📊 Monitoring

### Prometheus Metrics

ArticDBM exposes Prometheus metrics at `http://localhost:9090/metrics`:

```bash
# View available metrics
curl http://localhost:9090/metrics
```

Key metrics include:
- `articdbm_connections_active`: Active database connections
- `articdbm_queries_total`: Total queries processed
- `articdbm_queries_duration`: Query execution time
- `articdbm_security_violations_total`: Security rule violations
- `articdbm_errors_total`: Error counts by type

### Grafana Dashboard

Import the provided Grafana dashboard for visualization:

```bash
# Import dashboard
curl -X POST http://grafana:3000/api/dashboards/db \
  -H "Content-Type: application/json" \
  -d @grafana-dashboard.json
```

### Health Checks

```bash
# Manager health check
curl http://localhost:8000/api/health

# Proxy health check  
curl http://localhost:9090/health
```

### Audit Logging

All database operations are logged for security and compliance:

```bash
# View audit logs via API
curl -H "Authorization: Bearer your-token" \
  "http://localhost:8000/api/audit-log?limit=50&offset=0"
```

Audit log entries include:
- User ID and username
- Database and table accessed
- SQL query executed
- Execution result
- Timestamp and IP address

## 🧪 Examples

### Complete Setup Example

Here's a complete example of setting up ArticDBM with a MySQL backend:

```bash
# 1. Start ArticDBM
docker-compose up -d

# 2. Wait for services to be ready
sleep 30

# 3. Add a MySQL backend server
curl -X POST http://localhost:8000/api/servers \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer admin-token" \
  -d '{
    "name": "production-mysql",
    "type": "mysql",
    "host": "prod-mysql.company.com",
    "port": 3306,
    "username": "app_user",
    "password": "app_password",
    "database": "app_database",
    "role": "both",
    "weight": 1,
    "tls_enabled": true
  }'

# 4. Create a user
curl -X POST http://localhost:8000/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "developer@company.com",
    "password": "dev_password"
  }'

# 5. Grant permissions
curl -X POST http://localhost:8000/api/permissions \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer admin-token" \
  -d '{
    "user_id": 2,
    "database_name": "app_database",
    "table_name": "*",
    "actions": ["read", "write"]
  }'

# 6. Test connection
mysql -h localhost -P 3306 -u developer@company.com -p
```

### Multi-Database Setup

Example configuration with multiple database types:

```yaml
# docker-compose.override.yml
version: '3.8'

services:
  proxy:
    environment:
      MYSQL_ENABLED: "true"
      POSTGRESQL_ENABLED: "true"
      MONGODB_ENABLED: "true"
      REDIS_PROXY_ENABLED: "true"
      
      # Backend configurations
      MYSQL_BACKENDS: |
        [
          {"host":"mysql-primary","port":3306,"type":"write","weight":1},
          {"host":"mysql-replica-1","port":3306,"type":"read","weight":1},
          {"host":"mysql-replica-2","port":3306,"type":"read","weight":1}
        ]
      
      POSTGRESQL_BACKENDS: |
        [
          {"host":"postgres-primary","port":5432,"type":"write","weight":1},
          {"host":"postgres-replica","port":5432,"type":"read","weight":1}
        ]
```

### Security Configuration Example

```bash
# Add SQL injection detection rule
curl -X POST http://localhost:8000/api/security-rules \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer admin-token" \
  -d '{
    "name": "Detect UNION attacks",
    "pattern": "(?i)(\\bunion\\b.*\\bselect\\b|\\bselect\\b.*\\bunion\\b)",
    "action": "block",
    "severity": "high",
    "active": true
  }'

# Add suspicious query detection
curl -X POST http://localhost:8000/api/security-rules \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer admin-token" \
  -d '{
    "name": "Detect suspicious OR conditions",
    "pattern": "(?i)(\\bor\\b\\s*\\d+\\s*=\\s*\\d+|\\band\\b\\s*\\d+\\s*=\\s*\\d+)",
    "action": "alert",
    "severity": "medium",
    "active": true
  }'
```

## 🛠️ Troubleshooting

### Common Issues

#### Connection Refused Errors

```bash
# Check if services are running
docker-compose ps

# Check service logs
docker-compose logs manager
docker-compose logs proxy
```

#### Authentication Problems

```bash
# Reset admin password
docker-compose exec manager python -c "
from app import db, auth
user = db(db.auth_user.email == 'admin@articdbm.local').select().first()
if user:
    user.update_record(password=auth.get_secure_password_store().get('password', 'new_password'))
    print('Password reset to: new_password')
"
```

#### Database Connection Issues

1. **Check backend database connectivity**:
```bash
# Test MySQL backend
docker-compose exec proxy nc -zv mysql-backend 3306

# Test PostgreSQL backend  
docker-compose exec proxy nc -zv postgres-backend 5432
```

2. **Verify credentials in Redis**:
```bash
# Check stored configuration
docker-compose exec redis redis-cli GET "articdbm:backends"
```

#### Performance Issues

1. **Check connection pool settings**:
```bash
# View current connection statistics
curl http://localhost:9090/metrics | grep articdbm_connections
```

2. **Adjust connection limits**:
```yaml
# docker-compose.override.yml
services:
  proxy:
    environment:
      MAX_CONNECTIONS: "2000"  # Increase if needed
```

#### Memory Usage

```bash
# Check memory usage
docker stats

# Adjust memory limits
docker-compose up -d --scale proxy=2  # Scale horizontally
```

### Debug Mode

Enable debug logging for troubleshooting:

```yaml
# docker-compose.override.yml
services:
  manager:
    environment:
      LOG_LEVEL: "debug"
  
  proxy:
    environment:
      LOG_LEVEL: "debug"
```

### Getting Support

1. **📖 Check the documentation** - Most issues are covered in our guides
2. **🔍 Search existing issues** - Someone may have had the same problem
3. **📊 Collect diagnostic information**:
```bash
# Generate diagnostic report
curl -H "Authorization: Bearer admin-token" \
  http://localhost:8000/api/stats > diagnostics.json
```
4. **🐛 Open an issue** with diagnostic information and logs

---

For more advanced configuration and deployment scenarios, see the [Deployment Guide](./deployment.md).
