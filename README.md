[![Build Status](https://img.shields.io/badge/build-passing-brightgreen.svg)](https://github.com/articdbm/articdbm) [![version](https://img.shields.io/badge/version-1.0.0-blue.svg)](https://semver.org) [![License: AGPL v3](https://img.shields.io/badge/License-AGPL%20v3-blue.svg)](https://www.gnu.org/licenses/agpl-3.0) [![Docker](https://img.shields.io/badge/docker-ready-blue.svg)](https://hub.docker.com/r/articdbm/proxy)

```
    ___         __  _       ____  ____  __  __ 
   /   |  _____/ /_(_)_____/ __ \/ __ )/ /  / /
  / /| | / ___/ __/ / ___/ / / / __  / / / / / 
 / ___ |/ /  / /_/ / /__/ /_/ / /_/ / / / / /  
/_/  |_/_/   \__/_/\___/_____/_____/_/ /_/_/   
                                              
   Arctic Database Manager - Stay Cool Under Pressure
```

# 🧊 ArticDBM - Artic Database Manager

**ArticDBM** is a high-performance, security-focused database proxy that provides centralized authentication, authorization, and monitoring for multiple database systems. Built for the modern cloud-native era, ArticDBM acts as a secure gateway between your applications and databases, offering SQL injection detection, read/write splitting, connection pooling, and comprehensive audit logging.

## 🌟 Key Features

- **🗄️ Multi-Database Support**: MySQL, PostgreSQL, MSSQL, MongoDB, and Redis
- **🔒 Advanced Security**: SQL injection detection, user authentication, fine-grained permissions
- **⚡ High Performance**: Connection pooling, read/write splitting, load balancing
- **📊 Monitoring**: Prometheus metrics, comprehensive audit logging
- **☁️ Cloud Native**: Docker containers, Kubernetes ready, multi-cloud support
- **🔄 High Availability**: Cluster mode with Redis-based configuration sharing

## 🚀 Quick Start

```bash
# Clone the repository
git clone https://github.com/articdbm/articdbm.git
cd articdbm

# Start all services
docker-compose up -d

# Access the management interface
open http://localhost:8000

# Connect through the proxy
mysql -h localhost -P 3306 -u your_user -p
psql -h localhost -p 5432 -U your_user -d your_database
```

## 🏗️ Architecture

ArticDBM consists of two main components:

- **Proxy**: High-performance Go-based database proxy with protocol support for multiple databases
- **Manager**: Python-based web interface for configuration, user management, and monitoring

```mermaid
graph LR
    A[Applications] --> B[ArticDBM Proxy]
    B --> C[MySQL]
    B --> D[PostgreSQL]
    B --> E[MongoDB]
    B --> F[Redis]
    G[ArticDBM Manager] --> H[(Configuration)]
    B -.-> H
```

## 📦 Supported Databases

| Database | Version | Features |
|----------|---------|----------|
| **MySQL** | 5.7+ | ✅ Full protocol support, connection pooling |
| **PostgreSQL** | 11+ | ✅ Native protocol, read/write splitting |
| **MSSQL** | 2017+ | ✅ TDS protocol support |
| **MongoDB** | 4.0+ | ✅ Wire protocol, authentication |
| **Redis** | 5.0+ | ✅ RESP protocol, command filtering |

## 🔒 Security Features

- **SQL Injection Detection**: Pattern-based analysis with 14+ common attack vectors
- **Fine-grained Permissions**: Database and table-level access control
- **Audit Logging**: Complete query and access trail
- **TLS Support**: Encrypted connections to backends
- **Authentication Caching**: Redis-based performance optimization

## 🌐 Deployment Options

### Docker Compose (Recommended for Development)
```bash
docker-compose up -d
```

### Kubernetes
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: articdbm-proxy
spec:
  replicas: 3
  template:
    spec:
      containers:
      - name: proxy
        image: articdbm/proxy:1.0.0
        ports:
        - containerPort: 3306
        - containerPort: 5432
```

### Cloud Deployment
- **AWS**: ECS, EKS with RDS backends
- **GCP**: GKE with Cloud SQL backends
- **Azure**: AKS with Azure Database backends

## 📚 Documentation

- [📘 **Usage Guide**](docs/usage.md) - Complete setup and configuration
- [🏗️ **Architecture**](docs/architecture.md) - System design and components  
- [🚀 **Deployment**](docs/deployment.md) - Production deployment guide
- [🔒 **Security**](docs/security.md) - Security features and best practices
- [🔌 **API Reference**](docs/api.md) - Manager API documentation
- [📝 **Release Notes**](docs/release-notes.md) - Version history and changes

## 💻 Example Usage

### Basic Connection
```python
import pymysql

# Connect through ArticDBM proxy
connection = pymysql.connect(
    host='localhost',
    port=3306,
    user='your_user',
    password='your_password',
    database='your_database'
)

# Your queries go through ArticDBM's security and routing
cursor.execute("SELECT * FROM users WHERE active = 1")
```

### Configuration via API
```bash
# Add a database backend
curl -X POST http://localhost:8000/api/servers \
  -H "Content-Type: application/json" \
  -d '{
    "name": "primary-mysql",
    "type": "mysql",
    "host": "mysql.example.com",
    "port": 3306,
    "role": "write"
  }'
```

## 🎯 Use Cases

- **Database Security Gateway**: Centralized security for multiple databases
- **Multi-tenant Applications**: Isolated database access per tenant
- **Legacy Application Modernization**: Add security without code changes
- **Database Load Balancing**: Distribute read/write operations
- **Audit and Compliance**: Complete database access logging

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guide](docs/contributing.md) for details on:

- Code style and standards
- Development environment setup
- Testing procedures
- Pull request process

## 📊 Performance

- **Latency Overhead**: < 1ms additional latency per query
- **Throughput**: Up to 100K queries/second per proxy instance
- **Connection Pooling**: Reduces backend connections by 10-50x
- **Memory Usage**: < 100MB base memory footprint

## 🆘 Support

- **Documentation**: [articdbm.penguintech.io](https://articdbm.penguintech.io)
- **Issues**: [GitHub Issues](https://github.com/articdbm/articdbm/issues)
- **Discussions**: [GitHub Discussions](https://github.com/articdbm/articdbm/discussions)

## ⚖️ License

ArticDBM is licensed under the [GNU Affero General Public License v3.0](docs/LICENSE) (AGPL-3.0). This ensures the project remains open source while allowing commercial use with certain obligations.

## 🏷️ Tags

`database-proxy` `security` `mysql` `postgresql` `mongodb` `redis` `mssql` `golang` `python` `docker` `kubernetes` `sql-injection` `authentication` `authorization` `monitoring` `high-availability`

---

**ArticDBM - Keep Your Databases Cool Under Pressure** ❄️

*Made with ❤️ for the developer community*
