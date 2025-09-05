# Welcome to ArticDBM

**Arctic Database Manager - Stay Cool Under Pressure** ❄️

ArticDBM is a high-performance, security-focused database proxy that sits between your applications and database servers, providing authentication, authorization, connection pooling, and advanced security features.

## 🎯 Key Features

- **Multi-Database Support**: MySQL, PostgreSQL, MSSQL, MongoDB, Redis
- **Advanced Security**: SQL injection detection, threat intelligence integration, TLS encryption
- **Enterprise Authentication**: API keys, temporary access, IP whitelisting, rate limiting
- **Threat Intelligence**: STIX/TAXII feeds, OpenIOC support, MISP integration
- **High Performance**: Optimized connection pooling, read/write splitting, warmup
- **User Management**: Enhanced web-based administration with granular permissions
- **MSP Ready**: Multi-tenant support, usage-based billing, white-label capabilities
- **Cloud Native**: Docker containers, Kubernetes deployments, horizontal scaling
- **Monitoring**: Prometheus metrics, comprehensive audit logging, usage tracking

## 🚀 Quick Start

Get ArticDBM running in minutes with Docker Compose:

```bash
# Clone the repository
git clone https://github.com/penguintechinc/articdbm.git
cd articdbm

# Start all services
docker-compose up -d

# Access the management interface
open http://localhost:8000
```

## 📖 Documentation

- **[Usage Guide](USAGE.md)** - Complete installation and configuration guide
- **[Architecture](ARCHITECTURE.md)** - System design and component overview
- **[User Management](USER-MANAGEMENT.md)** - Enhanced authentication, API keys, and security controls
- **[Threat Intelligence](THREAT-INTELLIGENCE.md)** - STIX/TAXII feeds, MISP integration, and threat blocking
- **[API Reference](API_REFERENCE.md)** - Complete REST API documentation
- **[Kubernetes Deployment](KUBERNETES.md)** - Production deployment guide
- **[Cloudflare Setup](CLOUDFLARE-SETUP.md)** - Web hosting and CDN configuration

## 🏗️ Architecture

ArticDBM consists of two main components:

### 🔌 Proxy Server (Go)
- High-performance database protocol translation
- Connection pooling and load balancing
- Security policy enforcement
- Multi-protocol support (MySQL, PostgreSQL, etc.)

### 🎛️ Management Interface (Python)
- Web-based administration dashboard
- User and permission management
- Database server configuration
- Monitoring and analytics

## 🔒 Security First

ArticDBM is built with enterprise-grade security as a top priority:

- **Advanced SQL Injection Protection** - 40+ attack patterns with real-time threat prevention
- **Threat Intelligence Integration** - STIX/TAXII feeds, OpenIOC support, MISP integration
- **Multi-Factor Authentication** - API keys, temporary tokens, username/password combinations
- **Enhanced Access Control** - IP whitelisting, TLS enforcement, rate limiting, account expiration
- **Comprehensive Audit Logging** - Complete query and access logging with security event tracking
- **Per-User Security Policies** - Granular permissions with time limits and usage quotas
- **Network Security** - Advanced firewall integration and CIDR-based access control

## 📊 Performance

Designed for high-throughput environments:

- **Connection Pooling** - Efficient database connection management
- **Read/Write Splitting** - Automatic query routing to replicas
- **Intelligent Caching** - Redis-backed configuration and query caching
- **Load Balancing** - Weighted distribution across backend servers
- **Horizontal Scaling** - Multi-instance cluster support

## 🌐 Multi-Database Support

Connect to multiple database types through a single proxy:

| Database | Protocol | Features |
|----------|----------|----------|
| MySQL | Native | Full compatibility, read/write splitting |
| PostgreSQL | Native | Complete protocol support, connection pooling |
| MSSQL | TDS | Enterprise features, authentication |
| MongoDB | Wire Protocol | Document queries, aggregation pipeline |
| Redis | RESP | Caching, pub/sub, cluster support |

## 🛠️ Use Cases

Perfect for:

- **Microservices Architecture** - Centralized database access control
- **Multi-Tenant Applications** - Isolated database access per tenant
- **Legacy System Integration** - Secure proxy for older applications  
- **Compliance & Auditing** - Complete query logging and monitoring
- **Development & Testing** - Safe database access for dev teams

## 🤝 Contributing

We welcome contributions! See our [Contributing Guide](CONTRIBUTING.md) for details on:

- Code contributions and pull requests
- Bug reports and feature requests  
- Documentation improvements
- Community guidelines

## 📜 License

ArticDBM is released under the [AGPL-3.0 License](LICENSE.md), ensuring it remains free and open source.

---

**Ready to get started?** Check out our [Usage Guide](USAGE.md) or jump straight into the [Quick Start](#quick-start) above!