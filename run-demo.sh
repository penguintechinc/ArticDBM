#!/bin/bash

# ArticDBM Development Cluster Demo Runner
# This script sets up and runs the complete ArticDBM demo environment

set -e

echo "🚀 ArticDBM Development Cluster Setup"
echo "====================================="
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

print_header() {
    echo -e "${BLUE}$1${NC}"
    echo "----------------------------------------"
}

print_success() {
    echo -e "${GREEN}✅ $1${NC}"
}

print_info() {
    echo -e "${YELLOW}ℹ️  $1${NC}"
}

print_error() {
    echo -e "${RED}❌ $1${NC}"
}

# Check prerequisites
print_header "Checking Prerequisites"

# Check Docker
if ! command -v docker &> /dev/null; then
    print_error "Docker is not installed"
    exit 1
fi

# Check Docker Compose
if ! command -v docker-compose &> /dev/null; then
    print_error "Docker Compose is not installed"
    exit 1
fi

# Check available memory (16GB total for safe operation)
TOTAL_MEM=$(free -g | awk '/^Mem:/{print $2}')
if [ "$TOTAL_MEM" -lt 12 ]; then
    print_error "Insufficient memory. At least 12GB RAM recommended for full demo"
    print_info "You can continue but some services may be resource constrained"
    read -p "Continue anyway? (y/N): " continue_anyway
    if [[ ! "$continue_anyway" =~ ^[Yy]$ ]]; then
        exit 1
    fi
fi

print_success "Prerequisites check passed"
echo ""

# Create necessary directories
print_header "Creating Demo Environment"

mkdir -p test/dashboards
mkdir -p data/articdbm
chmod +x test/setup-demo-data.sh test/demo-queries.sh

# Make scripts executable
chmod +x test/*.sh

# Create missing configuration files if they don't exist
if [ ! -f test/haproxy.cfg ]; then
    print_info "Creating HAProxy configuration..."
    cat > test/haproxy.cfg << 'EOF'
global
    daemon
    log stdout local0 info
    stats socket /tmp/haproxy.sock mode 666 level admin

defaults
    mode tcp
    timeout connect 5s
    timeout client 30s
    timeout server 30s
    log global
    option tcplog
    balance roundrobin

# MySQL load balancing
frontend mysql_frontend
    bind *:3306
    default_backend mysql_backend

backend mysql_backend
    balance roundrobin
    server proxy1 proxy-dev-1:3306 check
    server proxy2 proxy-dev-2:3306 check

# PostgreSQL load balancing
frontend postgres_frontend
    bind *:5432
    default_backend postgres_backend

backend postgres_backend
    balance roundrobin
    server proxy1 proxy-dev-1:5432 check
    server proxy2 proxy-dev-2:5432 check

# MongoDB load balancing
frontend mongo_frontend
    bind *:27017
    default_backend mongo_backend

backend mongo_backend
    balance roundrobin
    server proxy1 proxy-dev-1:27017 check
    server proxy2 proxy-dev-2:27017 check

# Redis load balancing
frontend redis_frontend
    bind *:6379
    default_backend redis_backend

backend redis_backend
    balance roundrobin
    server proxy1 proxy-dev-1:6379 check
    server proxy2 proxy-dev-2:6379 check

# SQLite load balancing
frontend sqlite_frontend
    bind *:8765
    default_backend sqlite_backend

backend sqlite_backend
    balance roundrobin
    server proxy1 proxy-dev-1:8765 check
    server proxy2 proxy-dev-2:8765 check

# HAProxy statistics
frontend stats
    bind *:9090
    stats enable
    stats uri /stats
    stats refresh 30s
    stats admin if TRUE
EOF
fi

if [ ! -f test/prometheus.yml ]; then
    print_info "Creating Prometheus configuration..."
    cat > test/prometheus.yml << 'EOF'
global:
  scrape_interval: 15s
  evaluation_interval: 15s

scrape_configs:
  - job_name: 'articdbm-proxy-1'
    static_configs:
      - targets: ['proxy-dev-1:9091']
    scrape_interval: 5s
    metrics_path: /metrics

  - job_name: 'articdbm-proxy-2'
    static_configs:
      - targets: ['proxy-dev-2:9092']
    scrape_interval: 5s
    metrics_path: /metrics

  - job_name: 'haproxy'
    static_configs:
      - targets: ['haproxy-dev:9090']
    metrics_path: /stats/prometheus
    scrape_interval: 10s

  - job_name: 'prometheus'
    static_configs:
      - targets: ['localhost:9090']
    scrape_interval: 30s
EOF
fi

if [ ! -f test/grafana-datasources.yml ]; then
    print_info "Creating Grafana datasources..."
    cat > test/grafana-datasources.yml << 'EOF'
apiVersion: 1

datasources:
  - name: Prometheus
    type: prometheus
    access: proxy
    orgId: 1
    url: http://prometheus-dev:9090
    basicAuth: false
    isDefault: true
    editable: true
EOF
fi

if [ ! -f test/grafana-dashboards.yml ]; then
    print_info "Creating Grafana dashboards config..."
    cat > test/grafana-dashboards.yml << 'EOF'
apiVersion: 1

providers:
  - name: 'default'
    orgId: 1
    folder: ''
    type: file
    disableDeletion: false
    editable: true
    options:
      path: /var/lib/grafana/dashboards
EOF
fi

print_success "Configuration files created"
echo ""

# Stop any existing containers
print_header "Cleaning Up Existing Environment"
docker-compose -f docker-compose.dev.yml down -v --remove-orphans 2>/dev/null || true
docker system prune -f --volumes 2>/dev/null || true
print_success "Environment cleaned"
echo ""

# Start the development cluster
print_header "Starting ArticDBM Development Cluster"
print_info "This may take a few minutes to download images and start services..."
echo ""

docker-compose -f docker-compose.dev.yml up -d

# Wait for services to start
print_info "Waiting for services to start up..."
sleep 30

# Check service status
print_header "Checking Service Status"
docker-compose -f docker-compose.dev.yml ps

echo ""

# Set up demo data
print_header "Setting Up Demo Data"
print_info "Creating SQLite databases with sample data..."

# Run demo data setup
docker-compose -f docker-compose.dev.yml exec -T proxy-dev-1 bash -c "
mkdir -p /data/articdbm
cd /data/articdbm

# Create main application database
sqlite3 main.db << 'EOF'
-- Create application schema
CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL,
    username TEXT NOT NULL,
    full_name TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    is_active BOOLEAN DEFAULT 1
);

CREATE TABLE products (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    description TEXT,
    price DECIMAL(10,2) NOT NULL,
    category TEXT,
    stock_quantity INTEGER DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Insert demo data
INSERT INTO users (email, username, full_name) VALUES
    ('admin@articdbm.demo', 'admin', 'System Administrator'),
    ('john.doe@example.com', 'johndoe', 'John Doe'),
    ('jane.smith@example.com', 'janesmith', 'Jane Smith');

INSERT INTO products (name, description, price, category, stock_quantity) VALUES
    ('ArticDBM Pro', 'Enterprise database proxy', 199.99, 'software', 100),
    ('Security Scanner', 'SQL injection detection', 29.99, 'security', 50),
    ('Load Balancer', 'Database load balancing', 59.99, 'networking', 25);

-- Enable optimizations
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;
PRAGMA synchronous=NORMAL;

SELECT 'Demo data created successfully!' as result;
EOF

# Set permissions
chmod 666 /data/articdbm/*.db
"

if [ $? -eq 0 ]; then
    print_success "Demo data setup completed"
else
    print_error "Demo data setup failed, but continuing..."
fi

echo ""

# Wait a bit more for full initialization
print_info "Allowing services to fully initialize..."
sleep 20

# Check service health
print_header "Performing Health Checks"

# Check ArticDBM Manager
print_info "Checking ArticDBM Manager..."
if curl -f -s http://localhost:18000/api/health > /dev/null; then
    print_success "ArticDBM Manager is healthy"
else
    print_error "ArticDBM Manager health check failed"
fi

# Check Prometheus
print_info "Checking Prometheus..."
if curl -f -s http://localhost:19093/-/healthy > /dev/null; then
    print_success "Prometheus is healthy"
else
    print_error "Prometheus health check failed"
fi

# Check Grafana
print_info "Checking Grafana..."
if curl -f -s http://localhost:13000/api/health > /dev/null; then
    print_success "Grafana is healthy"
else
    print_error "Grafana health check failed"
fi

echo ""

# Test basic connectivity
print_header "Testing Database Connectivity"

print_info "Testing MySQL connection..."
if mysql -h localhost -P 13306 -u testuser -ptestpass123 -D testapp -e "SELECT 1" > /dev/null 2>&1; then
    print_success "MySQL proxy is working"
else
    print_error "MySQL proxy test failed"
fi

print_info "Testing PostgreSQL connection..."
if PGPASSWORD=testpass123 psql -h localhost -p 15432 -U testuser -d testapp -c "SELECT 1" > /dev/null 2>&1; then
    print_success "PostgreSQL proxy is working"
else
    print_error "PostgreSQL proxy test failed"
fi

print_info "Testing Redis connection..."
if redis-cli -h localhost -p 16379 ping > /dev/null 2>&1; then
    print_success "Redis proxy is working"
else
    print_error "Redis proxy test failed"
fi

echo ""

# Display access information
print_header "🎉 ArticDBM Development Cluster is Ready!"
echo ""
print_info "Database Proxy Endpoints:"
echo "  • MySQL Proxy (Node 1): localhost:13306"
echo "  • MySQL Proxy (Node 2): localhost:13308"
echo "  • PostgreSQL Proxy (Node 1): localhost:15432"
echo "  • PostgreSQL Proxy (Node 2): localhost:15435"
echo "  • MongoDB Proxy (Node 1): localhost:27017"
echo "  • MongoDB Proxy (Node 2): localhost:27018"
echo "  • Redis Proxy (Node 1): localhost:16379"
echo "  • Redis Proxy (Node 2): localhost:16381"
echo "  • SQLite Proxy (Node 1): localhost:18765"
echo "  • SQLite Proxy (Node 2): localhost:18766"
echo ""
print_info "Management & Monitoring:"
echo "  • ArticDBM Manager: http://localhost:18000"
echo "  • Grafana Dashboard: http://localhost:13000 (admin/devpass123)"
echo "  • Prometheus Metrics: http://localhost:19093"
echo "  • Jaeger Tracing: http://localhost:116686"
echo "  • HAProxy Stats: http://localhost:19090/stats"
echo "  • Redis Insight: http://localhost:18001"
echo "  • pgAdmin: http://localhost:18080 (admin@articdbm.dev/devpass123)"
echo "  • Adminer: http://localhost:18081"
echo ""
print_info "Demo Credentials:"
echo "  • MySQL: testuser/testpass123"
echo "  • PostgreSQL: testuser/testpass123"
echo "  • Redis: (no password)"
echo "  • MongoDB: testuser/testpass123"
echo ""
print_success "Setup Complete!"
echo ""
print_info "Next Steps:"
echo "  1. Run './test/demo-queries.sh' to test all database connections"
echo "  2. Visit http://localhost:18000 to access the ArticDBM Manager"
echo "  3. Check http://localhost:13000 for Grafana dashboards"
echo "  4. Monitor logs with: docker-compose -f docker-compose.dev.yml logs -f"
echo "  5. Stop the cluster with: docker-compose -f docker-compose.dev.yml down"
echo ""
print_success "ArticDBM Development Cluster is running! 🚀"

# Optionally run demo queries
echo ""
read -p "Would you like to run the demo queries now? (y/N): " run_demo
if [[ "$run_demo" =~ ^[Yy]$ ]]; then
    echo ""
    ./test/demo-queries.sh
fi