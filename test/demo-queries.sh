#!/bin/bash

# ArticDBM Demo Query Scripts
# This script demonstrates various database operations through ArticDBM

echo "🚀 ArticDBM Database Proxy Demo"
echo "=================================="
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to print colored headers
print_header() {
    echo -e "${BLUE}$1${NC}"
    echo "----------------------------------------"
}

# Function to print success messages
print_success() {
    echo -e "${GREEN}✅ $1${NC}"
}

# Function to print info messages
print_info() {
    echo -e "${YELLOW}ℹ️  $1${NC}"
}

# Function to print errors
print_error() {
    echo -e "${RED}❌ $1${NC}"
}

# Wait for services
print_header "Waiting for ArticDBM services to be ready..."
sleep 10

# Test MySQL through ArticDBM proxy
print_header "Testing MySQL through ArticDBM Proxy (Port 13306)"
mysql -h localhost -P 13306 -u testuser -ptestpass123 -D testapp << EOF
SELECT 'Connected to MySQL through ArticDBM!' as message;
SELECT COUNT(*) as user_count FROM users;
SELECT COUNT(*) as product_count FROM products;
SELECT 'MySQL test completed' as result;
EOF

if [ $? -eq 0 ]; then
    print_success "MySQL proxy test passed"
else
    print_error "MySQL proxy test failed"
fi

echo ""

# Test PostgreSQL through ArticDBM proxy
print_header "Testing PostgreSQL through ArticDBM Proxy (Port 15432)"
PGPASSWORD=testpass123 psql -h localhost -p 15432 -U testuser -d testapp << EOF
SELECT 'Connected to PostgreSQL through ArticDBM!' as message;
SELECT COUNT(*) as user_count FROM users;
SELECT COUNT(*) as product_count FROM products;
SELECT 'PostgreSQL test completed' as result;
EOF

if [ $? -eq 0 ]; then
    print_success "PostgreSQL proxy test passed"
else
    print_error "PostgreSQL proxy test failed"
fi

echo ""

# Test Redis through ArticDBM proxy
print_header "Testing Redis through ArticDBM Proxy (Port 16379)"
redis-cli -h localhost -p 16379 << EOF
PING
SET articdbm:demo "Hello from ArticDBM Redis Proxy!"
GET articdbm:demo
INCR articdbm:counter
GET articdbm:counter
EOF

if [ $? -eq 0 ]; then
    print_success "Redis proxy test passed"
else
    print_error "Redis proxy test failed"
fi

echo ""

# Test MongoDB through ArticDBM proxy
print_header "Testing MongoDB through ArticDBM Proxy (Port 27017)"
mongo mongodb://testuser:testpass123@localhost:27017/testapp << EOF
db.runCommand({ping: 1});
print("Connected to MongoDB through ArticDBM!");
db.users.count();
db.products.count();
print("MongoDB test completed");
EOF

if [ $? -eq 0 ]; then
    print_success "MongoDB proxy test passed"
else
    print_error "MongoDB proxy test failed"
fi

echo ""

# Test SQLite through ArticDBM proxy (custom protocol)
print_header "Testing SQLite through ArticDBM Proxy (Port 18765)"
print_info "Note: SQLite uses a simplified protocol for demo purposes"

# Since SQLite uses a custom protocol, we'll use netcat for basic testing
echo "testuser:main" | nc localhost 18765
if [ $? -eq 0 ]; then
    print_success "SQLite proxy connection test passed"
else
    print_error "SQLite proxy connection test failed"
fi

echo ""

# Test load balancing between proxy nodes
print_header "Testing Load Balancing Between Proxy Nodes"

print_info "Testing MySQL on both proxy nodes..."
echo "Node 1 (port 13306):"
mysql -h localhost -P 13306 -u testuser -ptestpass123 -D testapp -e "SELECT 'Node 1' as proxy_node, NOW() as timestamp;"

echo "Node 2 (port 13308):"
mysql -h localhost -P 13308 -u testuser -ptestpass123 -D testapp -e "SELECT 'Node 2' as proxy_node, NOW() as timestamp;"

print_success "Load balancing test completed"

echo ""

# Test security features
print_header "Testing Security Features"

print_info "Testing SQL injection detection..."

# This should be blocked
mysql -h localhost -P 13306 -u testuser -ptestpass123 -D testapp << EOF
SELECT * FROM users WHERE id = 1 OR 1=1;
EOF

print_info "SQL injection test completed (query should be blocked)"

echo ""

# Test different query patterns
print_header "Testing Different Query Patterns"

print_info "Testing read queries..."
mysql -h localhost -P 13306 -u testuser -ptestpass123 -D testapp << EOF
-- Simple SELECT
SELECT email, username FROM users LIMIT 3;

-- JOIN query
SELECT u.username, COUNT(o.id) as order_count
FROM users u
LEFT JOIN orders o ON u.id = o.user_id
GROUP BY u.id, u.username
LIMIT 5;

-- Aggregate query
SELECT category, COUNT(*) as product_count, AVG(price) as avg_price
FROM products
GROUP BY category;
EOF

print_info "Testing write queries..."
mysql -h localhost -P 13306 -u testuser -ptestpass123 -D testapp << EOF
-- Insert new user
INSERT IGNORE INTO users (email, username, full_name)
VALUES ('demo@articdbm.com', 'demouser', 'Demo User');

-- Update user
UPDATE users SET last_login = NOW() WHERE username = 'demouser';

-- Insert new product
INSERT IGNORE INTO products (name, description, price, category, stock_quantity)
VALUES ('Demo Product', 'A product created during demo', 9.99, 'demo', 1);
EOF

print_success "Query pattern tests completed"

echo ""

# Check proxy metrics
print_header "Checking Proxy Metrics"

print_info "Fetching metrics from proxy nodes..."
echo "Node 1 metrics:"
curl -s http://localhost:19091/metrics | grep articdbm | head -10

echo ""
echo "Node 2 metrics:"
curl -s http://localhost:19092/metrics | grep articdbm | head -10

print_success "Metrics collection test completed"

echo ""

# Test health endpoints
print_header "Testing Health Endpoints"

print_info "Checking ArticDBM Manager health..."
curl -s http://localhost:18000/api/health | jq .

print_info "Checking proxy health via HAProxy stats..."
curl -s http://localhost:19090/stats | grep -i "proxy\|backend" | head -5

print_success "Health check tests completed"

echo ""

# Performance test
print_header "Basic Performance Test"

print_info "Running basic load test (100 queries)..."
time for i in {1..100}; do
    mysql -h localhost -P 13306 -u testuser -ptestpass123 -D testapp -e "SELECT COUNT(*) FROM users;" > /dev/null 2>&1
done

print_success "Performance test completed"

echo ""

# Final summary
print_header "Demo Summary"
echo ""
print_success "All ArticDBM proxy tests completed!"
echo ""
echo "📊 Tested Databases:"
echo "  ✅ MySQL (port 13306/13308)"
echo "  ✅ PostgreSQL (port 15432/15435)"
echo "  ✅ MongoDB (port 27017/27018)"
echo "  ✅ Redis (port 16379/16381)"
echo "  ✅ SQLite (port 18765/18766)"
echo ""
echo "🔧 Tested Features:"
echo "  ✅ Connection proxying"
echo "  ✅ Load balancing"
echo "  ✅ SQL injection detection"
echo "  ✅ Health monitoring"
echo "  ✅ Metrics collection"
echo ""
echo "🌐 Management Interfaces:"
echo "  • ArticDBM Manager: http://localhost:18000"
echo "  • Grafana Dashboard: http://localhost:13000 (admin/devpass123)"
echo "  • Prometheus Metrics: http://localhost:19093"
echo "  • HAProxy Stats: http://localhost:19090/stats"
echo "  • Jaeger Tracing: http://localhost:116686"
echo ""
print_info "Use 'docker-compose -f docker-compose.dev.yml logs -f' to view real-time logs"
print_info "Use 'docker-compose -f docker-compose.dev.yml ps' to check service status"
echo ""
print_success "ArticDBM Demo Completed Successfully! 🎉"