#!/bin/bash

# ArticDBM Demo Data Setup Script
# This script creates sample data in all supported databases for demonstration

echo "🚀 Setting up ArticDBM Demo Data..."

# Wait for services to be ready
echo "⏳ Waiting for services to start..."
sleep 30

# Create SQLite demo databases
echo "📱 Creating SQLite demo databases..."

# Create main application database
sqlite3 /data/articdbm/main.db << EOF
-- Create application schema
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL,
    username TEXT NOT NULL,
    full_name TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_login DATETIME,
    is_active BOOLEAN DEFAULT 1
);

CREATE TABLE IF NOT EXISTS products (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    description TEXT,
    price DECIMAL(10,2) NOT NULL,
    category TEXT,
    stock_quantity INTEGER DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS orders (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER REFERENCES users(id),
    total_amount DECIMAL(10,2) NOT NULL,
    status TEXT DEFAULT 'pending',
    order_date DATETIME DEFAULT CURRENT_TIMESTAMP,
    shipping_address TEXT
);

CREATE TABLE IF NOT EXISTS order_items (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    order_id INTEGER REFERENCES orders(id),
    product_id INTEGER REFERENCES products(id),
    quantity INTEGER NOT NULL,
    unit_price DECIMAL(10,2) NOT NULL
);

-- Create indexes for better performance
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
CREATE INDEX IF NOT EXISTS idx_products_category ON products(category);
CREATE INDEX IF NOT EXISTS idx_orders_user_id ON orders(user_id);
CREATE INDEX IF NOT EXISTS idx_orders_date ON orders(order_date);

-- Insert sample data
INSERT OR IGNORE INTO users (email, username, full_name, last_login, is_active) VALUES
    ('admin@articdbm.demo', 'admin', 'System Administrator', datetime('now', '-1 hour'), 1),
    ('john.doe@example.com', 'johndoe', 'John Doe', datetime('now', '-2 hours'), 1),
    ('jane.smith@example.com', 'janesmith', 'Jane Smith', datetime('now', '-3 hours'), 1),
    ('mike.johnson@example.com', 'mikej', 'Mike Johnson', datetime('now', '-1 day'), 1),
    ('sarah.wilson@example.com', 'sarahw', 'Sarah Wilson', datetime('now', '-2 days'), 1),
    ('test.user@example.com', 'testuser', 'Test User', datetime('now', '-1 week'), 0);

INSERT OR IGNORE INTO products (name, description, price, category, stock_quantity) VALUES
    ('ArticDBM Pro License', 'Enterprise database proxy license', 199.99, 'software', 100),
    ('Database Monitoring Dashboard', 'Real-time database monitoring', 49.99, 'software', 50),
    ('Security Scanner Plugin', 'Advanced SQL injection detection', 29.99, 'security', 25),
    ('Performance Optimizer', 'Automated query optimization', 79.99, 'tools', 75),
    ('Backup Manager', 'Automated backup and recovery', 39.99, 'tools', 30),
    ('Load Balancer Module', 'Intelligent load balancing', 59.99, 'networking', 40),
    ('SSL Certificate Manager', 'TLS certificate automation', 19.99, 'security', 60),
    ('Galera Cluster Support', 'MariaDB Galera cluster support', 99.99, 'database', 20);

INSERT OR IGNORE INTO orders (user_id, total_amount, status, shipping_address) VALUES
    (2, 199.99, 'completed', '123 Main St, Anytown, USA'),
    (3, 79.98, 'processing', '456 Oak Ave, Somewhere, USA'),
    (4, 149.97, 'shipped', '789 Pine Rd, Nowhere, USA'),
    (5, 29.99, 'pending', '321 Elm St, Everywhere, USA');

INSERT OR IGNORE INTO order_items (order_id, product_id, quantity, unit_price) VALUES
    (1, 1, 1, 199.99),
    (2, 2, 1, 49.99),
    (2, 3, 1, 29.99),
    (3, 1, 1, 199.99),
    (3, 4, 1, 79.99),
    (4, 3, 1, 29.99);

-- Enable WAL mode for better concurrency
PRAGMA journal_mode=WAL;
PRAGMA synchronous=NORMAL;
PRAGMA cache_size=-64000;
PRAGMA foreign_keys=ON;

-- Analyze for better query planning
ANALYZE;

SELECT 'SQLite main database created successfully!' as result;
EOF

# Create reference data database (read-only)
sqlite3 /data/articdbm/reference.db << EOF
-- Create reference tables
CREATE TABLE IF NOT EXISTS countries (
    id INTEGER PRIMARY KEY,
    code TEXT UNIQUE NOT NULL,
    name TEXT NOT NULL,
    continent TEXT
);

CREATE TABLE IF NOT EXISTS currencies (
    id INTEGER PRIMARY KEY,
    code TEXT UNIQUE NOT NULL,
    name TEXT NOT NULL,
    symbol TEXT
);

CREATE TABLE IF NOT EXISTS database_types (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT,
    supported BOOLEAN DEFAULT 1
);

-- Insert reference data
INSERT OR IGNORE INTO countries (code, name, continent) VALUES
    ('US', 'United States', 'North America'),
    ('CA', 'Canada', 'North America'),
    ('GB', 'United Kingdom', 'Europe'),
    ('DE', 'Germany', 'Europe'),
    ('FR', 'France', 'Europe'),
    ('JP', 'Japan', 'Asia'),
    ('AU', 'Australia', 'Oceania'),
    ('BR', 'Brazil', 'South America');

INSERT OR IGNORE INTO currencies (code, name, symbol) VALUES
    ('USD', 'US Dollar', '$'),
    ('EUR', 'Euro', '€'),
    ('GBP', 'British Pound', '£'),
    ('JPY', 'Japanese Yen', '¥'),
    ('CAD', 'Canadian Dollar', 'C$'),
    ('AUD', 'Australian Dollar', 'A$');

INSERT OR IGNORE INTO database_types (name, description, supported) VALUES
    ('MySQL', 'Popular open-source relational database', 1),
    ('PostgreSQL', 'Advanced open-source relational database', 1),
    ('SQLite', 'Embedded SQL database engine', 1),
    ('MongoDB', 'Document-oriented NoSQL database', 1),
    ('Redis', 'In-memory data structure store', 1),
    ('MariaDB Galera', 'Synchronous multi-master cluster', 1),
    ('Oracle', 'Enterprise relational database', 0),
    ('Firebird', 'Open-source SQL relational database', 0);

PRAGMA journal_mode=WAL;
PRAGMA query_only=ON;
ANALYZE;

SELECT 'SQLite reference database created successfully!' as result;
EOF

# Create analytics database (in-memory cache simulation)
sqlite3 /data/articdbm/analytics.db << EOF
-- Create analytics tables
CREATE TABLE IF NOT EXISTS page_views (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    page_url TEXT NOT NULL,
    user_agent TEXT,
    ip_address TEXT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    session_id TEXT
);

CREATE TABLE IF NOT EXISTS api_calls (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    endpoint TEXT NOT NULL,
    method TEXT NOT NULL,
    response_code INTEGER,
    response_time_ms INTEGER,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    user_id INTEGER
);

CREATE TABLE IF NOT EXISTS database_metrics (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    database_name TEXT NOT NULL,
    metric_name TEXT NOT NULL,
    metric_value REAL,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Create indexes
CREATE INDEX IF NOT EXISTS idx_page_views_timestamp ON page_views(timestamp);
CREATE INDEX IF NOT EXISTS idx_api_calls_endpoint ON api_calls(endpoint);
CREATE INDEX IF NOT EXISTS idx_database_metrics_name ON database_metrics(database_name);

-- Insert sample analytics data
INSERT INTO page_views (page_url, user_agent, ip_address, session_id, timestamp) VALUES
    ('/dashboard', 'Mozilla/5.0 (Chrome)', '192.168.1.100', 'sess_001', datetime('now', '-1 hour')),
    ('/databases', 'Mozilla/5.0 (Firefox)', '192.168.1.101', 'sess_002', datetime('now', '-45 minutes')),
    ('/security', 'Mozilla/5.0 (Safari)', '192.168.1.102', 'sess_003', datetime('now', '-30 minutes')),
    ('/monitoring', 'Mozilla/5.0 (Chrome)', '192.168.1.103', 'sess_004', datetime('now', '-15 minutes'));

INSERT INTO api_calls (endpoint, method, response_code, response_time_ms, user_id, timestamp) VALUES
    ('/api/health', 'GET', 200, 45, 1, datetime('now', '-2 hours')),
    ('/api/databases', 'GET', 200, 120, 2, datetime('now', '-1 hour')),
    ('/api/servers', 'POST', 201, 340, 1, datetime('now', '-45 minutes')),
    ('/api/metrics', 'GET', 200, 78, 3, datetime('now', '-30 minutes'));

INSERT INTO database_metrics (database_name, metric_name, metric_value, timestamp) VALUES
    ('mysql-main', 'connections', 25.0, datetime('now', '-5 minutes')),
    ('postgres-main', 'connections', 18.0, datetime('now', '-5 minutes')),
    ('sqlite-main', 'file_size_mb', 2.4, datetime('now', '-5 minutes')),
    ('redis-cache', 'memory_usage_mb', 156.7, datetime('now', '-5 minutes'));

PRAGMA journal_mode=WAL;
ANALYZE;

SELECT 'SQLite analytics database created successfully!' as result;
EOF

echo "✅ SQLite databases created successfully!"

# Set proper permissions
chmod 644 /data/articdbm/*.db
chmod 600 /data/articdbm/reference.db  # Read-only reference data

echo "🎉 Demo data setup complete!"
echo ""
echo "📊 Available databases:"
echo "  • SQLite Main (primary): /data/articdbm/main.db"
echo "  • SQLite Reference (read-only): /data/articdbm/reference.db"
echo "  • SQLite Analytics: /data/articdbm/analytics.db"
echo ""
echo "🔌 Connection endpoints:"
echo "  • SQLite Proxy (Node 1): localhost:8765"
echo "  • SQLite Proxy (Node 2): localhost:8766"
echo "  • MySQL Proxy: localhost:3306"
echo "  • PostgreSQL Proxy: localhost:5432"
echo "  • MongoDB Proxy: localhost:27017"
echo "  • Redis Proxy: localhost:6379"
echo ""
echo "🌐 Management interfaces:"
echo "  • ArticDBM Manager: http://localhost:8000"
echo "  • Prometheus: http://localhost:9093"
echo "  • Grafana: http://localhost:3000"
echo "  • Jaeger: http://localhost:16686"
echo ""
EOF