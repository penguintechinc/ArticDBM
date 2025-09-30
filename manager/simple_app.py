#!/usr/bin/env python3

import os
from flask import Flask, jsonify, render_template_string

app = Flask(__name__)

# Simple HTML template for demo
HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>ArticDBM Manager - Demo</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }
        .header { background: #2c3e50; color: white; padding: 20px; border-radius: 8px; margin-bottom: 20px; }
        .card { background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); margin-bottom: 20px; }
        .success { color: #27ae60; }
        .info { color: #3498db; }
        .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px; }
    </style>
</head>
<body>
    <div class="header">
        <h1>🚀 ArticDBM Development Manager</h1>
        <p>Database Proxy Management Interface - Demo Mode</p>
    </div>

    <div class="card">
        <h2>📊 Cluster Status</h2>
        <p class="success">✅ ArticDBM Manager is running</p>
        <p class="info">ℹ️  Demo cluster active with SQLite support</p>
        <p class="info">ℹ️  All enterprise features available</p>
    </div>

    <div class="grid">
        <div class="card">
            <h3>🗄️ Supported Databases</h3>
            <ul>
                <li>✅ MySQL (Ports: 13306, 13308)</li>
                <li>✅ PostgreSQL (Ports: 15432, 15435)</li>
                <li>✅ MongoDB (Ports: 27017, 27018)</li>
                <li>✅ Redis (Ports: 16379, 16381)</li>
                <li>🆕 SQLite (Ports: 18765, 18766)</li>
            </ul>
        </div>

        <div class="card">
            <h3>🛡️ Security Features</h3>
            <ul>
                <li>✅ SQL Injection Detection</li>
                <li>✅ Threat Intelligence Integration</li>
                <li>✅ ML-Powered Query Optimization</li>
                <li>✅ Galera Cluster Support</li>
                <li>✅ Advanced Access Control</li>
            </ul>
        </div>

        <div class="card">
            <h3>📈 Monitoring</h3>
            <ul>
                <li><a href="http://localhost:13000" target="_blank">Grafana Dashboard</a></li>
                <li><a href="http://localhost:19093" target="_blank">Prometheus Metrics</a></li>
                <li><a href="http://localhost:116686" target="_blank">Jaeger Tracing</a></li>
                <li><a href="http://localhost:19090/stats" target="_blank">HAProxy Stats</a></li>
            </ul>
        </div>

        <div class="card">
            <h3>🔧 Database Tools</h3>
            <ul>
                <li><a href="http://localhost:18080" target="_blank">pgAdmin</a></li>
                <li><a href="http://localhost:18001" target="_blank">Redis Insight</a></li>
                <li><a href="http://localhost:18081" target="_blank">Adminer</a></li>
            </ul>
        </div>
    </div>

    <div class="card">
        <h3>🚀 Quick Start</h3>
        <p><strong>Test Database Connections:</strong></p>
        <code>./test/demo-queries.sh</code>

        <p><strong>Connection Examples:</strong></p>
        <ul>
            <li><code>mysql -h localhost -P 13306 -u testuser -ptestpass123 -D testapp</code></li>
            <li><code>psql -h localhost -p 15432 -U testuser -d testapp</code></li>
            <li><code>redis-cli -h localhost -p 16379</code></li>
        </ul>
    </div>
</body>
</html>
"""

@app.route('/')
def index():
    return render_template_string(HTML_TEMPLATE)

@app.route('/api/health')
def health():
    return jsonify({
        "status": "healthy",
        "version": "1.2.0",
        "features": {
            "sqlite_support": True,
            "galera_support": True,
            "threat_intelligence": True,
            "ml_optimization": True,
            "xdp_optimization": False  # Disabled for demo
        },
        "databases": {
            "mysql": {"enabled": True, "ports": [13306, 13308]},
            "postgresql": {"enabled": True, "ports": [15432, 15435]},
            "mongodb": {"enabled": True, "ports": [27017, 27018]},
            "redis": {"enabled": True, "ports": [16379, 16381]},
            "sqlite": {"enabled": True, "ports": [18765, 18766]}
        }
    })

@app.route('/api/status')
def status():
    return jsonify({
        "cluster_status": "active",
        "proxy_nodes": 2,
        "active_connections": 0,
        "total_queries": 0,
        "uptime": "Demo Mode"
    })

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8000, debug=True)