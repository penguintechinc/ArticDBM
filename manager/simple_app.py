#!/usr/bin/env python3

import os
from flask import Flask, jsonify, render_template_string, redirect

app = Flask(__name__)

# Portal redirect template
PORTAL_REDIRECT_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>ArticDBM Manager - Redirecting</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            margin: 0;
            padding: 0;
            background: linear-gradient(135deg, #2c3e50, #3498db);
            color: white;
            display: flex;
            align-items: center;
            justify-content: center;
            height: 100vh;
        }
        .container {
            text-align: center;
            max-width: 600px;
            padding: 40px;
        }
        .spinner {
            border: 4px solid rgba(255,255,255,0.3);
            border-radius: 50%;
            border-top: 4px solid white;
            width: 40px;
            height: 40px;
            animation: spin 1s linear infinite;
            margin: 20px auto;
        }
        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }
        .logo { font-size: 3rem; margin-bottom: 20px; }
        .btn {
            display: inline-block;
            padding: 12px 24px;
            background: rgba(255,255,255,0.2);
            color: white;
            text-decoration: none;
            border-radius: 6px;
            margin: 10px;
            border: 2px solid rgba(255,255,255,0.3);
            transition: all 0.3s;
        }
        .btn:hover {
            background: rgba(255,255,255,0.3);
            border-color: rgba(255,255,255,0.6);
        }
    </style>
    <script>
        // Auto-redirect to py4web portal
        setTimeout(function() {
            window.location.href = 'http://localhost:8000';
        }, 3000);
    </script>
</head>
<body>
    <div class="container">
        <div class="logo">🚀</div>
        <h1>ArticDBM Enterprise Manager v1.2.0</h1>
        <div class="spinner"></div>
        <p>Redirecting to full management portal...</p>
        <p class="text-muted">
            Comprehensive database proxy management with all enterprise features
        </p>

        <div style="margin-top: 30px;">
            <a href="http://localhost:8000" class="btn">Go to Portal Now</a>
            <a href="#" onclick="showDemo()" class="btn">View Demo Info</a>
        </div>

        <div id="demoInfo" style="display:none; margin-top: 30px; text-align: left; background: rgba(0,0,0,0.2); padding: 20px; border-radius: 8px;">
            <h3>🎯 Available Features:</h3>
            <ul>
                <li><strong>Cluster Management:</strong> Configure MySQL, PostgreSQL, MongoDB, Redis, SQLite clusters</li>
                <li><strong>Node Configuration:</strong> Set Read/Write roles, load balancing weights</li>
                <li><strong>Security Center:</strong> SQL injection protection, threat intelligence</li>
                <li><strong>User Management:</strong> API keys, permissions, temporary access</li>
                <li><strong>Performance Tuning:</strong> ML optimization, XDP/AF_XDP, cache settings</li>
                <li><strong>Monitoring:</strong> Real-time metrics, audit logs, health checks</li>
                <li><strong>Cloud Integration:</strong> AWS, GCP, Azure provider management</li>
                <li><strong>Galera Support:</strong> MariaDB/MySQL cluster management</li>
            </ul>
        </div>
    </div>

    <script>
        function showDemo() {
            document.getElementById('demoInfo').style.display = 'block';
        }
    </script>
</body>
</html>
"""

@app.route('/')
def index():
    return render_template_string(PORTAL_REDIRECT_TEMPLATE)

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