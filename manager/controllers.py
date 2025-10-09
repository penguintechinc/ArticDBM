#!/usr/bin/env python3
"""
ArticDBM Manager - py4web Controllers
Enterprise Database Proxy Management Portal
"""

from py4web import action, request, response, abort, redirect, URL
from py4web.utils.cors import CORS
from py4web.core import Template
from pydal import DAL, Field
import json
import redis
import os
from datetime import datetime, timedelta
import secrets
import hashlib

# Initialize CORS
cors = CORS(
    origin="*",
    headers="Origin, X-Requested-With, Content-Type, Accept, Authorization",
    methods="GET, POST, PUT, DELETE, OPTIONS"
)

# Redis connection
redis_client = redis.Redis(
    host=os.environ.get('REDIS_HOST', 'localhost'),
    port=int(os.environ.get('REDIS_PORT', 6379)),
    decode_responses=True
)

# Initialize database
db = DAL(os.environ.get('DATABASE_URL', 'sqlite://storage.db'))

# Define tables if they don't exist
db.define_table('clusters',
    Field('name', 'string', unique=True, notnull=True),
    Field('type', 'string', notnull=True),  # mysql, postgresql, mongodb, redis, sqlite
    Field('status', 'string', default='active'),
    Field('created_at', 'datetime', default=datetime.now),
    Field('config', 'json')
)

db.define_table('nodes',
    Field('cluster_id', 'reference clusters'),
    Field('host', 'string', notnull=True),
    Field('port', 'integer', notnull=True),
    Field('role', 'string', default='both'),  # read, write, both
    Field('weight', 'integer', default=100),
    Field('status', 'string', default='active'),
    Field('health_check_url', 'string'),
    Field('last_health_check', 'datetime')
)

db.define_table('users',
    Field('username', 'string', unique=True, notnull=True),
    Field('email', 'string', unique=True, notnull=True),
    Field('password_hash', 'string'),
    Field('role', 'string', default='user'),  # admin, user, viewer
    Field('created_at', 'datetime', default=datetime.now),
    Field('last_login', 'datetime'),
    Field('is_active', 'boolean', default=True)
)

db.define_table('api_keys',
    Field('user_id', 'reference users'),
    Field('key', 'string', unique=True, notnull=True),
    Field('name', 'string'),
    Field('created_at', 'datetime', default=datetime.now),
    Field('expires_at', 'datetime'),
    Field('last_used', 'datetime'),
    Field('is_active', 'boolean', default=True)
)

# Home page route
@action('/')
@action.uses('home.html')
def home():
    return dict(
        title="ArticDBM Enterprise Manager",
        version="1.2.0",
        features=[
            {"name": "Cluster Management", "url": URL('clusters'), "icon": "bi-diagram-3", "description": "Manage database clusters"},
            {"name": "Node Configuration", "url": URL('nodes'), "icon": "bi-hdd-network", "description": "Configure read/write nodes"},
            {"name": "Security Center", "url": URL('security/overview'), "icon": "bi-shield-lock", "description": "SQL injection and threat protection"},
            {"name": "User Management", "url": URL('users'), "icon": "bi-people", "description": "Manage users and permissions"},
            {"name": "API Keys", "url": URL('api-keys'), "icon": "bi-key", "description": "Generate and manage API keys"},
            {"name": "Performance", "url": URL('performance/overview'), "icon": "bi-speedometer", "description": "Optimize performance settings"},
            {"name": "Monitoring", "url": URL('monitoring/metrics'), "icon": "bi-graph-up", "description": "Real-time metrics and logs"},
            {"name": "Cloud Integration", "url": URL('cloud-integration'), "icon": "bi-cloud", "description": "AWS, GCP, Azure integration"},
            {"name": "Settings", "url": URL('settings'), "icon": "bi-gear", "description": "System configuration"}
        ]
    )

# Dashboard route
@action('index')
@action('dashboard')
@action.uses('index.html')
def index():
    # Get cluster statistics
    clusters = db(db.clusters).select()
    active_clusters = len([c for c in clusters if c.status == 'active'])

    # Get node statistics
    nodes = db(db.nodes).select()
    active_nodes = len([n for n in nodes if n.status == 'active'])

    return dict(
        title="Dashboard",
        clusters=clusters,
        active_clusters=active_clusters,
        total_nodes=len(nodes),
        active_nodes=active_nodes,
        version="1.2.0"
    )

# Clusters management
@action('clusters')
@action.uses('clusters.html')
def clusters():
    clusters = db(db.clusters).select(orderby=db.clusters.name)
    return dict(title="Cluster Management", clusters=clusters)

@action('clusters/create', method=['GET', 'POST'])
@action.uses('cluster_create.html')
def cluster_create():
    if request.method == 'POST':
        data = request.json or request.forms
        cluster_id = db.clusters.insert(
            name=data.get('name'),
            type=data.get('type'),
            status='active',
            config=data.get('config', {})
        )
        if request.json:
            return {'status': 'success', 'cluster_id': cluster_id}
        redirect(URL('clusters'))
    return dict(title="Create Cluster")

@action('clusters/<cluster_id:int>/nodes')
@action.uses('cluster_nodes.html')
def cluster_nodes(cluster_id):
    cluster = db.clusters[cluster_id]
    if not cluster:
        abort(404)
    nodes = db(db.nodes.cluster_id == cluster_id).select()
    return dict(title=f"Nodes - {cluster.name}", cluster=cluster, nodes=nodes)

# Node management
@action('nodes')
@action.uses('nodes.html')
def nodes():
    nodes = db(db.nodes).select()
    return dict(title="Node Management", nodes=nodes)

@action('nodes/create', method=['GET', 'POST'])
@action.uses('node_create.html')
def node_create():
    if request.method == 'POST':
        data = request.json or request.forms
        node_id = db.nodes.insert(
            cluster_id=data.get('cluster_id'),
            host=data.get('host'),
            port=data.get('port'),
            role=data.get('role', 'both'),
            weight=data.get('weight', 100),
            status='active'
        )
        if request.json:
            return {'status': 'success', 'node_id': node_id}
        redirect(URL('nodes'))
    clusters = db(db.clusters).select()
    return dict(title="Add Node", clusters=clusters)

# Security management
@action('security/overview')
@action.uses('security_overview.html')
def security_overview():
    return dict(
        title="Security Overview",
        sql_injection_enabled=True,
        threat_intel_enabled=True,
        blocked_patterns_count=42
    )

@action('security/rules')
@action.uses('security_rules.html')
def security_rules():
    return dict(title="SQL Injection Rules")

@action('security/threat-intel')
@action.uses('threat_intelligence.html')
def threat_intelligence():
    return dict(title="Threat Intelligence")

# User management
@action('users')
@action.uses('users.html')
def users():
    users = db(db.users).select()
    return dict(title="User Management", users=users)

@action('users/create', method=['GET', 'POST'])
@action.uses('user_create.html')
def user_create():
    if request.method == 'POST':
        data = request.json or request.forms
        password_hash = hashlib.sha256(data.get('password', '').encode()).hexdigest()
        user_id = db.users.insert(
            username=data.get('username'),
            email=data.get('email'),
            password_hash=password_hash,
            role=data.get('role', 'user')
        )
        if request.json:
            return {'status': 'success', 'user_id': user_id}
        redirect(URL('users'))
    return dict(title="Create User")

# API Key management
@action('api-keys')
@action.uses('api_keys.html')
def api_keys():
    keys = db(db.api_keys).select()
    return dict(title="API Key Management", api_keys=keys)

@action('api-keys/generate', method=['POST'])
def generate_api_key():
    data = request.json or request.forms
    key = secrets.token_urlsafe(32)
    key_id = db.api_keys.insert(
        user_id=data.get('user_id'),
        key=key,
        name=data.get('name'),
        expires_at=datetime.now() + timedelta(days=365)
    )
    return {'status': 'success', 'key': key, 'key_id': key_id}

# Temporary tokens
@action('temporary-tokens')
@action.uses('temporary_tokens.html')
def temporary_tokens():
    return dict(title="Temporary Access Tokens")

# Performance management
@action('performance/overview')
@action.uses('performance_overview.html')
def performance_overview():
    return dict(title="Performance Overview")

@action('performance/cache')
@action.uses('cache_settings.html')
def cache_settings():
    return dict(title="Cache Settings")

@action('performance/ml')
@action.uses('ml_optimization.html')
def ml_optimization():
    return dict(title="ML Optimization")

# Monitoring
@action('monitoring/metrics')
@action.uses('metrics.html')
def metrics():
    return dict(title="Metrics Dashboard")

@action('monitoring/logs')
@action.uses('audit_logs.html')
def audit_logs():
    return dict(title="Audit Logs")

@action('monitoring/health')
@action.uses('health_checks.html')
def health_checks():
    nodes = db(db.nodes).select()
    return dict(title="Health Checks", nodes=nodes)

# Cloud integration
@action('cloud-integration')
@action.uses('cloud_integration.html')
def cloud_integration():
    return dict(title="Cloud Integration")

# Galera clusters
@action('galera')
@action.uses('galera.html')
def galera():
    return dict(title="Galera Clusters")

# Settings
@action('settings')
@action.uses('settings.html')
def settings():
    return dict(title="Settings")

# API endpoints
@action('api/health', method=['GET'])
@action.uses(cors)
def api_health():
    response.headers['Content-Type'] = 'application/json'
    return json.dumps({
        "status": "healthy",
        "version": "1.2.0",
        "features": {
            "sqlite_support": True,
            "galera_support": True,
            "threat_intelligence": True,
            "ml_optimization": True,
            "xdp_optimization": False
        },
        "databases": {
            "mysql": {"enabled": True, "ports": [13306, 13308]},
            "postgresql": {"enabled": True, "ports": [15432, 15435]},
            "mongodb": {"enabled": True, "ports": [27017, 27018]},
            "redis": {"enabled": True, "ports": [16379, 16381]},
            "sqlite": {"enabled": True, "ports": [18765, 18766]}
        }
    })

@action('api/status', method=['GET'])
@action.uses(cors)
def api_status():
    response.headers['Content-Type'] = 'application/json'
    clusters = db(db.clusters.status == 'active').count()
    nodes = db(db.nodes.status == 'active').count()
    return json.dumps({
        "cluster_status": "active",
        "proxy_nodes": nodes,
        "active_clusters": clusters,
        "active_connections": 0,
        "total_queries": 0,
        "uptime": "Running"
    })

@action('api/clusters', method=['GET'])
@action.uses(cors)
def api_clusters():
    response.headers['Content-Type'] = 'application/json'
    clusters = db(db.clusters).select().as_list()
    return json.dumps({"clusters": clusters})

@action('api/clusters', method=['POST'])
@action.uses(cors)
def api_cluster_create():
    data = request.json
    cluster_id = db.clusters.insert(
        name=data.get('name'),
        type=data.get('type'),
        status='active',
        config=data.get('config', {})
    )
    response.headers['Content-Type'] = 'application/json'
    return json.dumps({'status': 'success', 'cluster_id': cluster_id})

@action('api/nodes', method=['GET'])
@action.uses(cors)
def api_nodes():
    response.headers['Content-Type'] = 'application/json'
    nodes = db(db.nodes).select().as_list()
    return json.dumps({"nodes": nodes})

@action('api/nodes', method=['POST'])
@action.uses(cors)
def api_node_create():
    data = request.json
    node_id = db.nodes.insert(
        cluster_id=data.get('cluster_id'),
        host=data.get('host'),
        port=data.get('port'),
        role=data.get('role', 'both'),
        weight=data.get('weight', 100),
        status='active'
    )
    response.headers['Content-Type'] = 'application/json'
    return json.dumps({'status': 'success', 'node_id': node_id})

@action('api/users', method=['GET'])
@action.uses(cors)
def api_users():
    response.headers['Content-Type'] = 'application/json'
    users = db(db.users).select(db.users.id, db.users.username, db.users.email, db.users.role).as_list()
    return json.dumps({"users": users})

@action('api/api-keys', method=['GET'])
@action.uses(cors)
def api_get_api_keys():
    response.headers['Content-Type'] = 'application/json'
    keys = db(db.api_keys).select().as_list()
    return json.dumps({"api_keys": keys})

@action('api/api-keys', method=['POST'])
@action.uses(cors)
def api_generate_key():
    data = request.json
    key = secrets.token_urlsafe(32)
    key_id = db.api_keys.insert(
        user_id=data.get('user_id'),
        key=key,
        name=data.get('name'),
        expires_at=datetime.now() + timedelta(days=365)
    )
    response.headers['Content-Type'] = 'application/json'
    return json.dumps({'status': 'success', 'key': key, 'key_id': key_id})

# Commit database changes
db.commit()