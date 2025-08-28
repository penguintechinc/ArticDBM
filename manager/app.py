import os
import json
import asyncio
import secrets
import hashlib
from datetime import datetime, timedelta
from typing import Dict, List, Optional

from py4web import action, request, response, abort, Session, Cache, DAL, Field
from py4web.utils.cors import CORS
from py4web.utils.auth import Auth
from pydal.validators import *

import redis.asyncio as aioredis
import redis
from pydantic import BaseModel, Field as PydanticField

db = DAL(
    os.getenv("DATABASE_URL", "postgresql://articdbm:articdbm@postgres/articdbm"),
    pool_size=20,
    migrate=True,
    fake_migrate_all=False
)

session = Session(secret=os.getenv("SESSION_SECRET", secrets.token_urlsafe(32)))
cache = Cache(size=1000)
auth = Auth(session, db, registration_requires_confirmation=False)
cors = CORS(origin="*", headers="*", methods="*")

redis_client = redis.Redis(
    host=os.getenv("REDIS_HOST", "redis"),
    port=int(os.getenv("REDIS_PORT", 6379)),
    password=os.getenv("REDIS_PASSWORD", ""),
    db=int(os.getenv("REDIS_DB", 0)),
    decode_responses=True
)

aio_redis = None

async def init_aio_redis():
    global aio_redis
    aio_redis = await aioredis.create_redis_pool(
        f'redis://{os.getenv("REDIS_HOST", "redis")}:{os.getenv("REDIS_PORT", 6379)}',
        password=os.getenv("REDIS_PASSWORD", None),
        db=int(os.getenv("REDIS_DB", 0))
    )

db.define_table(
    'database_server',
    Field('name', 'string', required=True, unique=True),
    Field('type', 'string', requires=IS_IN_SET(['mysql', 'postgresql', 'mssql', 'mongodb', 'redis'])),
    Field('host', 'string', required=True),
    Field('port', 'integer', required=True),
    Field('username', 'string'),
    Field('password', 'string'),
    Field('database', 'string'),
    Field('role', 'string', requires=IS_IN_SET(['read', 'write', 'both']), default='both'),
    Field('weight', 'integer', default=1),
    Field('tls_enabled', 'boolean', default=False),
    Field('active', 'boolean', default=True),
    Field('created_at', 'datetime', default=datetime.utcnow),
    Field('updated_at', 'datetime', update=datetime.utcnow)
)

db.define_table(
    'user_permission',
    Field('user_id', 'reference auth_user', required=True),
    Field('database_name', 'string', required=True),
    Field('table_name', 'string', default='*'),
    Field('actions', 'list:string', default=['read']),
    Field('created_at', 'datetime', default=datetime.utcnow),
    Field('updated_at', 'datetime', update=datetime.utcnow)
)

db.define_table(
    'audit_log',
    Field('user_id', 'reference auth_user'),
    Field('action', 'string'),
    Field('database_name', 'string'),
    Field('table_name', 'string'),
    Field('query', 'text'),
    Field('result', 'string'),
    Field('ip_address', 'string'),
    Field('timestamp', 'datetime', default=datetime.utcnow)
)

db.define_table(
    'security_rule',
    Field('name', 'string', required=True, unique=True),
    Field('pattern', 'text', required=True),
    Field('action', 'string', requires=IS_IN_SET(['block', 'alert', 'log'])),
    Field('severity', 'string', requires=IS_IN_SET(['low', 'medium', 'high', 'critical'])),
    Field('active', 'boolean', default=True),
    Field('created_at', 'datetime', default=datetime.utcnow)
)

class DatabaseServerModel(BaseModel):
    name: str
    type: str
    host: str
    port: int
    username: Optional[str] = None
    password: Optional[str] = None
    database: Optional[str] = None
    role: str = 'both'
    weight: int = 1
    tls_enabled: bool = False
    active: bool = True

class PermissionModel(BaseModel):
    user_id: int
    database_name: str
    table_name: str = '*'
    actions: List[str] = ['read']

class SecurityRuleModel(BaseModel):
    name: str
    pattern: str
    action: str
    severity: str
    active: bool = True

@action('api/health', method=['GET'])
@cors
def health():
    return {'status': 'healthy', 'timestamp': datetime.utcnow().isoformat()}

@action('api/servers', method=['GET'])
@action.uses(auth, cors)
def get_servers():
    servers = db(db.database_server.active == True).select()
    result = []
    for server in servers:
        result.append({
            'id': server.id,
            'name': server.name,
            'type': server.type,
            'host': server.host,
            'port': server.port,
            'role': server.role,
            'weight': server.weight,
            'tls_enabled': server.tls_enabled,
            'active': server.active
        })
    return {'servers': result}

@action('api/servers', method=['POST'])
@action.uses(auth, cors, db)
def create_server():
    try:
        data = request.json
        server = DatabaseServerModel(**data)
        
        server_id = db.database_server.insert(
            name=server.name,
            type=server.type,
            host=server.host,
            port=server.port,
            username=server.username,
            password=server.password,
            database=server.database,
            role=server.role,
            weight=server.weight,
            tls_enabled=server.tls_enabled,
            active=server.active
        )
        
        sync_to_redis()
        
        return {'id': server_id, 'message': 'Server created successfully'}
    except Exception as e:
        abort(400, str(e))

@action('api/servers/<server_id:int>', method=['PUT'])
@action.uses(auth, cors, db)
def update_server(server_id):
    try:
        data = request.json
        server = db.database_server[server_id]
        if not server:
            abort(404, 'Server not found')
        
        server.update_record(**data)
        sync_to_redis()
        
        return {'message': 'Server updated successfully'}
    except Exception as e:
        abort(400, str(e))

@action('api/servers/<server_id:int>', method=['DELETE'])
@action.uses(auth, cors, db)
def delete_server(server_id):
    try:
        server = db.database_server[server_id]
        if not server:
            abort(404, 'Server not found')
        
        server.update_record(active=False)
        sync_to_redis()
        
        return {'message': 'Server deleted successfully'}
    except Exception as e:
        abort(400, str(e))

@action('api/permissions', method=['GET'])
@action.uses(auth, cors)
def get_permissions():
    permissions = db(db.user_permission).select()
    result = []
    for perm in permissions:
        user = db.auth_user[perm.user_id]
        result.append({
            'id': perm.id,
            'user_id': perm.user_id,
            'username': user.email if user else 'Unknown',
            'database_name': perm.database_name,
            'table_name': perm.table_name,
            'actions': perm.actions
        })
    return {'permissions': result}

@action('api/permissions', method=['POST'])
@action.uses(auth, cors, db)
def create_permission():
    try:
        data = request.json
        perm = PermissionModel(**data)
        
        perm_id = db.user_permission.insert(
            user_id=perm.user_id,
            database_name=perm.database_name,
            table_name=perm.table_name,
            actions=perm.actions
        )
        
        sync_to_redis()
        
        return {'id': perm_id, 'message': 'Permission created successfully'}
    except Exception as e:
        abort(400, str(e))

@action('api/permissions/<perm_id:int>', method=['PUT'])
@action.uses(auth, cors, db)
def update_permission(perm_id):
    try:
        data = request.json
        perm = db.user_permission[perm_id]
        if not perm:
            abort(404, 'Permission not found')
        
        perm.update_record(**data)
        sync_to_redis()
        
        return {'message': 'Permission updated successfully'}
    except Exception as e:
        abort(400, str(e))

@action('api/permissions/<perm_id:int>', method=['DELETE'])
@action.uses(auth, cors, db)
def delete_permission(perm_id):
    try:
        perm = db.user_permission[perm_id]
        if not perm:
            abort(404, 'Permission not found')
        
        db(db.user_permission.id == perm_id).delete()
        sync_to_redis()
        
        return {'message': 'Permission deleted successfully'}
    except Exception as e:
        abort(400, str(e))

@action('api/security-rules', method=['GET'])
@action.uses(auth, cors)
def get_security_rules():
    rules = db(db.security_rule.active == True).select()
    result = []
    for rule in rules:
        result.append({
            'id': rule.id,
            'name': rule.name,
            'pattern': rule.pattern,
            'action': rule.action,
            'severity': rule.severity,
            'active': rule.active
        })
    return {'rules': result}

@action('api/security-rules', method=['POST'])
@action.uses(auth, cors, db)
def create_security_rule():
    try:
        data = request.json
        rule = SecurityRuleModel(**data)
        
        rule_id = db.security_rule.insert(
            name=rule.name,
            pattern=rule.pattern,
            action=rule.action,
            severity=rule.severity,
            active=rule.active
        )
        
        sync_to_redis()
        
        return {'id': rule_id, 'message': 'Security rule created successfully'}
    except Exception as e:
        abort(400, str(e))

@action('api/audit-log', method=['GET'])
@action.uses(auth, cors)
def get_audit_log():
    limit = request.params.get('limit', 100)
    offset = request.params.get('offset', 0)
    
    logs = db(db.audit_log).select(
        limitby=(int(offset), int(offset) + int(limit)),
        orderby=~db.audit_log.timestamp
    )
    
    result = []
    for log in logs:
        user = db.auth_user[log.user_id] if log.user_id else None
        result.append({
            'id': log.id,
            'username': user.email if user else 'System',
            'action': log.action,
            'database_name': log.database_name,
            'table_name': log.table_name,
            'query': log.query[:100] if log.query else None,
            'result': log.result,
            'ip_address': log.ip_address,
            'timestamp': log.timestamp.isoformat()
        })
    
    return {'logs': result, 'total': db(db.audit_log).count()}

@action('api/stats', method=['GET'])
@action.uses(auth, cors)
def get_stats():
    stats = {
        'total_servers': db(db.database_server.active == True).count(),
        'total_users': db(db.auth_user).count(),
        'total_permissions': db(db.user_permission).count(),
        'total_security_rules': db(db.security_rule.active == True).count(),
        'recent_queries': db(db.audit_log).count(),
        'servers_by_type': {}
    }
    
    for server_type in ['mysql', 'postgresql', 'mssql', 'mongodb', 'redis']:
        count = db((db.database_server.type == server_type) & 
                  (db.database_server.active == True)).count()
        stats['servers_by_type'][server_type] = count
    
    return stats

def sync_to_redis():
    try:
        users = {}
        for user in db(db.auth_user).select():
            users[user.email] = {
                'username': user.email,
                'password_hash': user.password,
                'enabled': True,
                'created_at': user.created_on.isoformat() if hasattr(user, 'created_on') else None,
                'updated_at': user.modified_on.isoformat() if hasattr(user, 'modified_on') else None
            }
        
        permissions = {}
        for perm in db(db.user_permission).select():
            user = db.auth_user[perm.user_id]
            if user:
                permissions[user.email] = {
                    'user_id': user.email,
                    'database': perm.database_name,
                    'table': perm.table_name,
                    'actions': perm.actions
                }
        
        backends = {
            'mysql': [],
            'postgresql': [],
            'mssql': [],
            'mongodb': [],
            'redis': []
        }
        
        for server in db(db.database_server.active == True).select():
            backend_data = {
                'host': server.host,
                'port': server.port,
                'type': server.role,
                'weight': server.weight,
                'tls': server.tls_enabled,
                'user': server.username,
                'password': server.password,
                'database': server.database
            }
            if server.type in backends:
                backends[server.type].append(backend_data)
        
        redis_client.set('articdbm:users', json.dumps(users))
        redis_client.set('articdbm:permissions', json.dumps(permissions))
        redis_client.set('articdbm:backends', json.dumps(backends))
        
        redis_client.set('articdbm:manager:users', json.dumps(users))
        redis_client.set('articdbm:manager:permissions', json.dumps(permissions))
        
        redis_client.expire('articdbm:users', 300)
        redis_client.expire('articdbm:permissions', 300)
        redis_client.expire('articdbm:backends', 300)
        
        return True
    except Exception as e:
        print(f"Error syncing to Redis: {e}")
        return False

@action('api/sync', method=['POST'])
@action.uses(auth, cors)
def manual_sync():
    if sync_to_redis():
        return {'message': 'Configuration synced to Redis successfully'}
    else:
        abort(500, 'Failed to sync configuration')

async def periodic_sync():
    while True:
        await asyncio.sleep(60)
        sync_to_redis()

if __name__ == "__main__":
    asyncio.create_task(init_aio_redis())
    asyncio.create_task(periodic_sync())
    
    from py4web import start
    start(host='0.0.0.0', port=8000)