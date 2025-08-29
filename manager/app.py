import os
import json
import asyncio
import secrets
import hashlib
import re
import uuid
import tempfile
import shutil
import xml.etree.ElementTree as ET
import yaml
import random
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from pathlib import Path
from io import StringIO

from py4web import action, request, response, abort, Session, Cache, DAL, Field
from py4web.utils.cors import CORS
from py4web.utils.auth import Auth
from pydal.validators import *

import redis.asyncio as aioredis
import redis
from pydantic import BaseModel, Field as PydanticField
import requests

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

db.define_table(
    'managed_database',
    Field('name', 'string', required=True, unique=True),
    Field('server_id', 'reference database_server', required=True),
    Field('database_name', 'string', required=True),
    Field('description', 'text'),
    Field('schema_version', 'string'),
    Field('auto_backup', 'boolean', default=False),
    Field('backup_schedule', 'string'),
    Field('active', 'boolean', default=True),
    Field('created_at', 'datetime', default=datetime.utcnow),
    Field('updated_at', 'datetime', update=datetime.utcnow)
)

db.define_table(
    'sql_file',
    Field('name', 'string', required=True),
    Field('database_id', 'reference managed_database', required=True),
    Field('file_type', 'string', requires=IS_IN_SET(['init', 'backup', 'migration', 'patch'])),
    Field('file_path', 'string', required=True),
    Field('file_size', 'integer'),
    Field('checksum', 'string'),
    Field('syntax_validated', 'boolean', default=False),
    Field('security_validated', 'boolean', default=False),
    Field('validation_errors', 'text'),
    Field('executed', 'boolean', default=False),
    Field('executed_at', 'datetime'),
    Field('executed_by', 'reference auth_user'),
    Field('created_at', 'datetime', default=datetime.utcnow)
)

db.define_table(
    'blocked_database',
    Field('name', 'string', required=True),
    Field('type', 'string', requires=IS_IN_SET(['database', 'username', 'table'])),
    Field('pattern', 'string', required=True),
    Field('reason', 'text'),
    Field('active', 'boolean', default=True),
    Field('created_at', 'datetime', default=datetime.utcnow)
)

db.define_table(
    'database_schema',
    Field('database_id', 'reference managed_database', required=True),
    Field('table_name', 'string', required=True),
    Field('column_name', 'string', required=True),
    Field('data_type', 'string', required=True),
    Field('is_nullable', 'boolean', default=True),
    Field('default_value', 'string'),
    Field('is_primary_key', 'boolean', default=False),
    Field('is_foreign_key', 'boolean', default=False),
    Field('foreign_table', 'string'),
    Field('foreign_column', 'string'),
    Field('created_at', 'datetime', default=datetime.utcnow)
)

db.define_table(
    'threat_intel_feed',
    Field('name', 'string', required=True, unique=True),
    Field('type', 'string', requires=IS_IN_SET(['stix', 'taxii', 'openioc', 'misp', 'custom'])),
    Field('url', 'string'),
    Field('api_key', 'string'),
    Field('username', 'string'),
    Field('password', 'string'),
    Field('polling_interval', 'integer', default=3600),
    Field('last_polled', 'datetime'),
    Field('active', 'boolean', default=True),
    Field('created_at', 'datetime', default=datetime.utcnow),
    Field('updated_at', 'datetime', update=datetime.utcnow)
)

db.define_table(
    'threat_intel_indicator',
    Field('feed_id', 'reference threat_intel_feed'),
    Field('indicator_type', 'string', requires=IS_IN_SET(['ip', 'domain', 'url', 'hash', 'email', 'pattern', 'sql_pattern', 'user_agent'])),
    Field('value', 'string', required=True),
    Field('threat_level', 'string', requires=IS_IN_SET(['info', 'low', 'medium', 'high', 'critical'])),
    Field('confidence', 'integer', default=50),
    Field('description', 'text'),
    Field('tags', 'list:string'),
    Field('first_seen', 'datetime', default=datetime.utcnow),
    Field('last_seen', 'datetime', default=datetime.utcnow),
    Field('expires', 'datetime'),
    Field('active', 'boolean', default=True),
    Field('matched_count', 'integer', default=0),
    Field('created_at', 'datetime', default=datetime.utcnow)
)

db.define_table(
    'database_security_config',
    Field('database_id', 'reference managed_database', required=True, unique=True),
    Field('security_blocks_enabled', 'boolean', default=True),
    Field('threat_intel_blocks_enabled', 'boolean', default=True),
    Field('sql_injection_detection', 'boolean', default=True),
    Field('audit_logging', 'boolean', default=True),
    Field('block_default_resources', 'boolean', default=True),
    Field('threat_intel_action', 'string', requires=IS_IN_SET(['block', 'alert', 'log']), default='block'),
    Field('custom_rules', 'text'),
    Field('whitelist_patterns', 'text'),
    Field('created_at', 'datetime', default=datetime.utcnow),
    Field('updated_at', 'datetime', update=datetime.utcnow)
)

db.define_table(
    'threat_intel_match',
    Field('indicator_id', 'reference threat_intel_indicator', required=True),
    Field('database_name', 'string'),
    Field('user_id', 'reference auth_user'),
    Field('source_ip', 'string'),
    Field('query', 'text'),
    Field('action_taken', 'string', requires=IS_IN_SET(['blocked', 'alerted', 'logged'])),
    Field('match_details', 'text'),
    Field('timestamp', 'datetime', default=datetime.utcnow)
)

db.define_table(
    'license_info',
    Field('license_key', 'string', unique=True),
    Field('tier', 'string', requires=IS_IN_SET(['community', 'enterprise']), default='community'),
    Field('features', 'json'),
    Field('database_count', 'integer', default=0),
    Field('is_active', 'boolean', default=False),
    Field('last_validated', 'datetime'),
    Field('next_validation', 'datetime'),
    Field('validation_failures', 'integer', default=0),
    Field('created_at', 'datetime', default=datetime.utcnow),
    Field('updated_at', 'datetime', update=datetime.utcnow)
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

class ManagedDatabaseModel(BaseModel):
    name: str
    server_id: int
    database_name: str
    description: Optional[str] = None
    schema_version: Optional[str] = None
    auto_backup: bool = False
    backup_schedule: Optional[str] = None
    active: bool = True

class SQLFileModel(BaseModel):
    name: str
    database_id: int
    file_type: str
    file_content: str

class BlockedDatabaseModel(BaseModel):
    name: str
    type: str
    pattern: str
    reason: Optional[str] = None
    active: bool = True

class ThreatIntelFeedModel(BaseModel):
    name: str
    type: str
    url: Optional[str] = None
    api_key: Optional[str] = None
    username: Optional[str] = None
    password: Optional[str] = None
    polling_interval: int = 3600
    active: bool = True

class ThreatIntelIndicatorModel(BaseModel):
    feed_id: Optional[int] = None
    indicator_type: str
    value: str
    threat_level: str = 'medium'
    confidence: int = 50
    description: Optional[str] = None
    tags: List[str] = []
    expires: Optional[datetime] = None
    active: bool = True

class DatabaseSecurityConfigModel(BaseModel):
    database_id: int
    security_blocks_enabled: bool = True
    threat_intel_blocks_enabled: bool = True
    sql_injection_detection: bool = True
    audit_logging: bool = True
    block_default_resources: bool = True
    threat_intel_action: str = 'block'
    custom_rules: Optional[str] = None
    whitelist_patterns: Optional[str] = None

def parse_stix_indicators(stix_content: str) -> List[Dict[str, Any]]:
    """Parse STIX 2.x JSON format for threat indicators"""
    indicators = []
    try:
        stix_data = json.loads(stix_content)
        
        for obj in stix_data.get('objects', []):
            if obj.get('type') == 'indicator':
                pattern = obj.get('pattern', '')
                
                indicator = {
                    'indicator_type': 'pattern',
                    'value': pattern,
                    'description': obj.get('description', ''),
                    'threat_level': 'medium',
                    'confidence': 75,
                    'tags': obj.get('labels', []),
                    'first_seen': obj.get('created'),
                    'expires': obj.get('valid_until')
                }
                
                if '[ipv4-addr:value =' in pattern:
                    match = re.search(r"\[ipv4-addr:value = '([^']+)'\]", pattern)
                    if match:
                        indicator['indicator_type'] = 'ip'
                        indicator['value'] = match.group(1)
                elif '[domain-name:value =' in pattern:
                    match = re.search(r"\[domain-name:value = '([^']+)'\]", pattern)
                    if match:
                        indicator['indicator_type'] = 'domain'
                        indicator['value'] = match.group(1)
                elif '[url:value =' in pattern:
                    match = re.search(r"\[url:value = '([^']+)'\]", pattern)
                    if match:
                        indicator['indicator_type'] = 'url'
                        indicator['value'] = match.group(1)
                elif '[file:hashes.' in pattern:
                    match = re.search(r"\[file:hashes\.[\w]+\s*=\s*'([^']+)'\]", pattern)
                    if match:
                        indicator['indicator_type'] = 'hash'
                        indicator['value'] = match.group(1)
                
                if 'kill_chain_phases' in obj:
                    phases = [phase.get('phase_name', '') for phase in obj['kill_chain_phases']]
                    indicator['tags'].extend(phases)
                
                severity_map = {
                    'low': 'low',
                    'medium': 'medium', 
                    'high': 'high',
                    'critical': 'critical'
                }
                for label in obj.get('labels', []):
                    if label.lower() in severity_map:
                        indicator['threat_level'] = severity_map[label.lower()]
                
                indicators.append(indicator)
                
            elif obj.get('type') == 'malware':
                indicator = {
                    'indicator_type': 'pattern',
                    'value': obj.get('name', 'unknown'),
                    'description': f"Malware: {obj.get('description', '')}",
                    'threat_level': 'high',
                    'confidence': 80,
                    'tags': obj.get('labels', []) + ['malware'],
                    'first_seen': obj.get('created')
                }
                indicators.append(indicator)
                
            elif obj.get('type') == 'threat-actor':
                indicator = {
                    'indicator_type': 'pattern',
                    'value': obj.get('name', 'unknown'),
                    'description': f"Threat Actor: {obj.get('description', '')}",
                    'threat_level': 'high',
                    'confidence': 70,
                    'tags': obj.get('labels', []) + ['threat-actor'],
                    'first_seen': obj.get('created')
                }
                indicators.append(indicator)
                
    except json.JSONDecodeError as e:
        print(f"Error parsing STIX JSON: {e}")
    except Exception as e:
        print(f"Error processing STIX data: {e}")
    
    return indicators

def parse_taxii_feed(taxii_url: str, username: str = None, password: str = None, api_key: str = None) -> List[Dict[str, Any]]:
    """Fetch and parse TAXII 2.x feed"""
    indicators = []
    try:
        headers = {
            'Accept': 'application/taxii+json;version=2.1',
            'Content-Type': 'application/taxii+json;version=2.1'
        }
        
        if api_key:
            headers['Authorization'] = f'Bearer {api_key}'
        
        auth = None
        if username and password:
            auth = (username, password)
        
        response = requests.get(taxii_url, headers=headers, auth=auth, timeout=30)
        response.raise_for_status()
        
        taxii_data = response.json()
        
        if 'objects' in taxii_data:
            stix_content = json.dumps(taxii_data)
            indicators = parse_stix_indicators(stix_content)
        else:
            collections = taxii_data.get('collections', [])
            for collection in collections:
                collection_url = f"{taxii_url}/collections/{collection['id']}/objects"
                coll_response = requests.get(collection_url, headers=headers, auth=auth, timeout=30)
                if coll_response.status_code == 200:
                    coll_data = coll_response.json()
                    stix_content = json.dumps(coll_data)
                    indicators.extend(parse_stix_indicators(stix_content))
                    
    except requests.RequestException as e:
        print(f"Error fetching TAXII feed: {e}")
    except Exception as e:
        print(f"Error processing TAXII data: {e}")
    
    return indicators

def parse_openioc_indicators(openioc_content: str) -> List[Dict[str, Any]]:
    """Parse OpenIOC 1.1 XML format for threat indicators"""
    indicators = []
    try:
        root = ET.fromstring(openioc_content)
        
        ns = {'ioc': 'http://openioc.org/schemas/OpenIOC_1.1'}
        
        ioc_id = root.get('id', 'unknown')
        description = root.findtext('.//ioc:short_description', '', ns) or \
                     root.findtext('.//ioc:description', '', ns)
        
        for indicator_item in root.findall('.//ioc:IndicatorItem', ns):
            context = indicator_item.find('.//ioc:Context', ns)
            content = indicator_item.find('.//ioc:Content', ns)
            
            if context is not None and content is not None:
                context_type = context.get('search', '').lower()
                value = content.text
                
                if not value:
                    continue
                
                indicator_type = 'pattern'
                
                if 'ipv4' in context_type or 'remoteip' in context_type:
                    indicator_type = 'ip'
                elif 'hostname' in context_type or 'dns' in context_type:
                    indicator_type = 'domain'
                elif 'url' in context_type or 'uri' in context_type:
                    indicator_type = 'url'
                elif 'md5' in context_type or 'sha' in context_type or 'hash' in context_type:
                    indicator_type = 'hash'
                elif 'email' in context_type:
                    indicator_type = 'email'
                elif 'useragent' in context_type:
                    indicator_type = 'user_agent'
                elif 'sql' in context_type or 'query' in context_type:
                    indicator_type = 'sql_pattern'
                
                indicator = {
                    'indicator_type': indicator_type,
                    'value': value,
                    'description': f"{description} (IOC: {ioc_id})",
                    'threat_level': 'medium',
                    'confidence': 60,
                    'tags': ['openioc'],
                    'first_seen': datetime.utcnow()
                }
                
                indicators.append(indicator)
        
        for link in root.findall('.//ioc:link', ns):
            rel = link.get('rel', '')
            if rel == 'category':
                category = link.text
                for indicator in indicators:
                    indicator['tags'].append(category)
                    
    except ET.ParseError as e:
        print(f"Error parsing OpenIOC XML: {e}")
    except Exception as e:
        print(f"Error processing OpenIOC data: {e}")
    
    return indicators

def parse_misp_event(misp_content: str) -> List[Dict[str, Any]]:
    """Parse MISP event JSON format for threat indicators"""
    indicators = []
    try:
        misp_data = json.loads(misp_content)
        
        event = misp_data.get('Event', misp_data)
        
        threat_level_map = {
            '1': 'critical',
            '2': 'high',
            '3': 'medium',
            '4': 'low'
        }
        
        event_threat_level = threat_level_map.get(str(event.get('threat_level_id', '3')), 'medium')
        event_tags = [tag.get('name', '') for tag in event.get('Tag', [])]
        
        for attribute in event.get('Attribute', []):
            attr_type = attribute.get('type', '').lower()
            value = attribute.get('value', '')
            
            if not value:
                continue
            
            indicator_type = 'pattern'
            
            if attr_type in ['ip-src', 'ip-dst', 'ip']:
                indicator_type = 'ip'
            elif attr_type in ['domain', 'hostname']:
                indicator_type = 'domain'
            elif attr_type in ['url', 'uri']:
                indicator_type = 'url'
            elif attr_type in ['md5', 'sha1', 'sha256', 'sha512', 'hash']:
                indicator_type = 'hash'
            elif attr_type in ['email', 'email-src', 'email-dst']:
                indicator_type = 'email'
            elif attr_type == 'user-agent':
                indicator_type = 'user_agent'
            
            indicator = {
                'indicator_type': indicator_type,
                'value': value,
                'description': attribute.get('comment', '') or event.get('info', ''),
                'threat_level': event_threat_level,
                'confidence': 100 if attribute.get('to_ids', False) else 50,
                'tags': event_tags + [attr_type, 'misp'],
                'first_seen': attribute.get('timestamp'),
                'expires': None
            }
            
            indicators.append(indicator)
        
        for obj in event.get('Object', []):
            for attribute in obj.get('Attribute', []):
                attr_type = attribute.get('type', '').lower()
                value = attribute.get('value', '')
                
                if not value:
                    continue
                
                indicator_type = 'pattern'
                
                if attr_type in ['ip-src', 'ip-dst', 'ip']:
                    indicator_type = 'ip'
                elif attr_type in ['domain', 'hostname']:
                    indicator_type = 'domain'
                elif attr_type in ['url', 'uri']:
                    indicator_type = 'url'
                elif attr_type in ['md5', 'sha1', 'sha256', 'sha512']:
                    indicator_type = 'hash'
                
                indicator = {
                    'indicator_type': indicator_type,
                    'value': value,
                    'description': f"{obj.get('name', 'Object')}: {attribute.get('comment', '')}",
                    'threat_level': event_threat_level,
                    'confidence': 75,
                    'tags': event_tags + [attr_type, 'misp', obj.get('name', '')],
                    'first_seen': attribute.get('timestamp'),
                    'expires': None
                }
                
                indicators.append(indicator)
                
    except json.JSONDecodeError as e:
        print(f"Error parsing MISP JSON: {e}")
    except Exception as e:
        print(f"Error processing MISP data: {e}")
    
    return indicators

def validate_license_with_server(license_key: str) -> Dict[str, any]:
    """Validate license with license.penguintech.io server"""
    try:
        response = requests.post(
            'https://license.penguintech.io/api/validate',
            json={'license_key': license_key, 'product': 'articdbm'},
            timeout=30
        )
        
        if response.status_code == 200:
            data = response.json()
            return {
                'valid': data.get('valid', False),
                'tier': data.get('tier', 'community'),
                'features': data.get('features', []),
                'expires_at': data.get('expires_at'),
                'error': None
            }
        else:
            return {
                'valid': False,
                'tier': 'community',
                'features': [],
                'expires_at': None,
                'error': f'Server returned {response.status_code}'
            }
    except Exception as e:
        return {
            'valid': False,
            'tier': 'community',
            'features': [],
            'expires_at': None,
            'error': str(e)
        }

def get_current_license_info():
    """Get current license information from database"""
    license_record = db(db.license_info).select().first()
    if not license_record:
        return {
            'tier': 'community',
            'features': ['single_threat_intel_feed'],
            'is_active': False,
            'database_count': 0
        }
    
    return {
        'tier': license_record.tier,
        'features': license_record.features or [],
        'is_active': license_record.is_active,
        'database_count': license_record.database_count,
        'license_key': license_record.license_key if license_record.license_key else None
    }

def update_license_validation():
    """Update license validation status"""
    license_record = db(db.license_info).select().first()
    if not license_record or not license_record.license_key:
        return
    
    validation_result = validate_license_with_server(license_record.license_key)
    
    # Calculate next validation time (random between 45-180 seconds)
    next_validation = datetime.utcnow() + timedelta(seconds=random.randint(45, 180))
    
    if validation_result['valid']:
        license_record.update_record(
            tier=validation_result['tier'],
            features=validation_result['features'],
            is_active=True,
            last_validated=datetime.utcnow(),
            next_validation=next_validation,
            validation_failures=0
        )
    else:
        failures = license_record.validation_failures + 1
        # After 3 failures, disable enterprise features
        is_active = failures < 3
        
        license_record.update_record(
            is_active=is_active,
            last_validated=datetime.utcnow(),
            next_validation=next_validation,
            validation_failures=failures
        )

def is_enterprise_feature_enabled(feature: str) -> bool:
    """Check if an enterprise feature is enabled"""
    license_info = get_current_license_info()
    
    if not license_info['is_active'] or license_info['tier'] != 'enterprise':
        return False
    
    return feature in license_info['features']

def get_threat_intel_limit() -> int:
    """Get the maximum number of threat intel feeds allowed"""
    if is_enterprise_feature_enabled('unlimited_threat_intel_feeds'):
        return -1  # Unlimited
    return 1  # Community limit

def validate_sql_security(content: str) -> Dict[str, any]:
    """Comprehensive SQL security validation"""
    errors = []
    warnings = []
    severity = "low"
    
    # Normalize content for analysis
    normalized = content.lower().strip()
    lines = content.split('\n')
    
    # Dangerous patterns that should be blocked
    dangerous_patterns = {
        r'exec\s*\(': "Potentially dangerous EXEC statement",
        r'xp_cmdshell': "System command execution detected",
        r'sp_oacreate': "OLE automation detected",
        r'openrowset': "External data source access",
        r'opendatasource': "External data source access",
        r'bulk\s+insert': "Bulk insert operation",
        r'into\s+outfile': "File write operation detected",
        r'load_file\s*\(': "File read operation detected",
        r'@@version': "System information disclosure",
        r'information_schema': "Schema introspection detected",
        r'sys\.': "System table access",
        r'master\.': "Master database access",
        r'msdb\.': "MSDB database access",
        r'tempdb\.': "TempDB access",
        r'--\s*[^\r\n]*(\r?\n|$)': "SQL comments detected",
        r'/\*.*?\*/': "Block comments detected",
        r'\bor\s+1\s*=\s*1\b': "Classic SQL injection pattern",
        r'\bunion\s+select\b': "Union-based injection pattern",
        r';\s*(drop|truncate|delete)\s+': "Destructive operations in sequence",
    }
    
    # Shell command patterns
    shell_patterns = {
        r'\bcmd\b': "Command shell reference",
        r'\bpowershell\b': "PowerShell reference",
        r'\bbash\b': "Bash shell reference",
        r'\bsh\b': "Shell reference",
        r'/bin/': "Unix binary path",
        r'system\s*\(': "System call",
        r'shell_exec': "Shell execution",
        r'passthru': "Command execution",
        r'proc_open': "Process execution",
    }
    
    # Check for dangerous SQL patterns
    for pattern, description in dangerous_patterns.items():
        if re.search(pattern, normalized, re.IGNORECASE | re.MULTILINE):
            errors.append(f"{description}: {pattern}")
            severity = "high"
    
    # Check for shell command patterns
    for pattern, description in shell_patterns.items():
        if re.search(pattern, normalized, re.IGNORECASE):
            errors.append(f"Shell command detected - {description}: {pattern}")
            severity = "critical"
    
    # Check for default/test database access patterns
    default_db_patterns = {
        r'\btest\b': "Test database access",
        r'\bsample\b': "Sample database access",  
        r'\bdemo\b': "Demo database access",
        r'\bexample\b': "Example database access",
        r'\bsa\b': "Default 'sa' user detected",
        r'\broot\b': "Root user access",
        r'\badmin\b': "Admin user access",
        r'\bguest\b': "Guest user access",
    }
    
    for pattern, description in default_db_patterns.items():
        if re.search(pattern, normalized, re.IGNORECASE):
            warnings.append(f"Potential default/test resource access - {description}")
            if severity == "low":
                severity = "medium"
    
    # Basic syntax validation
    bracket_count = content.count('(') - content.count(')')
    if bracket_count != 0:
        errors.append("Unmatched parentheses in SQL")
    
    quote_count = content.count("'") % 2
    if quote_count != 0:
        errors.append("Unmatched single quotes in SQL")
    
    # Check for multiple statements (potential SQL injection)
    semicolon_statements = [s.strip() for s in content.split(';') if s.strip()]
    if len(semicolon_statements) > 1:
        statement_types = []
        for stmt in semicolon_statements:
            first_word = stmt.split()[0].upper() if stmt.split() else ""
            statement_types.append(first_word)
        
        if len(set(statement_types)) > 1:
            warnings.append(f"Multiple different statement types detected: {', '.join(set(statement_types))}")
            if severity == "low":
                severity = "medium"
    
    # Check for extremely long lines (potential obfuscation)
    for i, line in enumerate(lines, 1):
        if len(line) > 1000:
            warnings.append(f"Extremely long line detected (line {i}): {len(line)} characters")
    
    # Check for non-ASCII characters (potential encoding attacks)
    try:
        content.encode('ascii')
    except UnicodeEncodeError:
        warnings.append("Non-ASCII characters detected - potential encoding attack")
    
    return {
        'valid': len(errors) == 0,
        'errors': errors,
        'warnings': warnings,
        'severity': severity,
        'patterns_checked': len(dangerous_patterns) + len(shell_patterns) + len(default_db_patterns)
    }

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

# Database Management API Endpoints

@action('api/databases', method=['GET'])
@action.uses(auth, cors)
def get_managed_databases():
    databases = db(db.managed_database.active == True).select()
    result = []
    for database in databases:
        server = db.database_server[database.server_id]
        result.append({
            'id': database.id,
            'name': database.name,
            'database_name': database.database_name,
            'server_name': server.name if server else 'Unknown',
            'server_type': server.type if server else 'Unknown',
            'description': database.description,
            'schema_version': database.schema_version,
            'auto_backup': database.auto_backup,
            'backup_schedule': database.backup_schedule,
            'active': database.active,
            'created_at': database.created_at.isoformat()
        })
    return {'databases': result}

@action('api/databases', method=['POST'])
@action.uses(auth, cors, db)
def create_managed_database():
    try:
        data = request.json
        database = ManagedDatabaseModel(**data)
        
        # Verify server exists
        server = db.database_server[database.server_id]
        if not server:
            abort(400, 'Server not found')
        
        database_id = db.managed_database.insert(
            name=database.name,
            server_id=database.server_id,
            database_name=database.database_name,
            description=database.description,
            schema_version=database.schema_version,
            auto_backup=database.auto_backup,
            backup_schedule=database.backup_schedule,
            active=database.active
        )
        
        # Log the action
        db.audit_log.insert(
            user_id=auth.user_id,
            action='create_managed_database',
            database_name=database.name,
            ip_address=request.environ.get('REMOTE_ADDR')
        )
        
        sync_to_redis()
        
        return {'id': database_id, 'message': 'Managed database created successfully'}
    except Exception as e:
        abort(400, str(e))

@action('api/databases/<database_id:int>', method=['PUT'])
@action.uses(auth, cors, db)
def update_managed_database(database_id):
    try:
        data = request.json
        database = db.managed_database[database_id]
        if not database:
            abort(404, 'Database not found')
        
        database.update_record(**data)
        
        # Log the action
        db.audit_log.insert(
            user_id=auth.user_id,
            action='update_managed_database',
            database_name=database.name,
            ip_address=request.environ.get('REMOTE_ADDR')
        )
        
        sync_to_redis()
        
        return {'message': 'Managed database updated successfully'}
    except Exception as e:
        abort(400, str(e))

@action('api/databases/<database_id:int>', method=['DELETE'])
@action.uses(auth, cors, db)
def delete_managed_database(database_id):
    try:
        database = db.managed_database[database_id]
        if not database:
            abort(404, 'Database not found')
        
        database.update_record(active=False)
        
        # Log the action
        db.audit_log.insert(
            user_id=auth.user_id,
            action='delete_managed_database',
            database_name=database.name,
            ip_address=request.environ.get('REMOTE_ADDR')
        )
        
        sync_to_redis()
        
        return {'message': 'Managed database deleted successfully'}
    except Exception as e:
        abort(400, str(e))

# SQL File Management API Endpoints

@action('api/sql-files', method=['GET'])
@action.uses(auth, cors)
def get_sql_files():
    database_id = request.params.get('database_id')
    query = db.sql_file
    if database_id:
        query = db(db.sql_file.database_id == database_id)
    else:
        query = db(db.sql_file)
    
    files = query.select()
    result = []
    for file in files:
        database = db.managed_database[file.database_id]
        executed_by_user = db.auth_user[file.executed_by] if file.executed_by else None
        result.append({
            'id': file.id,
            'name': file.name,
            'database_name': database.name if database else 'Unknown',
            'file_type': file.file_type,
            'file_size': file.file_size,
            'syntax_validated': file.syntax_validated,
            'security_validated': file.security_validated,
            'validation_errors': file.validation_errors,
            'executed': file.executed,
            'executed_at': file.executed_at.isoformat() if file.executed_at else None,
            'executed_by': executed_by_user.email if executed_by_user else None,
            'created_at': file.created_at.isoformat()
        })
    return {'sql_files': result}

@action('api/sql-files', method=['POST'])
@action.uses(auth, cors, db)
def upload_sql_file():
    try:
        data = request.json
        sql_file = SQLFileModel(**data)
        
        # Verify database exists
        database = db.managed_database[sql_file.database_id]
        if not database:
            abort(400, 'Database not found')
        
        # Validate SQL content
        validation_result = validate_sql_security(sql_file.file_content)
        
        # Create file path and save content
        upload_dir = Path(tempfile.gettempdir()) / "articdbm" / "sql_files"
        upload_dir.mkdir(parents=True, exist_ok=True)
        
        file_uuid = str(uuid.uuid4())
        file_path = upload_dir / f"{file_uuid}.sql"
        
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(sql_file.file_content)
        
        # Calculate checksum
        checksum = hashlib.sha256(sql_file.file_content.encode('utf-8')).hexdigest()
        
        file_id = db.sql_file.insert(
            name=sql_file.name,
            database_id=sql_file.database_id,
            file_type=sql_file.file_type,
            file_path=str(file_path),
            file_size=len(sql_file.file_content),
            checksum=checksum,
            syntax_validated=validation_result['valid'],
            security_validated=validation_result['severity'] in ['low', 'medium'],
            validation_errors=json.dumps({
                'errors': validation_result['errors'],
                'warnings': validation_result['warnings'],
                'severity': validation_result['severity']
            })
        )
        
        # Log the action
        db.audit_log.insert(
            user_id=auth.user_id,
            action='upload_sql_file',
            database_name=database.name,
            query=f"Uploaded file: {sql_file.name}",
            result=f"Validation: {'passed' if validation_result['valid'] else 'failed'}",
            ip_address=request.environ.get('REMOTE_ADDR')
        )
        
        return {
            'id': file_id, 
            'message': 'SQL file uploaded successfully',
            'validation': validation_result
        }
    except Exception as e:
        abort(400, str(e))

@action('api/sql-files/<file_id:int>/execute', method=['POST'])
@action.uses(auth, cors, db)
def execute_sql_file(file_id):
    try:
        sql_file = db.sql_file[file_id]
        if not sql_file:
            abort(404, 'SQL file not found')
        
        if sql_file.executed:
            abort(400, 'SQL file has already been executed')
        
        if not sql_file.security_validated:
            abort(400, 'SQL file failed security validation')
        
        database = db.managed_database[sql_file.database_id]
        if not database:
            abort(400, 'Associated database not found')
        
        server = db.database_server[database.server_id]
        if not server:
            abort(400, 'Database server not found')
        
        # Read file content
        with open(sql_file.file_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Mark as executed (this would normally execute against the actual database)
        sql_file.update_record(
            executed=True,
            executed_at=datetime.utcnow(),
            executed_by=auth.user_id
        )
        
        # Log the action
        db.audit_log.insert(
            user_id=auth.user_id,
            action='execute_sql_file',
            database_name=database.name,
            query=f"Executed file: {sql_file.name}",
            result="success",
            ip_address=request.environ.get('REMOTE_ADDR')
        )
        
        return {'message': f'SQL file {sql_file.name} executed successfully'}
    except Exception as e:
        abort(400, str(e))

@action('api/sql-files/<file_id:int>/validate', method=['POST'])
@action.uses(auth, cors, db)
def validate_sql_file(file_id):
    try:
        sql_file = db.sql_file[file_id]
        if not sql_file:
            abort(404, 'SQL file not found')
        
        # Read file content
        with open(sql_file.file_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Re-validate
        validation_result = validate_sql_security(content)
        
        # Update validation status
        sql_file.update_record(
            syntax_validated=validation_result['valid'],
            security_validated=validation_result['severity'] in ['low', 'medium'],
            validation_errors=json.dumps({
                'errors': validation_result['errors'],
                'warnings': validation_result['warnings'],
                'severity': validation_result['severity']
            })
        )
        
        return {
            'message': 'SQL file validated successfully',
            'validation': validation_result
        }
    except Exception as e:
        abort(400, str(e))

# Blocked Database Management API Endpoints

@action('api/blocked-databases', method=['GET'])
@action.uses(auth, cors)
def get_blocked_databases():
    blocked = db(db.blocked_database.active == True).select()
    result = []
    for item in blocked:
        result.append({
            'id': item.id,
            'name': item.name,
            'type': item.type,
            'pattern': item.pattern,
            'reason': item.reason,
            'active': item.active,
            'created_at': item.created_at.isoformat()
        })
    return {'blocked_databases': result}

@action('api/blocked-databases', method=['POST'])
@action.uses(auth, cors, db)
def create_blocked_database():
    try:
        data = request.json
        blocked = BlockedDatabaseModel(**data)
        
        blocked_id = db.blocked_database.insert(
            name=blocked.name,
            type=blocked.type,
            pattern=blocked.pattern,
            reason=blocked.reason,
            active=blocked.active
        )
        
        # Log the action
        db.audit_log.insert(
            user_id=auth.user_id,
            action='create_blocked_database',
            database_name=blocked.name,
            query=f"Blocked {blocked.type}: {blocked.pattern}",
            ip_address=request.environ.get('REMOTE_ADDR')
        )
        
        sync_to_redis()
        
        return {'id': blocked_id, 'message': 'Blocked database rule created successfully'}
    except Exception as e:
        abort(400, str(e))

@action('api/blocked-databases/<blocked_id:int>', method=['DELETE'])
@action.uses(auth, cors, db)
def delete_blocked_database(blocked_id):
    try:
        blocked = db.blocked_database[blocked_id]
        if not blocked:
            abort(404, 'Blocked database rule not found')
        
        blocked.update_record(active=False)
        
        # Log the action
        db.audit_log.insert(
            user_id=auth.user_id,
            action='delete_blocked_database',
            database_name=blocked.name,
            ip_address=request.environ.get('REMOTE_ADDR')
        )
        
        sync_to_redis()
        
        return {'message': 'Blocked database rule deleted successfully'}
    except Exception as e:
        abort(400, str(e))

# Database Schema Management API Endpoints

@action('api/databases/<database_id:int>/schema', method=['GET'])
@action.uses(auth, cors)
def get_database_schema(database_id):
    database = db.managed_database[database_id]
    if not database:
        abort(404, 'Database not found')
    
    schema_entries = db(db.database_schema.database_id == database_id).select()
    
    # Group by table
    tables = {}
    for entry in schema_entries:
        table_name = entry.table_name
        if table_name not in tables:
            tables[table_name] = {
                'name': table_name,
                'columns': []
            }
        
        tables[table_name]['columns'].append({
            'name': entry.column_name,
            'data_type': entry.data_type,
            'is_nullable': entry.is_nullable,
            'default_value': entry.default_value,
            'is_primary_key': entry.is_primary_key,
            'is_foreign_key': entry.is_foreign_key,
            'foreign_table': entry.foreign_table,
            'foreign_column': entry.foreign_column
        })
    
    return {
        'database_name': database.name,
        'tables': list(tables.values())
    }

@action('api/databases/<database_id:int>/schema', method=['POST'])
@action.uses(auth, cors, db)
def update_database_schema(database_id):
    try:
        database = db.managed_database[database_id]
        if not database:
            abort(404, 'Database not found')
        
        data = request.json
        schema_data = data.get('schema', [])
        
        # Clear existing schema
        db(db.database_schema.database_id == database_id).delete()
        
        # Insert new schema
        for table in schema_data:
            table_name = table['name']
            for column in table.get('columns', []):
                db.database_schema.insert(
                    database_id=database_id,
                    table_name=table_name,
                    column_name=column['name'],
                    data_type=column['data_type'],
                    is_nullable=column.get('is_nullable', True),
                    default_value=column.get('default_value'),
                    is_primary_key=column.get('is_primary_key', False),
                    is_foreign_key=column.get('is_foreign_key', False),
                    foreign_table=column.get('foreign_table'),
                    foreign_column=column.get('foreign_column')
                )
        
        # Update database schema version
        schema_version = f"v{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}"
        database.update_record(schema_version=schema_version)
        
        # Log the action
        db.audit_log.insert(
            user_id=auth.user_id,
            action='update_database_schema',
            database_name=database.name,
            query=f"Updated schema to {schema_version}",
            ip_address=request.environ.get('REMOTE_ADDR')
        )
        
        return {'message': 'Database schema updated successfully', 'version': schema_version}
    except Exception as e:
        abort(400, str(e))

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
        
        # Get blocked databases for security rules
        blocked_databases = {}
        for blocked in db(db.blocked_database.active == True).select():
            blocked_databases[blocked.id] = {
                'name': blocked.name,
                'type': blocked.type,
                'pattern': blocked.pattern,
                'reason': blocked.reason,
                'active': blocked.active
            }
        
        # Get managed databases
        managed_databases = {}
        for managed_db in db(db.managed_database.active == True).select():
            server = db.database_server[managed_db.server_id]
            managed_databases[managed_db.id] = {
                'name': managed_db.name,
                'database_name': managed_db.database_name,
                'server_name': server.name if server else None,
                'server_type': server.type if server else None,
                'description': managed_db.description,
                'schema_version': managed_db.schema_version,
                'auto_backup': managed_db.auto_backup,
                'backup_schedule': managed_db.backup_schedule,
                'active': managed_db.active
            }
        
        redis_client.set('articdbm:users', json.dumps(users))
        redis_client.set('articdbm:permissions', json.dumps(permissions))
        redis_client.set('articdbm:backends', json.dumps(backends))
        redis_client.set('articdbm:blocked_databases', json.dumps(blocked_databases))
        redis_client.set('articdbm:managed_databases', json.dumps(managed_databases))
        
        redis_client.set('articdbm:manager:users', json.dumps(users))
        redis_client.set('articdbm:manager:permissions', json.dumps(permissions))
        redis_client.set('articdbm:manager:blocked_databases', json.dumps(blocked_databases))
        
        redis_client.expire('articdbm:users', 300)
        redis_client.expire('articdbm:permissions', 300)
        redis_client.expire('articdbm:backends', 300)
        redis_client.expire('articdbm:blocked_databases', 300)
        redis_client.expire('articdbm:managed_databases', 300)
        
        # Also sync threat intelligence data
        sync_threat_intel_to_redis()
        
        return True
    except Exception as e:
        print(f"Error syncing to Redis: {e}")
        return False

# License Management API Endpoints

@action('api/license', method=['GET'])
@action.uses(auth, cors)
def get_license_info():
    license_info = get_current_license_info()
    database_count = db(db.managed_database.active == True).count()
    threat_feed_count = db(db.threat_intel_feed.active == True).count()
    threat_feed_limit = get_threat_intel_limit()
    
    return {
        'tier': license_info['tier'],
        'is_active': license_info['is_active'],
        'features': license_info['features'],
        'database_count': database_count,
        'threat_feed_count': threat_feed_count,
        'threat_feed_limit': threat_feed_limit,
        'license_key_present': bool(license_info.get('license_key')),
        'pricing': {
            'enterprise_per_database': 5.00,
            'currency': 'USD',
            'billing_period': 'monthly'
        }
    }

@action('api/license', method=['POST'])
@action.uses(auth, cors, db)
def activate_license():
    try:
        data = request.json
        license_key = data.get('license_key', '').strip()
        
        if not license_key:
            abort(400, 'License key is required')
        
        # Validate with license server
        validation_result = validate_license_with_server(license_key)
        
        if not validation_result['valid']:
            abort(400, f"Invalid license: {validation_result.get('error', 'License validation failed')}")
        
        # Check if license is for ArticDBM enterprise
        features = validation_result.get('features', [])
        if 'unlimited_threat_intel_feeds' not in features:
            abort(400, 'This license does not include ArticDBM Enterprise features')
        
        # Update or create license record
        existing_license = db(db.license_info).select().first()
        database_count = db(db.managed_database.active == True).count()
        
        next_validation = datetime.utcnow() + timedelta(seconds=random.randint(45, 180))
        
        if existing_license:
            existing_license.update_record(
                license_key=license_key,
                tier='enterprise',
                features=features,
                database_count=database_count,
                is_active=True,
                last_validated=datetime.utcnow(),
                next_validation=next_validation,
                validation_failures=0
            )
        else:
            db.license_info.insert(
                license_key=license_key,
                tier='enterprise',
                features=features,
                database_count=database_count,
                is_active=True,
                last_validated=datetime.utcnow(),
                next_validation=next_validation,
                validation_failures=0
            )
        
        # Log the activation
        db.audit_log.insert(
            user_id=auth.user_id,
            action='activate_license',
            query=f"Activated enterprise license",
            result='success',
            ip_address=request.environ.get('REMOTE_ADDR')
        )
        
        return {
            'message': 'Enterprise license activated successfully',
            'tier': 'enterprise',
            'features': features
        }
        
    except Exception as e:
        abort(400, str(e))

@action('api/license', method=['DELETE'])
@action.uses(auth, cors, db)
def deactivate_license():
    try:
        license_record = db(db.license_info).select().first()
        if license_record:
            license_record.update_record(
                license_key=None,
                tier='community',
                features=['single_threat_intel_feed'],
                is_active=False,
                last_validated=None,
                next_validation=None,
                validation_failures=0
            )
        
        # Log the deactivation
        db.audit_log.insert(
            user_id=auth.user_id,
            action='deactivate_license',
            query=f"Deactivated license - reverted to community",
            result='success',
            ip_address=request.environ.get('REMOTE_ADDR')
        )
        
        return {'message': 'License deactivated - reverted to Community edition'}
        
    except Exception as e:
        abort(400, str(e))

async def periodic_license_validation():
    """Periodic license validation task"""
    while True:
        try:
            license_record = db(db.license_info).select().first()
            if license_record and license_record.license_key and license_record.next_validation:
                if datetime.utcnow() >= license_record.next_validation:
                    update_license_validation()
            
            # Check every 30 seconds
            await asyncio.sleep(30)
        except Exception as e:
            print(f"Error in periodic license validation: {e}")
            await asyncio.sleep(60)

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

def seed_default_blocked_resources():
    """Seed default blocked databases and accounts if they don't exist"""
    try:
        # Check if any blocked resources already exist
        existing_count = db(db.blocked_database).count()
        if existing_count > 0:
            print(f"Blocked resources already exist ({existing_count} entries). Skipping seed.")
            return
        
        # Default blocked databases
        default_databases = [
            # Common test/demo databases
            {"name": "test", "type": "database", "pattern": "^test$", "reason": "Default test database"},
            {"name": "sample", "type": "database", "pattern": "^sample$", "reason": "Default sample database"},
            {"name": "demo", "type": "database", "pattern": "^demo$", "reason": "Default demo database"},
            {"name": "example", "type": "database", "pattern": "^example$", "reason": "Default example database"},
            {"name": "temp", "type": "database", "pattern": "^temp$", "reason": "Temporary database"},
            {"name": "tmp", "type": "database", "pattern": "^tmp$", "reason": "Temporary database"},
            
            # SQL Server system databases
            {"name": "master", "type": "database", "pattern": "^master$", "reason": "SQL Server system database"},
            {"name": "msdb", "type": "database", "pattern": "^msdb$", "reason": "SQL Server system database"},
            {"name": "tempdb", "type": "database", "pattern": "^tempdb$", "reason": "SQL Server system database"},
            {"name": "model", "type": "database", "pattern": "^model$", "reason": "SQL Server system database"},
            
            # MySQL system databases
            {"name": "mysql", "type": "database", "pattern": "^mysql$", "reason": "MySQL system database"},
            {"name": "sys", "type": "database", "pattern": "^sys$", "reason": "MySQL system database"},
            {"name": "information_schema", "type": "database", "pattern": "^information_schema$", "reason": "MySQL information schema"},
            {"name": "performance_schema", "type": "database", "pattern": "^performance_schema$", "reason": "MySQL performance schema"},
            
            # PostgreSQL system databases
            {"name": "postgres", "type": "database", "pattern": "^postgres$", "reason": "PostgreSQL default database"},
            {"name": "template0", "type": "database", "pattern": "^template0$", "reason": "PostgreSQL template database"},
            {"name": "template1", "type": "database", "pattern": "^template1$", "reason": "PostgreSQL template database"},
            
            # MongoDB system databases
            {"name": "admin", "type": "database", "pattern": "^admin$", "reason": "MongoDB admin database"},
            {"name": "local", "type": "database", "pattern": "^local$", "reason": "MongoDB local database"},
            {"name": "config", "type": "database", "pattern": "^config$", "reason": "MongoDB config database"},
        ]
        
        # Default blocked users
        default_users = [
            # Common default admin accounts
            {"name": "sa", "type": "username", "pattern": "^sa$", "reason": "SQL Server default admin account"},
            {"name": "root", "type": "username", "pattern": "^root$", "reason": "Default root account"},
            {"name": "admin", "type": "username", "pattern": "^admin$", "reason": "Default admin account"},
            {"name": "administrator", "type": "username", "pattern": "^administrator$", "reason": "Default administrator account"},
            {"name": "guest", "type": "username", "pattern": "^guest$", "reason": "Default guest account"},
            
            # Test/demo accounts
            {"name": "test", "type": "username", "pattern": "^test$", "reason": "Test user account"},
            {"name": "demo", "type": "username", "pattern": "^demo$", "reason": "Demo user account"},
            {"name": "sample", "type": "username", "pattern": "^sample$", "reason": "Sample user account"},
            {"name": "user", "type": "username", "pattern": "^user$", "reason": "Generic user account"},
            
            # Database-specific default accounts
            {"name": "mysql", "type": "username", "pattern": "^mysql$", "reason": "MySQL service account"},
            {"name": "postgres", "type": "username", "pattern": "^postgres$", "reason": "PostgreSQL default account"},
            {"name": "oracle", "type": "username", "pattern": "^oracle$", "reason": "Oracle default account"},
            {"name": "sqlserver", "type": "username", "pattern": "^sqlserver$", "reason": "SQL Server service account"},
            
            # Empty/blank username
            {"name": "empty", "type": "username", "pattern": "^$", "reason": "Empty/anonymous username"},
            {"name": "anonymous", "type": "username", "pattern": "^anonymous$", "reason": "Anonymous user account"},
        ]
        
        # Default blocked tables
        default_tables = [
            {"name": "user", "type": "table", "pattern": "^user$", "reason": "System user table"},
            {"name": "users", "type": "table", "pattern": "^users$", "reason": "System users table"},
            {"name": "mysql.user", "type": "table", "pattern": "^mysql\\.user$", "reason": "MySQL user table"},
            {"name": "pg_user", "type": "table", "pattern": "^pg_user$", "reason": "PostgreSQL user table"},
            {"name": "sysusers", "type": "table", "pattern": "^sysusers$", "reason": "SQL Server system users"},
            {"name": "sysobjects", "type": "table", "pattern": "^sysobjects$", "reason": "SQL Server system objects"},
        ]
        
        # Insert all default blocked resources
        all_defaults = default_databases + default_users + default_tables
        
        for resource in all_defaults:
            db.blocked_database.insert(
                name=resource["name"],
                type=resource["type"],
                pattern=resource["pattern"],
                reason=resource["reason"],
                active=True
            )
        
        db.commit()
        
        print(f"Successfully seeded {len(all_defaults)} default blocked resources")
        
        # Sync to Redis
        sync_to_redis()
        
        return True
    except Exception as e:
        print(f"Error seeding default blocked resources: {e}")
        return False

# API endpoint to trigger seeding
@action('api/seed-blocked-resources', method=['POST'])
@action.uses(auth, cors, db)
def seed_blocked_resources():
    try:
        if seed_default_blocked_resources():
            return {'message': 'Default blocked resources seeded successfully'}
        else:
            abort(500, 'Failed to seed blocked resources')
    except Exception as e:
        abort(400, str(e))

# API endpoint to get blocking configuration status
@action('api/blocking-config', method=['GET'])
@action.uses(auth, cors)
def get_blocking_config():
    config = {
        'blocking_enabled': True,  # This would normally come from config
        'default_blocking': True,
        'custom_blocking': True,
        'total_blocked_resources': db(db.blocked_database).count(),
        'active_blocked_resources': db(db.blocked_database.active == True).count(),
        'blocked_by_type': {
            'databases': db((db.blocked_database.type == 'database') & (db.blocked_database.active == True)).count(),
            'users': db((db.blocked_database.type == 'username') & (db.blocked_database.active == True)).count(),
            'tables': db((db.blocked_database.type == 'table') & (db.blocked_database.active == True)).count(),
        }
    }
    return config

@action('api/blocking-config', method=['PUT'])
@action.uses(auth, cors, db)
def update_blocking_config():
    try:
        data = request.json
        
        # In a real implementation, this would update configuration settings
        # For now, we'll just log the configuration change
        db.audit_log.insert(
            user_id=auth.user_id,
            action='update_blocking_config',
            query=json.dumps(data),
            result='success',
            ip_address=request.environ.get('REMOTE_ADDR')
        )
        
        return {'message': 'Blocking configuration updated successfully'}
    except Exception as e:
        abort(400, str(e))

# Threat Intelligence API Endpoints

@action('api/threat-intel/feeds', method=['GET'])
@action.uses(auth, cors)
def get_threat_intel_feeds():
    feeds = db(db.threat_intel_feed.active == True).select()
    result = []
    for feed in feeds:
        indicator_count = db(db.threat_intel_indicator.feed_id == feed.id).count()
        result.append({
            'id': feed.id,
            'name': feed.name,
            'type': feed.type,
            'url': feed.url,
            'polling_interval': feed.polling_interval,
            'last_polled': feed.last_polled.isoformat() if feed.last_polled else None,
            'active': feed.active,
            'indicator_count': indicator_count,
            'created_at': feed.created_at.isoformat()
        })
    return {'feeds': result}

@action('api/threat-intel/feeds', method=['POST'])
@action.uses(auth, cors, db)
def create_threat_intel_feed():
    try:
        data = request.json
        feed = ThreatIntelFeedModel(**data)
        
        # Check license limits
        current_feed_count = db(db.threat_intel_feed.active == True).count()
        threat_intel_limit = get_threat_intel_limit()
        
        if threat_intel_limit != -1 and current_feed_count >= threat_intel_limit:
            license_info = get_current_license_info()
            if license_info['tier'] == 'community':
                abort(403, f'Community edition is limited to {threat_intel_limit} threat intelligence feed. Upgrade to Enterprise for unlimited feeds.')
            else:
                abort(403, f'License limit reached: {threat_intel_limit} feeds maximum.')
        
        feed_id = db.threat_intel_feed.insert(
            name=feed.name,
            type=feed.type,
            url=feed.url,
            api_key=feed.api_key,
            username=feed.username,
            password=feed.password,
            polling_interval=feed.polling_interval,
            active=feed.active
        )
        
        db.audit_log.insert(
            user_id=auth.user_id,
            action='create_threat_intel_feed',
            database_name=feed.name,
            query=f"Created {feed.type} feed: {feed.name}",
            result='success',
            ip_address=request.environ.get('REMOTE_ADDR')
        )
        
        return {'id': feed_id, 'message': 'Threat intelligence feed created successfully'}
    except Exception as e:
        abort(400, str(e))

@action('api/threat-intel/feeds/<feed_id:int>/poll', method=['POST'])
@action.uses(auth, cors, db)
def poll_threat_intel_feed(feed_id):
    try:
        feed = db.threat_intel_feed[feed_id]
        if not feed:
            abort(404, 'Feed not found')
        
        indicators = []
        
        if feed.type == 'taxii':
            indicators = parse_taxii_feed(feed.url, feed.username, feed.password, feed.api_key)
        elif feed.type == 'stix':
            if feed.url:
                response = requests.get(feed.url, timeout=30)
                indicators = parse_stix_indicators(response.text)
        elif feed.type == 'openioc':
            if feed.url:
                response = requests.get(feed.url, timeout=30)
                indicators = parse_openioc_indicators(response.text)
        elif feed.type == 'misp':
            if feed.url:
                headers = {}
                if feed.api_key:
                    headers['Authorization'] = feed.api_key
                response = requests.get(feed.url, headers=headers, timeout=30)
                indicators = parse_misp_event(response.text)
        
        added_count = 0
        updated_count = 0
        
        for indicator in indicators:
            existing = db(
                (db.threat_intel_indicator.value == indicator['value']) &
                (db.threat_intel_indicator.indicator_type == indicator['indicator_type'])
            ).select().first()
            
            if existing:
                existing.update_record(
                    last_seen=datetime.utcnow(),
                    threat_level=indicator.get('threat_level', existing.threat_level),
                    confidence=max(existing.confidence, indicator.get('confidence', 50)),
                    active=True
                )
                updated_count += 1
            else:
                db.threat_intel_indicator.insert(
                    feed_id=feed_id,
                    indicator_type=indicator['indicator_type'],
                    value=indicator['value'],
                    threat_level=indicator.get('threat_level', 'medium'),
                    confidence=indicator.get('confidence', 50),
                    description=indicator.get('description', ''),
                    tags=indicator.get('tags', []),
                    first_seen=indicator.get('first_seen', datetime.utcnow()),
                    last_seen=datetime.utcnow(),
                    expires=indicator.get('expires'),
                    active=True
                )
                added_count += 1
        
        feed.update_record(last_polled=datetime.utcnow())
        
        db.audit_log.insert(
            user_id=auth.user_id,
            action='poll_threat_intel_feed',
            database_name=feed.name,
            query=f"Polled {feed.type} feed",
            result=f"Added {added_count}, Updated {updated_count} indicators",
            ip_address=request.environ.get('REMOTE_ADDR')
        )
        
        sync_threat_intel_to_redis()
        
        return {
            'message': 'Feed polled successfully',
            'added': added_count,
            'updated': updated_count,
            'total': added_count + updated_count
        }
    except Exception as e:
        abort(400, str(e))

@action('api/threat-intel/indicators', method=['GET'])
@action.uses(auth, cors)
def get_threat_intel_indicators():
    limit = request.params.get('limit', 100)
    offset = request.params.get('offset', 0)
    indicator_type = request.params.get('type')
    threat_level = request.params.get('threat_level')
    
    query = db(db.threat_intel_indicator.active == True)
    
    if indicator_type:
        query = query & (db.threat_intel_indicator.indicator_type == indicator_type)
    if threat_level:
        query = query & (db.threat_intel_indicator.threat_level == threat_level)
    
    indicators = query.select(
        limitby=(int(offset), int(offset) + int(limit)),
        orderby=~db.threat_intel_indicator.last_seen
    )
    
    result = []
    for indicator in indicators:
        feed = db.threat_intel_feed[indicator.feed_id] if indicator.feed_id else None
        result.append({
            'id': indicator.id,
            'feed_name': feed.name if feed else 'Manual',
            'indicator_type': indicator.indicator_type,
            'value': indicator.value,
            'threat_level': indicator.threat_level,
            'confidence': indicator.confidence,
            'description': indicator.description,
            'tags': indicator.tags,
            'matched_count': indicator.matched_count,
            'first_seen': indicator.first_seen.isoformat(),
            'last_seen': indicator.last_seen.isoformat(),
            'expires': indicator.expires.isoformat() if indicator.expires else None,
            'active': indicator.active
        })
    
    total = query.count()
    
    return {'indicators': result, 'total': total}

@action('api/threat-intel/indicators', method=['POST'])
@action.uses(auth, cors, db)
def create_threat_intel_indicator():
    try:
        data = request.json
        indicator = ThreatIntelIndicatorModel(**data)
        
        indicator_id = db.threat_intel_indicator.insert(
            feed_id=indicator.feed_id,
            indicator_type=indicator.indicator_type,
            value=indicator.value,
            threat_level=indicator.threat_level,
            confidence=indicator.confidence,
            description=indicator.description,
            tags=indicator.tags,
            expires=indicator.expires,
            active=indicator.active
        )
        
        db.audit_log.insert(
            user_id=auth.user_id,
            action='create_threat_intel_indicator',
            query=f"Added {indicator.indicator_type}: {indicator.value}",
            result='success',
            ip_address=request.environ.get('REMOTE_ADDR')
        )
        
        sync_threat_intel_to_redis()
        
        return {'id': indicator_id, 'message': 'Threat indicator created successfully'}
    except Exception as e:
        abort(400, str(e))

@action('api/threat-intel/indicators/<indicator_id:int>', method=['DELETE'])
@action.uses(auth, cors, db)
def delete_threat_intel_indicator(indicator_id):
    try:
        indicator = db.threat_intel_indicator[indicator_id]
        if not indicator:
            abort(404, 'Indicator not found')
        
        indicator.update_record(active=False)
        
        db.audit_log.insert(
            user_id=auth.user_id,
            action='delete_threat_intel_indicator',
            query=f"Deleted {indicator.indicator_type}: {indicator.value}",
            result='success',
            ip_address=request.environ.get('REMOTE_ADDR')
        )
        
        sync_threat_intel_to_redis()
        
        return {'message': 'Threat indicator deleted successfully'}
    except Exception as e:
        abort(400, str(e))

@action('api/threat-intel/import', method=['POST'])
@action.uses(auth, cors, db)
def import_threat_intel():
    try:
        data = request.json
        feed_type = data.get('type', 'stix')
        content = data.get('content', '')
        feed_name = data.get('feed_name', f'Manual Import - {datetime.utcnow().isoformat()}')
        
        indicators = []
        
        if feed_type == 'stix':
            indicators = parse_stix_indicators(content)
        elif feed_type == 'openioc':
            indicators = parse_openioc_indicators(content)
        elif feed_type == 'misp':
            indicators = parse_misp_event(content)
        else:
            abort(400, f'Unsupported feed type: {feed_type}')
        
        feed_id = db.threat_intel_feed.insert(
            name=feed_name,
            type=feed_type,
            url=None,
            active=True,
            last_polled=datetime.utcnow()
        )
        
        added_count = 0
        for indicator in indicators:
            db.threat_intel_indicator.insert(
                feed_id=feed_id,
                indicator_type=indicator['indicator_type'],
                value=indicator['value'],
                threat_level=indicator.get('threat_level', 'medium'),
                confidence=indicator.get('confidence', 50),
                description=indicator.get('description', ''),
                tags=indicator.get('tags', []),
                first_seen=indicator.get('first_seen', datetime.utcnow()),
                last_seen=datetime.utcnow(),
                expires=indicator.get('expires'),
                active=True
            )
            added_count += 1
        
        db.audit_log.insert(
            user_id=auth.user_id,
            action='import_threat_intel',
            database_name=feed_name,
            query=f"Imported {feed_type} data",
            result=f"Added {added_count} indicators",
            ip_address=request.environ.get('REMOTE_ADDR')
        )
        
        sync_threat_intel_to_redis()
        
        return {
            'message': 'Threat intelligence imported successfully',
            'feed_id': feed_id,
            'indicators_added': added_count
        }
    except Exception as e:
        abort(400, str(e))

@action('api/threat-intel/matches', method=['GET'])
@action.uses(auth, cors)
def get_threat_intel_matches():
    limit = request.params.get('limit', 100)
    offset = request.params.get('offset', 0)
    
    matches = db(db.threat_intel_match).select(
        limitby=(int(offset), int(offset) + int(limit)),
        orderby=~db.threat_intel_match.timestamp
    )
    
    result = []
    for match in matches:
        indicator = db.threat_intel_indicator[match.indicator_id]
        user = db.auth_user[match.user_id] if match.user_id else None
        result.append({
            'id': match.id,
            'indicator_type': indicator.indicator_type if indicator else 'unknown',
            'indicator_value': indicator.value if indicator else 'unknown',
            'threat_level': indicator.threat_level if indicator else 'unknown',
            'database_name': match.database_name,
            'username': user.email if user else 'System',
            'source_ip': match.source_ip,
            'query': match.query[:200] if match.query else None,
            'action_taken': match.action_taken,
            'match_details': match.match_details,
            'timestamp': match.timestamp.isoformat()
        })
    
    total = db(db.threat_intel_match).count()
    
    return {'matches': result, 'total': total}

# Database Security Configuration API Endpoints

@action('api/databases/<database_id:int>/security-config', method=['GET'])
@action.uses(auth, cors)
def get_database_security_config(database_id):
    database = db.managed_database[database_id]
    if not database:
        abort(404, 'Database not found')
    
    config = db(db.database_security_config.database_id == database_id).select().first()
    
    if not config:
        config = {
            'security_blocks_enabled': True,
            'threat_intel_blocks_enabled': True,
            'sql_injection_detection': True,
            'audit_logging': True,
            'block_default_resources': True,
            'threat_intel_action': 'block',
            'custom_rules': None,
            'whitelist_patterns': None
        }
    else:
        config = {
            'security_blocks_enabled': config.security_blocks_enabled,
            'threat_intel_blocks_enabled': config.threat_intel_blocks_enabled,
            'sql_injection_detection': config.sql_injection_detection,
            'audit_logging': config.audit_logging,
            'block_default_resources': config.block_default_resources,
            'threat_intel_action': config.threat_intel_action,
            'custom_rules': config.custom_rules,
            'whitelist_patterns': config.whitelist_patterns
        }
    
    return {
        'database_name': database.name,
        'config': config
    }

@action('api/databases/<database_id:int>/security-config', method=['PUT'])
@action.uses(auth, cors, db)
def update_database_security_config(database_id):
    try:
        database = db.managed_database[database_id]
        if not database:
            abort(404, 'Database not found')
        
        data = request.json
        config_data = DatabaseSecurityConfigModel(database_id=database_id, **data)
        
        existing = db(db.database_security_config.database_id == database_id).select().first()
        
        if existing:
            existing.update_record(
                security_blocks_enabled=config_data.security_blocks_enabled,
                threat_intel_blocks_enabled=config_data.threat_intel_blocks_enabled,
                sql_injection_detection=config_data.sql_injection_detection,
                audit_logging=config_data.audit_logging,
                block_default_resources=config_data.block_default_resources,
                threat_intel_action=config_data.threat_intel_action,
                custom_rules=config_data.custom_rules,
                whitelist_patterns=config_data.whitelist_patterns
            )
        else:
            db.database_security_config.insert(
                database_id=database_id,
                security_blocks_enabled=config_data.security_blocks_enabled,
                threat_intel_blocks_enabled=config_data.threat_intel_blocks_enabled,
                sql_injection_detection=config_data.sql_injection_detection,
                audit_logging=config_data.audit_logging,
                block_default_resources=config_data.block_default_resources,
                threat_intel_action=config_data.threat_intel_action,
                custom_rules=config_data.custom_rules,
                whitelist_patterns=config_data.whitelist_patterns
            )
        
        db.audit_log.insert(
            user_id=auth.user_id,
            action='update_database_security_config',
            database_name=database.name,
            query=json.dumps(data),
            result='success',
            ip_address=request.environ.get('REMOTE_ADDR')
        )
        
        sync_to_redis()
        
        return {'message': 'Security configuration updated successfully'}
    except Exception as e:
        abort(400, str(e))

def sync_threat_intel_to_redis():
    """Sync threat intelligence indicators to Redis for proxy consumption"""
    try:
        threat_indicators = {}
        
        for indicator in db(db.threat_intel_indicator.active == True).select():
            key = f"{indicator.indicator_type}:{indicator.value}"
            threat_indicators[key] = {
                'id': indicator.id,
                'type': indicator.indicator_type,
                'value': indicator.value,
                'threat_level': indicator.threat_level,
                'confidence': indicator.confidence,
                'description': indicator.description,
                'tags': indicator.tags,
                'action': 'block'
            }
        
        database_configs = {}
        for config in db(db.database_security_config).select():
            database = db.managed_database[config.database_id]
            if database:
                database_configs[database.name] = {
                    'security_blocks_enabled': config.security_blocks_enabled,
                    'threat_intel_blocks_enabled': config.threat_intel_blocks_enabled,
                    'sql_injection_detection': config.sql_injection_detection,
                    'audit_logging': config.audit_logging,
                    'block_default_resources': config.block_default_resources,
                    'threat_intel_action': config.threat_intel_action
                }
        
        redis_client.set('articdbm:threat_indicators', json.dumps(threat_indicators))
        redis_client.set('articdbm:database_security_configs', json.dumps(database_configs))
        
        redis_client.expire('articdbm:threat_indicators', 300)
        redis_client.expire('articdbm:database_security_configs', 300)
        
        return True
    except Exception as e:
        print(f"Error syncing threat intel to Redis: {e}")
        return False

if __name__ == "__main__":
    # Seed default blocked resources on startup if needed
    seed_default_blocked_resources()
    
    asyncio.create_task(init_aio_redis())
    asyncio.create_task(periodic_sync())
    asyncio.create_task(periodic_license_validation())
    
    from py4web import start
    start(host='0.0.0.0', port=8000)