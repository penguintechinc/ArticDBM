import yaml
from py4web import action, request, HTTP
from py4web.utils.auth import authenticated
import redis
import ldap3

# Load configuration from YAML file
with open("config.yaml", "r") as config_file:
    config = yaml.safe_load(config_file)

# Redis setup
redis_client = None
if config.get("use_redis"):
    redis_client = redis.StrictRedis(
        host=config["redis"]["host"],
        port=config["redis"]["port"],
        db=config["redis"]["db"],
    )

# LDAP setup
ldap_server = None
ldap_connection = None
if config.get("use_ldap"):
    ldap_server = ldap3.Server(config["ldap"]["server"])
    ldap_connection = ldap3.Connection(
        ldap_server,
        user=config["ldap"]["user"],
        password=config["ldap"]["password"],
        auto_bind=True,
    )

@action("add_user", method=["POST"])
@authenticated
def add_user():
    data = request.json
    if not data or "username" not in data or "password" not in data:
        raise HTTP(400, "Invalid input")

    username = data["username"]
    password = data["password"]

    if config.get("use_redis"):
        if redis_client:
            redis_client.hset("users", username, password)
            return {"status": "success", "message": "User added to Redis"}
        else:
            raise HTTP(500, "Redis is not configured properly")

    elif config.get("use_ldap"):
        if ldap_connection:
            dn = f"cn={username},{config['ldap']['base_dn']}"
            attributes = {
                "objectClass": ["inetOrgPerson"],
                "sn": username,
                "cn": username,
                "userPassword": password,
            }
            ldap_connection.add(dn, attributes=attributes)
            return {"status": "success", "message": "User added to LDAP"}
        else:
            raise HTTP(500, "LDAP is not configured properly")

    else:
        raise HTTP(500, "No valid backend configured")
    
@action("delete_user", method=["POST"])
@authenticated
def delete_user():
    data = request.json
    if not data or "username" not in data:
        raise HTTP(400, "Invalid input")

    username = data["username"]

    if config.get("use_redis"):
        if redis_client:
            if redis_client.hexists("users", username):
                redis_client.hdel("users", username)
                return {"status": "success", "message": "User deleted from Redis"}
            else:
                raise HTTP(404, "User not found in Redis")
        else:
            raise HTTP(500, "Redis is not configured properly")

    elif config.get("use_ldap"):
        if ldap_connection:
            dn = f"cn={username},{config['ldap']['base_dn']}"
            if ldap_connection.search(dn, "(objectClass=*)"):
                ldap_connection.delete(dn)
                return {"status": "success", "message": "User deleted from LDAP"}
            else:
                raise HTTP(404, "User not found in LDAP")
        else:
            raise HTTP(500, "LDAP is not configured properly")

    else:
        raise HTTP(500, "No valid backend configured")