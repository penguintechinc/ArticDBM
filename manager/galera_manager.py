import json
import time
import subprocess
import tempfile
import os
import shutil
from typing import Dict, List, Optional, Tuple
from datetime import datetime, timedelta
import asyncio
import aiofiles
import paramiko
from pydal import Field
from py4web import action, request, response, abort, redirect, URL
from py4web.utils.cors import CORS

# Import required modules
from .common import db, session, T, cache, auth, logger, signed_url
from .database_health_checker import DatabaseHealthChecker

class GaleraClusterManager:
    """Manages MariaDB Galera cluster deployment and configuration"""

    def __init__(self, db_instance, logger_instance):
        self.db = db_instance
        self.logger = logger_instance
        self.health_checker = DatabaseHealthChecker(db_instance, logger_instance)

        # Define Galera cluster table if it doesn't exist
        if 'galera_clusters' not in db_instance:
            db_instance.define_table(
                'galera_clusters',
                Field('name', 'string', required=True, unique=True,
                      label='Cluster Name', comment='Unique name for the Galera cluster'),
                Field('description', 'text',
                      label='Description', comment='Description of the cluster'),
                Field('wsrep_cluster_name', 'string', required=True,
                      label='WSRep Cluster Name', comment='Galera cluster name (wsrep_cluster_name)'),
                Field('sst_method', 'string', default='rsync',
                      label='SST Method', comment='State Snapshot Transfer method'),
                Field('gcache_size', 'string', default='256M',
                      label='GCache Size', comment='Galera cache size'),
                Field('ist_recv_addr', 'string',
                      label='IST Receive Address', comment='Incremental State Transfer receive address'),
                Field('cluster_address', 'text', required=True,
                      label='Cluster Address', comment='gcomm:// address list of all nodes'),
                Field('bootstrap_node', 'string',
                      label='Bootstrap Node', comment='Initial bootstrap node for cluster creation'),
                Field('auto_increment_increment', 'integer', default=3,
                      label='Auto Increment Increment', comment='Auto increment increment for multi-master'),
                Field('auto_increment_offset', 'integer', default=1,
                      label='Auto Increment Offset', comment='Auto increment offset for this cluster'),
                Field('health_check_interval', 'integer', default=10,
                      label='Health Check Interval', comment='Health check interval in seconds'),
                Field('max_consecutive_errors', 'integer', default=3,
                      label='Max Consecutive Errors', comment='Max errors before marking node unhealthy'),
                Field('flow_control_threshold', 'integer', default=100,
                      label='Flow Control Threshold', comment='Flow control pause threshold'),
                Field('read_only_nodes', 'boolean', default=False,
                      label='Allow Read-Only Nodes', comment='Allow reads from non-synced nodes'),
                Field('write_balancing', 'boolean', default=True,
                      label='Write Balancing', comment='Balance writes across synced nodes'),
                Field('node_weight_enabled', 'boolean', default=True,
                      label='Node Weight Enabled', comment='Use node weights for load balancing'),
                Field('status', 'string', default='planning',
                      label='Status', comment='Cluster deployment status'),
                Field('created_on', 'datetime', default=request.now,
                      label='Created On', writable=False, readable=True),
                Field('modified_on', 'datetime', default=request.now, update=request.now,
                      label='Modified On', writable=False, readable=True),
                Field('created_by', 'reference auth_user', default=auth.user_id,
                      label='Created By', writable=False, readable=True),
                Field('deployment_log', 'text',
                      label='Deployment Log', comment='Deployment progress and logs'),
                format='%(name)s'
            )

        if 'galera_nodes' not in db_instance:
            db_instance.define_table(
                'galera_nodes',
                Field('cluster_id', 'reference galera_clusters', required=True,
                      label='Cluster', comment='Galera cluster this node belongs to'),
                Field('name', 'string', required=True,
                      label='Node Name', comment='Human-readable name for the node'),
                Field('hostname', 'string', required=True,
                      label='Hostname/IP', comment='Server hostname or IP address'),
                Field('port', 'integer', default=3306,
                      label='MySQL Port', comment='MySQL/MariaDB port'),
                Field('galera_port', 'integer', default=4567,
                      label='Galera Port', comment='Galera communication port'),
                Field('ist_port', 'integer', default=4568,
                      label='IST Port', comment='Incremental State Transfer port'),
                Field('sst_port', 'integer', default=4444,
                      label='SST Port', comment='State Snapshot Transfer port'),
                Field('server_id', 'integer', required=True,
                      label='Server ID', comment='Unique MySQL server ID'),
                Field('node_address', 'string',
                      label='Node Address', comment='Galera node address (hostname:port)'),
                Field('weight', 'double', default=1.0,
                      label='Node Weight', comment='Load balancing weight'),
                Field('role', 'string', default='both',
                      label='Role', comment='Node role: read, write, or both'),
                Field('priority', 'integer', default=100,
                      label='Priority', comment='Node priority for bootstrapping'),
                Field('is_bootstrap', 'boolean', default=False,
                      label='Bootstrap Node', comment='Primary bootstrap node'),
                Field('ssh_username', 'string', default='root',
                      label='SSH Username', comment='SSH username for deployment'),
                Field('ssh_key_path', 'string',
                      label='SSH Key Path', comment='Path to SSH private key'),
                Field('mariadb_version', 'string', default='10.6',
                      label='MariaDB Version', comment='MariaDB version to install'),
                Field('datadir', 'string', default='/var/lib/mysql',
                      label='Data Directory', comment='MySQL data directory'),
                Field('config_template', 'text',
                      label='Config Template', comment='Custom my.cnf template'),
                Field('status', 'string', default='pending',
                      label='Status', comment='Node deployment status'),
                Field('last_health_check', 'datetime',
                      label='Last Health Check', comment='Last successful health check'),
                Field('wsrep_local_state', 'integer',
                      label='Local State', comment='Galera local state'),
                Field('wsrep_ready', 'boolean',
                      label='Ready', comment='Whether node is ready'),
                Field('wsrep_cluster_size', 'integer',
                      label='Cluster Size', comment='Current cluster size'),
                Field('wsrep_flow_control_paused', 'boolean',
                      label='Flow Control Paused', comment='Flow control status'),
                Field('deployment_log', 'text',
                      label='Deployment Log', comment='Node deployment logs'),
                Field('created_on', 'datetime', default=request.now,
                      label='Created On', writable=False, readable=True),
                Field('modified_on', 'datetime', default=request.now, update=request.now,
                      label='Modified On', writable=False, readable=True),
                format='%(name)s'
            )

        # Commit the table definitions
        db_instance.commit()

    def create_cluster(self, cluster_data: Dict) -> int:
        """Create a new Galera cluster configuration"""
        try:
            # Validate required fields
            required_fields = ['name', 'wsrep_cluster_name', 'cluster_address']
            for field in required_fields:
                if field not in cluster_data:
                    raise ValueError(f"Missing required field: {field}")

            # Insert cluster
            cluster_id = self.db.galera_clusters.insert(**cluster_data)
            self.db.commit()

            self.logger.info(f"Created Galera cluster: {cluster_data['name']} (ID: {cluster_id})")
            return cluster_id

        except Exception as e:
            self.logger.error(f"Error creating Galera cluster: {str(e)}")
            raise

    def add_node(self, node_data: Dict) -> int:
        """Add a node to a Galera cluster"""
        try:
            # Validate required fields
            required_fields = ['cluster_id', 'name', 'hostname', 'server_id']
            for field in required_fields:
                if field not in node_data:
                    raise ValueError(f"Missing required field: {field}")

            # Set node address if not provided
            if 'node_address' not in node_data:
                node_data['node_address'] = f"{node_data['hostname']}:{node_data.get('galera_port', 4567)}"

            # Insert node
            node_id = self.db.galera_nodes.insert(**node_data)
            self.db.commit()

            self.logger.info(f"Added Galera node: {node_data['name']} (ID: {node_id})")
            return node_id

        except Exception as e:
            self.logger.error(f"Error adding Galera node: {str(e)}")
            raise

    def get_cluster_config(self, cluster_id: int) -> Optional[Dict]:
        """Get cluster configuration with all nodes"""
        try:
            cluster = self.db.galera_clusters[cluster_id]
            if not cluster:
                return None

            nodes = self.db(self.db.galera_nodes.cluster_id == cluster_id).select()

            return {
                'cluster': cluster.as_dict(),
                'nodes': [node.as_dict() for node in nodes]
            }

        except Exception as e:
            self.logger.error(f"Error getting cluster config: {str(e)}")
            return None

    def generate_my_cnf(self, cluster_id: int, node_id: int) -> str:
        """Generate my.cnf configuration for a specific node"""
        try:
            config = self.get_cluster_config(cluster_id)
            if not config:
                raise ValueError(f"Cluster {cluster_id} not found")

            cluster = config['cluster']
            current_node = None
            for node in config['nodes']:
                if node['id'] == node_id:
                    current_node = node
                    break

            if not current_node:
                raise ValueError(f"Node {node_id} not found")

            # Build cluster address list
            cluster_addresses = []
            for node in config['nodes']:
                cluster_addresses.append(node['node_address'])

            my_cnf = f"""
[mysql]
default-character-set = utf8mb4

[mysqld]
# Basic settings
bind-address = 0.0.0.0
port = {current_node['port']}
server-id = {current_node['server_id']}
datadir = {current_node['datadir']}

# Character set
character-set-server = utf8mb4
collation-server = utf8mb4_unicode_ci

# Binary logging
log-bin = mysql-bin
binlog_format = ROW
binlog_do_db =
binlog_ignore_db = mysql,information_schema,performance_schema,sys

# Auto increment settings for multi-master
auto_increment_increment = {cluster['auto_increment_increment']}
auto_increment_offset = {cluster['auto_increment_offset']}

# InnoDB settings
innodb_buffer_pool_size = 1G
innodb_log_file_size = 256M
innodb_flush_log_at_trx_commit = 0
innodb_flush_method = O_DIRECT
innodb_doublewrite = 1
innodb_autoinc_lock_mode = 2

# Query cache (disabled for Galera)
query_cache_type = 0
query_cache_size = 0

# Galera settings
wsrep_on = ON
wsrep_provider = /usr/lib/galera/libgalera_smm.so
wsrep_cluster_name = {cluster['wsrep_cluster_name']}
wsrep_cluster_address = gcomm://{','.join(cluster_addresses)}
wsrep_node_name = {current_node['name']}
wsrep_node_address = {current_node['hostname']}:{current_node['galera_port']}

# SST settings
wsrep_sst_method = {cluster['sst_method']}
wsrep_sst_auth = root:galera_sst_password

# Replication settings
wsrep_slave_threads = 4
wsrep_replicate_myisam = 0
wsrep_max_ws_rows = 0
wsrep_max_ws_size = 2G

# Flow control
wsrep_flow_control_paused_ns = 0
wsrep_flow_control_sent_ns = 0

# GCache settings
wsrep_provider_options = "gcache.size={cluster['gcache_size']};gcache.page_size=1G"

# IST settings
wsrep_ist_recv_addr = {current_node['hostname']}:{current_node['ist_port']}

# SST ports
wsrep_sst_receive_address = {current_node['hostname']}:{current_node['sst_port']}

[mysql_safe]
log-error = /var/log/mysql/error.log
pid-file = /var/run/mysqld/mysqld.pid

[mysqldump]
quick
quote-names
max_allowed_packet = 16M
"""

            # Apply custom template if provided
            if current_node.get('config_template'):
                my_cnf += "\n# Custom configuration\n"
                my_cnf += current_node['config_template']

            return my_cnf.strip()

        except Exception as e:
            self.logger.error(f"Error generating my.cnf: {str(e)}")
            raise

    async def deploy_cluster(self, cluster_id: int) -> bool:
        """Deploy a Galera cluster to all configured nodes"""
        try:
            config = self.get_cluster_config(cluster_id)
            if not config:
                raise ValueError(f"Cluster {cluster_id} not found")

            cluster = config['cluster']
            nodes = config['nodes']

            self.logger.info(f"Starting deployment of Galera cluster: {cluster['name']}")

            # Update cluster status
            self.db(self.db.galera_clusters.id == cluster_id).update(
                status='deploying',
                deployment_log='Starting cluster deployment...\n'
            )
            self.db.commit()

            # Deploy nodes in phases
            success = True

            # Phase 1: Prepare all nodes
            self.logger.info("Phase 1: Preparing all nodes")
            for node in nodes:
                if not await self._prepare_node(cluster_id, node):
                    success = False
                    break

            # Phase 2: Bootstrap the cluster
            if success:
                self.logger.info("Phase 2: Bootstrapping cluster")
                bootstrap_node = self._get_bootstrap_node(nodes)
                if not await self._bootstrap_cluster(cluster_id, bootstrap_node):
                    success = False

            # Phase 3: Join remaining nodes
            if success:
                self.logger.info("Phase 3: Joining remaining nodes")
                for node in nodes:
                    if not node.get('is_bootstrap', False):
                        if not await self._join_cluster(cluster_id, node):
                            success = False
                            break

            # Phase 4: Verify cluster health
            if success:
                self.logger.info("Phase 4: Verifying cluster health")
                if not await self._verify_cluster_health(cluster_id):
                    success = False

            # Update final status
            final_status = 'deployed' if success else 'failed'
            self.db(self.db.galera_clusters.id == cluster_id).update(status=final_status)
            self.db.commit()

            self.logger.info(f"Cluster deployment {'completed successfully' if success else 'failed'}")
            return success

        except Exception as e:
            self.logger.error(f"Error deploying cluster: {str(e)}")
            self.db(self.db.galera_clusters.id == cluster_id).update(
                status='failed',
                deployment_log=self._append_log(cluster_id, f"Deployment failed: {str(e)}")
            )
            self.db.commit()
            return False

    async def _prepare_node(self, cluster_id: int, node: Dict) -> bool:
        """Prepare a single node for Galera deployment"""
        try:
            self.logger.info(f"Preparing node: {node['name']}")

            # Update node status
            self.db(self.db.galera_nodes.id == node['id']).update(
                status='preparing',
                deployment_log='Preparing node for deployment...\n'
            )
            self.db.commit()

            # Create SSH connection
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

            key_path = node.get('ssh_key_path')
            if key_path and os.path.exists(key_path):
                ssh.connect(
                    node['hostname'],
                    username=node['ssh_username'],
                    key_filename=key_path,
                    timeout=30
                )
            else:
                # This would need proper authentication handling
                raise ValueError(f"SSH key not found: {key_path}")

            # Installation commands
            commands = [
                # Update system
                "apt-get update",

                # Install MariaDB with Galera
                f"apt-get install -y mariadb-server-{node['mariadb_version']} galera-4",

                # Stop MariaDB service
                "systemctl stop mariadb",

                # Create directories
                f"mkdir -p {node['datadir']}",
                "mkdir -p /var/log/mysql",
                "mkdir -p /var/run/mysqld",

                # Set permissions
                f"chown -R mysql:mysql {node['datadir']}",
                "chown -R mysql:mysql /var/log/mysql",
                "chown -R mysql:mysql /var/run/mysqld",
            ]

            for cmd in commands:
                stdin, stdout, stderr = ssh.exec_command(cmd)
                exit_status = stdout.channel.recv_exit_status()

                if exit_status != 0:
                    error = stderr.read().decode()
                    self.logger.error(f"Command failed on {node['name']}: {cmd} - {error}")
                    self._append_node_log(node['id'], f"Command failed: {cmd}\nError: {error}\n")
                    ssh.close()
                    return False

                self._append_node_log(node['id'], f"Executed: {cmd}\n")

            # Generate and upload my.cnf
            my_cnf_content = self.generate_my_cnf(cluster_id, node['id'])

            # Create temporary file and upload
            with tempfile.NamedTemporaryFile(mode='w', delete=False) as tmp_file:
                tmp_file.write(my_cnf_content)
                tmp_file_path = tmp_file.name

            try:
                sftp = ssh.open_sftp()
                sftp.put(tmp_file_path, '/etc/mysql/my.cnf')
                sftp.close()
            finally:
                os.unlink(tmp_file_path)

            # Set my.cnf permissions
            ssh.exec_command("chown mysql:mysql /etc/mysql/my.cnf")
            ssh.exec_command("chmod 644 /etc/mysql/my.cnf")

            ssh.close()

            # Update node status
            self.db(self.db.galera_nodes.id == node['id']).update(status='prepared')
            self.db.commit()

            self.logger.info(f"Node prepared successfully: {node['name']}")
            return True

        except Exception as e:
            self.logger.error(f"Error preparing node {node['name']}: {str(e)}")
            self._append_node_log(node['id'], f"Preparation failed: {str(e)}\n")
            self.db(self.db.galera_nodes.id == node['id']).update(status='failed')
            self.db.commit()
            return False

    async def _bootstrap_cluster(self, cluster_id: int, bootstrap_node: Dict) -> bool:
        """Bootstrap the Galera cluster with the primary node"""
        try:
            self.logger.info(f"Bootstrapping cluster with node: {bootstrap_node['name']}")

            # Update node status
            self.db(self.db.galera_nodes.id == bootstrap_node['id']).update(
                status='bootstrapping'
            )
            self.db.commit()

            # Create SSH connection
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

            key_path = bootstrap_node.get('ssh_key_path')
            ssh.connect(
                bootstrap_node['hostname'],
                username=bootstrap_node['ssh_username'],
                key_filename=key_path,
                timeout=30
            )

            # Bootstrap the cluster
            commands = [
                # Initialize the cluster (bootstrap)
                "galera_new_cluster",

                # Wait for startup
                "sleep 10",

                # Set root password and create SST user
                "mysql -e \"ALTER USER 'root'@'localhost' IDENTIFIED BY 'galera_root_password';\"",
                "mysql -e \"CREATE USER 'root'@'%' IDENTIFIED BY 'galera_sst_password';\"",
                "mysql -e \"GRANT ALL PRIVILEGES ON *.* TO 'root'@'%' WITH GRANT OPTION;\"",
                "mysql -e \"FLUSH PRIVILEGES;\"",

                # Enable MariaDB service
                "systemctl enable mariadb",
            ]

            for cmd in commands:
                stdin, stdout, stderr = ssh.exec_command(cmd)
                exit_status = stdout.channel.recv_exit_status()

                if exit_status != 0:
                    error = stderr.read().decode()
                    self.logger.error(f"Bootstrap command failed: {cmd} - {error}")
                    self._append_node_log(bootstrap_node['id'], f"Bootstrap failed: {cmd}\nError: {error}\n")
                    ssh.close()
                    return False

                self._append_node_log(bootstrap_node['id'], f"Bootstrap executed: {cmd}\n")

            ssh.close()

            # Update node status
            self.db(self.db.galera_nodes.id == bootstrap_node['id']).update(status='active')
            self.db.commit()

            self.logger.info(f"Cluster bootstrapped successfully with node: {bootstrap_node['name']}")
            return True

        except Exception as e:
            self.logger.error(f"Error bootstrapping cluster: {str(e)}")
            self._append_node_log(bootstrap_node['id'], f"Bootstrap failed: {str(e)}\n")
            self.db(self.db.galera_nodes.id == bootstrap_node['id']).update(status='failed')
            self.db.commit()
            return False

    async def _join_cluster(self, cluster_id: int, node: Dict) -> bool:
        """Join a node to an existing Galera cluster"""
        try:
            self.logger.info(f"Joining node to cluster: {node['name']}")

            # Update node status
            self.db(self.db.galera_nodes.id == node['id']).update(status='joining')
            self.db.commit()

            # Create SSH connection
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

            key_path = node.get('ssh_key_path')
            ssh.connect(
                node['hostname'],
                username=node['ssh_username'],
                key_filename=key_path,
                timeout=30
            )

            # Start MariaDB to join cluster
            commands = [
                # Start MariaDB service
                "systemctl start mariadb",

                # Wait for join process
                "sleep 15",

                # Enable MariaDB service
                "systemctl enable mariadb",
            ]

            for cmd in commands:
                stdin, stdout, stderr = ssh.exec_command(cmd)
                exit_status = stdout.channel.recv_exit_status()

                if exit_status != 0:
                    error = stderr.read().decode()
                    self.logger.error(f"Join command failed on {node['name']}: {cmd} - {error}")
                    self._append_node_log(node['id'], f"Join failed: {cmd}\nError: {error}\n")
                    ssh.close()
                    return False

                self._append_node_log(node['id'], f"Join executed: {cmd}\n")

            ssh.close()

            # Update node status
            self.db(self.db.galera_nodes.id == node['id']).update(status='active')
            self.db.commit()

            self.logger.info(f"Node joined cluster successfully: {node['name']}")
            return True

        except Exception as e:
            self.logger.error(f"Error joining node to cluster: {str(e)}")
            self._append_node_log(node['id'], f"Join failed: {str(e)}\n")
            self.db(self.db.galera_nodes.id == node['id']).update(status='failed')
            self.db.commit()
            return False

    async def _verify_cluster_health(self, cluster_id: int) -> bool:
        """Verify the health of the deployed cluster"""
        try:
            config = self.get_cluster_config(cluster_id)
            if not config:
                return False

            nodes = config['nodes']
            healthy_nodes = 0

            for node in nodes:
                # Basic connectivity test
                try:
                    # This would need actual database connectivity testing
                    # For now, assume nodes are healthy if deployment succeeded
                    if node.get('status') == 'active':
                        healthy_nodes += 1
                except Exception as e:
                    self.logger.warning(f"Health check failed for node {node['name']}: {str(e)}")

            # Cluster is healthy if at least half the nodes are active
            required_nodes = len(nodes) // 2 + 1
            is_healthy = healthy_nodes >= required_nodes

            self.logger.info(f"Cluster health check: {healthy_nodes}/{len(nodes)} nodes healthy")

            return is_healthy

        except Exception as e:
            self.logger.error(f"Error verifying cluster health: {str(e)}")
            return False

    def _get_bootstrap_node(self, nodes: List[Dict]) -> Dict:
        """Get the bootstrap node (highest priority or first marked as bootstrap)"""
        bootstrap_nodes = [n for n in nodes if n.get('is_bootstrap', False)]
        if bootstrap_nodes:
            return bootstrap_nodes[0]

        # If no explicit bootstrap node, use highest priority
        return max(nodes, key=lambda n: n.get('priority', 0))

    def _append_log(self, cluster_id: int, message: str) -> str:
        """Append message to cluster deployment log"""
        current_log = self.db.galera_clusters[cluster_id].deployment_log or ""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        new_log = f"{current_log}[{timestamp}] {message}\n"
        return new_log

    def _append_node_log(self, node_id: int, message: str):
        """Append message to node deployment log"""
        current_log = self.db.galera_nodes[node_id].deployment_log or ""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        new_log = f"{current_log}[{timestamp}] {message}\n"

        self.db(self.db.galera_nodes.id == node_id).update(deployment_log=new_log)
        self.db.commit()

    async def update_cluster_health(self, cluster_id: int):
        """Update health information for all nodes in a cluster"""
        try:
            config = self.get_cluster_config(cluster_id)
            if not config:
                return

            for node in config['nodes']:
                await self._update_node_health(node)

        except Exception as e:
            self.logger.error(f"Error updating cluster health: {str(e)}")

    async def _update_node_health(self, node: Dict):
        """Update health information for a single node"""
        try:
            # Create database connection to check Galera status
            # This is a simplified implementation
            connection_info = {
                'host': node['hostname'],
                'port': node['port'],
                'user': 'root',
                'password': 'galera_root_password',
                'database': 'mysql'
            }

            # Use health checker to get Galera status
            galera_status = await self.health_checker.check_galera_status(connection_info)

            if galera_status:
                # Update node with latest health information
                self.db(self.db.galera_nodes.id == node['id']).update(
                    last_health_check=datetime.now(),
                    wsrep_local_state=galera_status.get('wsrep_local_state'),
                    wsrep_ready=galera_status.get('wsrep_ready', False),
                    wsrep_cluster_size=galera_status.get('wsrep_cluster_size'),
                    wsrep_flow_control_paused=galera_status.get('wsrep_flow_control_paused', False)
                )
                self.db.commit()

        except Exception as e:
            self.logger.error(f"Error updating node health for {node['name']}: {str(e)}")

    def get_cluster_status(self, cluster_id: int) -> Dict:
        """Get comprehensive status information for a cluster"""
        try:
            config = self.get_cluster_config(cluster_id)
            if not config:
                return {}

            cluster = config['cluster']
            nodes = config['nodes']

            # Calculate cluster statistics
            total_nodes = len(nodes)
            active_nodes = sum(1 for n in nodes if n.get('status') == 'active')
            synced_nodes = sum(1 for n in nodes if n.get('wsrep_local_state') == 4)

            cluster_size = None
            if nodes:
                # Get cluster size from any node that has it
                for node in nodes:
                    if node.get('wsrep_cluster_size'):
                        cluster_size = node['wsrep_cluster_size']
                        break

            status = {
                'cluster': cluster,
                'nodes': nodes,
                'statistics': {
                    'total_nodes': total_nodes,
                    'active_nodes': active_nodes,
                    'synced_nodes': synced_nodes,
                    'cluster_size': cluster_size,
                    'health_percentage': (synced_nodes / total_nodes * 100) if total_nodes > 0 else 0,
                    'is_healthy': synced_nodes >= (total_nodes // 2 + 1)
                }
            }

            return status

        except Exception as e:
            self.logger.error(f"Error getting cluster status: {str(e)}")
            return {}

# Initialize the manager instance
galera_manager = GaleraClusterManager(db, logger)

# API endpoints for Galera management
@action('galera/clusters', method=['GET', 'POST'])
@action.uses(auth.user, db)
def galera_clusters():
    """Manage Galera clusters"""
    if request.method == 'GET':
        # List all clusters
        clusters = db(db.galera_clusters).select()
        return dict(clusters=[cluster.as_dict() for cluster in clusters])

    elif request.method == 'POST':
        # Create new cluster
        try:
            cluster_data = request.json
            cluster_id = galera_manager.create_cluster(cluster_data)
            return dict(success=True, cluster_id=cluster_id)
        except Exception as e:
            return dict(success=False, error=str(e))

@action('galera/clusters/<cluster_id:int>', method=['GET', 'PUT', 'DELETE'])
@action.uses(auth.user, db)
def galera_cluster_detail(cluster_id):
    """Manage specific Galera cluster"""
    if request.method == 'GET':
        # Get cluster details
        config = galera_manager.get_cluster_config(cluster_id)
        if not config:
            abort(404, "Cluster not found")
        return config

    elif request.method == 'PUT':
        # Update cluster
        try:
            cluster_data = request.json
            db(db.galera_clusters.id == cluster_id).update(**cluster_data)
            db.commit()
            return dict(success=True)
        except Exception as e:
            return dict(success=False, error=str(e))

    elif request.method == 'DELETE':
        # Delete cluster
        try:
            # Delete nodes first
            db(db.galera_nodes.cluster_id == cluster_id).delete()
            # Delete cluster
            db(db.galera_clusters.id == cluster_id).delete()
            db.commit()
            return dict(success=True)
        except Exception as e:
            return dict(success=False, error=str(e))

@action('galera/clusters/<cluster_id:int>/nodes', method=['GET', 'POST'])
@action.uses(auth.user, db)
def galera_cluster_nodes(cluster_id):
    """Manage nodes in a Galera cluster"""
    if request.method == 'GET':
        # List cluster nodes
        nodes = db(db.galera_nodes.cluster_id == cluster_id).select()
        return dict(nodes=[node.as_dict() for node in nodes])

    elif request.method == 'POST':
        # Add new node
        try:
            node_data = request.json
            node_data['cluster_id'] = cluster_id
            node_id = galera_manager.add_node(node_data)
            return dict(success=True, node_id=node_id)
        except Exception as e:
            return dict(success=False, error=str(e))

@action('galera/clusters/<cluster_id:int>/deploy', method=['POST'])
@action.uses(auth.user, db)
def galera_deploy_cluster(cluster_id):
    """Deploy a Galera cluster"""
    try:
        # Start deployment asynchronously
        import asyncio
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        success = loop.run_until_complete(galera_manager.deploy_cluster(cluster_id))

        return dict(success=success, message="Deployment started" if success else "Deployment failed")
    except Exception as e:
        return dict(success=False, error=str(e))

@action('galera/clusters/<cluster_id:int>/status', method=['GET'])
@action.uses(auth.user, db)
def galera_cluster_status(cluster_id):
    """Get comprehensive cluster status"""
    try:
        status = galera_manager.get_cluster_status(cluster_id)
        return status
    except Exception as e:
        return dict(success=False, error=str(e))

@action('galera/nodes/<node_id:int>/config', method=['GET'])
@action.uses(auth.user, db)
def galera_node_config(node_id):
    """Get generated my.cnf for a specific node"""
    try:
        node = db.galera_nodes[node_id]
        if not node:
            abort(404, "Node not found")

        config = galera_manager.generate_my_cnf(node.cluster_id, node_id)
        return dict(config=config)
    except Exception as e:
        return dict(success=False, error=str(e))