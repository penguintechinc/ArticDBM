import sys
import getopt
import yaml
from pydal import DAL

class PyDALConnector:
    def __init__(self, argv=None, config_file=None):
        self.db = None
        self.db_settings = {
            'uri': None,
            'folder': './databases',
            'pool_size': 1,
            'fake_migrate_all': False
        }
        if argv:
            self._parse_cli_args(argv)
        if config_file:
            self._parse_yaml_config(config_file)
        if self.db_settings['uri']:
            self.connect()

    def _parse_cli_args(self, argv):
        try:
            opts, _ = getopt.getopt(argv, 'u:f:p:m:')
            for opt, arg in opts:
                if opt == '-u':
                    self.db_settings['uri'] = arg
                elif opt == '-f':
                    self.db_settings['folder'] = arg
                elif opt == '-p':
                    self.db_settings['pool_size'] = int(arg)
                elif opt == '-m':
                    self.db_settings['fake_migrate_all'] = (arg.lower() == 'true')
        except getopt.GetoptError:
            pass

    def _parse_yaml_config(self, config_path):
        with open(config_path, 'r', encoding='utf-8') as file:
            config = yaml.safe_load(file)
            for key in self.db_settings:
                if key in config:
                    self.db_settings[key] = config[key]

    def connect(self):
        self.db = DAL(
            self.db_settings['uri'],
            folder=self.db_settings['folder'],
            pool_size=self.db_settings['pool_size'],
            fake_migrate_all=self.db_settings['fake_migrate_all']
        )

    def create_database(self, request):
        """
        Handles gRPC requests for database creation.
        :param request: gRPC request containing database details.
        :return: Response indicating success or failure.
        """
        try:
            db_name = request.db_name
            if not db_name:
            return {"status": "error", "message": "Database name is required."}
            
            # Create the database
            self.db.define_table(db_name)
            return {"status": "success", "message": f"Database '{db_name}' created successfully."}
        except Exception as e:
            return {"status": "error", "message": str(e)}