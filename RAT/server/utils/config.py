"""
Server Configuration - Configuration spécifique au serveur RAT
"""

import os
from pathlib import Path
from typing import Dict, Any, List, Optional

from shared.config import BaseConfig, NetworkConfig, SecurityConfig, LoggingConfig
from shared.constants import DEFAULT_HOST, DEFAULT_PORT

class ServerConfig(BaseConfig):
    """Configuration spécialisée pour le serveur RAT"""
    
    def __init__(self, config_file: Optional[str] = None):
        super().__init__(config_file)
        
        # Configuration serveur spécifique
        self.MAX_CONNECTIONS = 100
        self.HANDSHAKE_TIMEOUT = 10  # secondes
        self.SESSION_TIMEOUT = 300   # 5 minutes
        self.CLEANUP_INTERVAL = 60   # 1 minute
        self.BUFFER_SIZE = 4096
        
        # Répertoires serveur
        self.DATA_DIR = "server/data"
        self.DOWNLOADS_DIR = "server/data/downloads"
        self.UPLOADS_DIR = "server/data/uploads"
        self.SSL_DIR = "server/data/ssl"
        self.LOGS_DIR = "logs"
        
        # Configuration SSL par défaut
        self.SSL_CERT_FILE = os.path.join(self.SSL_DIR, "server-certificate.pem")
        self.SSL_KEY_FILE = os.path.join(self.SSL_DIR, "server-private-key.pem")
        self.SSL_CA_FILE = os.path.join(self.SSL_DIR, "ca-certificate.pem")
        
        # Mise à jour de la configuration réseau avec les valeurs serveur
        if not config_file:  # Seulement si pas de fichier de config fourni
            self.network.host = os.environ.get('RAT_SERVER_HOST', DEFAULT_HOST)
            self.network.port = int(os.environ.get('RAT_SERVER_PORT', DEFAULT_PORT))
            self.network.ssl_cert_file = self.SSL_CERT_FILE
            self.network.ssl_key_file = self.SSL_KEY_FILE
            self.network.ssl_ca_file = self.SSL_CA_FILE
        
        # Création des répertoires nécessaires
        self._create_directories()
        
        # Propriétés de compatibilité (pour l'ancien code)
        self._setup_compatibility_properties()
    
    def _create_directories(self):
        """Crée les répertoires nécessaires"""
        directories = [
            self.DATA_DIR,
            self.DOWNLOADS_DIR,
            self.UPLOADS_DIR,
            self.SSL_DIR,
            self.LOGS_DIR
        ]
        
        for directory in directories:
            Path(directory).mkdir(parents=True, exist_ok=True)
    
    def _setup_compatibility_properties(self):
        """Configure les propriétés de compatibilité avec l'ancien code"""
        # Propriétés réseau
        self.HOST = self.network.host
        self.PORT = self.network.port
        self.USE_SSL = self.network.use_ssl
        
        # Propriétés de logging
        self.DEBUG = self.debug
        
        # Autres propriétés utiles
        self.COMPRESSION_ENABLED = True
        self.MAX_MESSAGE_SIZE = 50 * 1024 * 1024  # 50MB
    
    def update_from_args(self, args):
        """Met à jour la configuration depuis les arguments CLI"""
        if hasattr(args, 'host') and args.host:
            self.network.host = args.host
            self.HOST = args.host
        
        if hasattr(args, 'port') and args.port:
            self.network.port = args.port
            self.PORT = args.port
        
        if hasattr(args, 'ssl') and args.ssl:
            self.network.use_ssl = args.ssl
            self.USE_SSL = args.ssl
        
        if hasattr(args, 'debug') and args.debug:
            self.debug = args.debug
            self.DEBUG = args.debug
            self.logging.level = 'DEBUG'
    
    def get_ssl_config(self) -> Dict[str, str]:
        """Retourne la configuration SSL"""
        return {
            'cert_file': self.network.ssl_cert_file or self.SSL_CERT_FILE,
            'key_file': self.network.ssl_key_file or self.SSL_KEY_FILE,
            'ca_file': self.network.ssl_ca_file or self.SSL_CA_FILE
        }
    
    def validate_ssl_files(self) -> List[str]:
        """Valide la présence des fichiers SSL"""
        errors = []
        
        if self.network.use_ssl:
            ssl_config = self.get_ssl_config()
            
            for file_type, file_path in ssl_config.items():
                if file_path and not Path(file_path).exists():
                    errors.append(f"SSL {file_type} not found: {file_path}")
        
        return errors
    
    def get_server_info(self) -> Dict[str, Any]:
        """Retourne les informations du serveur"""
        return {
            'host': self.network.host,
            'port': self.network.port,
            'use_ssl': self.network.use_ssl,
            'max_connections': self.MAX_CONNECTIONS,
            'debug': self.debug,
            'version': self.version,
            'data_dir': self.DATA_DIR,
            'downloads_dir': self.DOWNLOADS_DIR,
            'uploads_dir': self.UPLOADS_DIR
        }
    
    def create_default_server_config(self) -> Dict[str, Any]:
        """Crée une configuration serveur par défaut"""
        return {
            'network': {
                'host': '0.0.0.0',
                'port': 8888,
                'use_ssl': False,
                'max_connections': 100
            },
            'security': {
                'max_file_size': 100 * 1024 * 1024,
                'session_timeout': 300,
                'enable_command_filtering': True,
                'log_security_events': True
            },
            'logging': {
                'level': 'INFO',
                'enable_console': True,
                'enable_file': True,
                'enable_json': True,
                'log_dir': 'logs'
            },
            'server': {
                'max_connections': 100,
                'handshake_timeout': 10,
                'session_timeout': 300,
                'cleanup_interval': 60,
                'buffer_size': 4096,
                'data_dir': 'server/data',
                'downloads_dir': 'server/data/downloads',
                'uploads_dir': 'server/data/uploads'
            },
            'debug': False,
            'environment': 'development'
        }
    
    def save_default_config(self, config_file: str = "server_config.json") -> bool:
        """Sauvegarde une configuration par défaut"""
        try:
            # Fusion avec la configuration par défaut
            default_config = self.create_default_server_config()
            current_config = self.to_dict()
            
            # Ajout des paramètres serveur spécifiques
            current_config['server'] = {
                'max_connections': self.MAX_CONNECTIONS,
                'handshake_timeout': self.HANDSHAKE_TIMEOUT,
                'session_timeout': self.SESSION_TIMEOUT,
                'cleanup_interval': self.CLEANUP_INTERVAL,
                'buffer_size': self.BUFFER_SIZE,
                'data_dir': self.DATA_DIR,
                'downloads_dir': self.DOWNLOADS_DIR,
                'uploads_dir': self.UPLOADS_DIR
            }
            
            return self.save_to_file(config_file, 'json')
            
        except Exception as e:
            print(f"Error saving default config: {e}")
            return False
    
    def validate_server_config(self) -> List[str]:
        """Valide la configuration serveur"""
        errors = []
        
        # Validation de base
        try:
            self.validate()
        except Exception as e:
            errors.append(str(e))
        
        # Validations spécifiques au serveur
        if self.MAX_CONNECTIONS <= 0:
            errors.append("MAX_CONNECTIONS must be positive")
        
        if self.HANDSHAKE_TIMEOUT <= 0:
            errors.append("HANDSHAKE_TIMEOUT must be positive")
        
        if self.SESSION_TIMEOUT <= 0:
            errors.append("SESSION_TIMEOUT must be positive")
        
        # Validation des répertoires
        critical_dirs = [self.DATA_DIR, self.DOWNLOADS_DIR, self.UPLOADS_DIR]
        for directory in critical_dirs:
            dir_path = Path(directory)
            if not dir_path.exists():
                try:
                    dir_path.mkdir(parents=True, exist_ok=True)
                except Exception as e:
                    errors.append(f"Cannot create directory {directory}: {e}")
            elif not os.access(directory, os.W_OK):
                errors.append(f"Directory not writable: {directory}")
        
        # Validation SSL si activé
        if self.network.use_ssl:
            errors.extend(self.validate_ssl_files())
        
        return errors
    
    def get_connection_string(self) -> str:
        """Retourne la chaîne de connexion du serveur"""
        protocol = "ratss" if self.network.use_ssl else "rat"
        return f"{protocol}://{self.network.host}:{self.network.port}"
    
    def get_bind_address(self) -> tuple:
        """Retourne l'adresse de bind du serveur"""
        return (self.network.host, self.network.port)
    
    def is_production_mode(self) -> bool:
        """Vérifie si on est en mode production"""
        return self.environment == "production" and not self.debug
    
    def get_security_settings(self) -> Dict[str, Any]:
        """Retourne les paramètres de sécurité"""
        return {
            'max_file_size': self.security.max_file_size,
            'max_keylog_duration': self.security.max_keylog_duration,
            'max_webcam_duration': self.security.max_webcam_duration,
            'max_audio_duration': self.security.max_audio_duration,
            'allowed_extensions': self.security.allowed_extensions,
            'dangerous_commands': self.security.dangerous_commands,
            'enable_command_filtering': self.security.enable_command_filtering,
            'enable_file_filtering': self.security.enable_file_filtering,
            'log_security_events': self.security.log_security_events
        }

# === FONCTIONS UTILITAIRES ===

def load_server_config(config_file: Optional[str] = None) -> ServerConfig:
    """Charge la configuration serveur"""
    config = ServerConfig(config_file)
    
    # Mise à jour depuis les variables d'environnement
    config.update_from_env('RAT_SERVER_')
    
    return config

def create_server_config_from_env() -> ServerConfig:
    """Crée une configuration serveur depuis les variables d'environnement"""
    config = ServerConfig()
    
    # Variables d'environnement spécifiques au serveur
    env_mappings = {
        'RAT_SERVER_HOST': 'network.host',
        'RAT_SERVER_PORT': 'network.port',
        'RAT_SERVER_SSL': 'network.use_ssl',
        'RAT_SERVER_MAX_CONNECTIONS': 'MAX_CONNECTIONS',
        'RAT_SERVER_DEBUG': 'debug',
        'RAT_SERVER_DATA_DIR': 'DATA_DIR',
        'RAT_SERVER_LOG_LEVEL': 'logging.level'
    }
    
    for env_var, config_path in env_mappings.items():
        if env_var in os.environ:
            value = os.environ[env_var]
            
            # Conversion de type
            if 'PORT' in env_var or 'CONNECTIONS' in env_var:
                try:
                    value = int(value)
                except ValueError:
                    continue
            elif 'SSL' in env_var or 'DEBUG' in env_var:
                value = value.lower() in ('true', '1', 'yes', 'on')
            
            # Application de la valeur
            try:
                if '.' in config_path:
                    section, key = config_path.split('.', 1)
                    if hasattr(config, section):
                        section_obj = getattr(config, section)
                        if hasattr(section_obj, key):
                            setattr(section_obj, key, value)
                else:
                    if hasattr(config, config_path):
                        setattr(config, config_path, value)
            except Exception:
                pass  # Ignore les erreurs de configuration
    
    return config

def validate_server_environment() -> List[str]:
    """Valide l'environnement serveur"""
    issues = []
    
    # Vérification des permissions
    if os.name == 'posix':  # Unix/Linux
        if os.geteuid() == 0:
            issues.append("Running as root is not recommended for security")
    
    # Vérification de l'espace disque
    try:
        import shutil
        total, used, free = shutil.disk_usage('.')
        if free < 1024 * 1024 * 1024:  # Moins de 1GB libre
            issues.append(f"Low disk space: {free // (1024*1024)}MB free")
    except Exception:
        pass
    
    # Vérification des ports privilégiés
    import socket
    try:
        port = int(os.environ.get('RAT_SERVER_PORT', DEFAULT_PORT))
        if port < 1024 and os.name == 'posix' and os.geteuid() != 0:
            issues.append(f"Port {port} requires root privileges on Unix systems")
    except ValueError:
        pass
    
    return issues