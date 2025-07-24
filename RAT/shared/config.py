"""
Configuration - Gestion de la configuration partagée
Configuration centralisée pour serveur et client avec validation
"""

import os
import json
import yaml
from pathlib import Path
from typing import Dict, Any, Optional, Union, List
from dataclasses import dataclass, field
import logging

from .constants import DEFAULT_HOST, DEFAULT_PORT, DEFAULT_CONFIG
from .exceptions import ConfigurationError, DataValidationError

logger = logging.getLogger(__name__)

@dataclass
class NetworkConfig:
    """Configuration réseau"""
    host: str = DEFAULT_HOST
    port: int = DEFAULT_PORT
    use_ssl: bool = False
    ssl_cert_file: Optional[str] = None
    ssl_key_file: Optional[str] = None
    ssl_ca_file: Optional[str] = None
    socket_timeout: int = 30
    connection_timeout: int = 10
    max_connections: int = 100
    
    def validate(self) -> List[str]:
        """Valide la configuration réseau"""
        errors = []
        
        if not isinstance(self.host, str) or not self.host:
            errors.append("Host must be a non-empty string")
        
        if not isinstance(self.port, int) or not (1 <= self.port <= 65535):
            errors.append("Port must be an integer between 1 and 65535")
        
        if self.use_ssl:
            if self.ssl_cert_file and not Path(self.ssl_cert_file).exists():
                errors.append(f"SSL certificate file not found: {self.ssl_cert_file}")
            
            if self.ssl_key_file and not Path(self.ssl_key_file).exists():
                errors.append(f"SSL key file not found: {self.ssl_key_file}")
        
        return errors

@dataclass
class SecurityConfig:
    """Configuration de sécurité"""
    max_file_size: int = 100 * 1024 * 1024  # 100MB
    max_keylog_duration: int = 600  # 10 minutes
    max_webcam_duration: int = 300  # 5 minutes
    max_audio_duration: int = 120   # 2 minutes
    max_screenshot_size: int = 1920 * 1080
    allowed_extensions: List[str] = field(default_factory=lambda: [
        '.txt', '.log', '.cfg', '.conf', '.ini', '.xml', '.json',
        '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.pdf'
    ])
    dangerous_commands: List[str] = field(default_factory=lambda: [
        'format', 'del /s', 'rm -rf /', 'dd if=', 'mkfs'
    ])
    enable_command_filtering: bool = True
    enable_file_filtering: bool = True
    log_security_events: bool = True
    
    def validate(self) -> List[str]:
        """Valide la configuration de sécurité"""
        errors = []
        
        if self.max_file_size <= 0:
            errors.append("max_file_size must be positive")
        
        if self.max_keylog_duration <= 0:
            errors.append("max_keylog_duration must be positive")
        
        return errors

@dataclass
class LoggingConfig:
    """Configuration du logging"""
    level: str = "INFO"
    enable_console: bool = True
    enable_file: bool = True
    enable_json: bool = False
    log_dir: str = "logs"
    max_file_size: int = 10 * 1024 * 1024  # 10MB
    backup_count: int = 5
    enable_colors: bool = True
    log_format: str = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    date_format: str = "%Y-%m-%d %H:%M:%S"
    
    def validate(self) -> List[str]:
        """Valide la configuration de logging"""
        errors = []
        
        valid_levels = ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']
        if self.level.upper() not in valid_levels:
            errors.append(f"Invalid log level: {self.level}")
        
        if self.max_file_size <= 0:
            errors.append("max_file_size must be positive")
        
        return errors

class BaseConfig:
    """Configuration de base avec fonctionnalités communes"""
    
    def __init__(self, config_file: Optional[str] = None):
        self.config_file = config_file
        self.network = NetworkConfig()
        self.security = SecurityConfig()
        self.logging = LoggingConfig()
        
        # Paramètres généraux
        self.debug = False
        self.version = "1.0.0"
        self.environment = "development"  # development, testing, production
        
        if config_file:
            self.load_from_file(config_file)
    
    def load_from_file(self, config_file: str) -> bool:
        """
        Charge la configuration depuis un fichier
        
        Args:
            config_file: Chemin vers le fichier de configuration
        
        Returns:
            bool: True si succès, False sinon
        """
        try:
            config_path = Path(config_file)
            
            if not config_path.exists():
                logger.warning(f"Configuration file not found: {config_file}")
                return False
            
            # Détection du format de fichier
            if config_path.suffix.lower() == '.json':
                return self._load_json_config(config_path)
            elif config_path.suffix.lower() in ['.yml', '.yaml']:
                return self._load_yaml_config(config_path)
            else:
                logger.error(f"Unsupported config file format: {config_path.suffix}")
                return False
                
        except Exception as e:
            logger.error(f"Error loading configuration: {e}")
            return False
    
    def _load_json_config(self, config_path: Path) -> bool:
        """Charge une configuration JSON"""
        try:
            with open(config_path, 'r', encoding='utf-8') as f:
                config_data = json.load(f)
            
            self._apply_config_data(config_data)
            logger.info(f"Configuration loaded from {config_path}")
            return True
            
        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON in config file: {e}")
            return False
    
    def _load_yaml_config(self, config_path: Path) -> bool:
        """Charge une configuration YAML"""
        try:
            import yaml
            
            with open(config_path, 'r', encoding='utf-8') as f:
                config_data = yaml.safe_load(f)
            
            self._apply_config_data(config_data)
            logger.info(f"Configuration loaded from {config_path}")
            return True
            
        except ImportError:
            logger.error("PyYAML not installed, cannot load YAML config")
            return False
        except Exception as e:
            logger.error(f"Error loading YAML config: {e}")
            return False
    
    def _apply_config_data(self, config_data: Dict[str, Any]):
        """Applique les données de configuration"""
        try:
            # Configuration réseau
            if 'network' in config_data:
                network_config = config_data['network']
                for key, value in network_config.items():
                    if hasattr(self.network, key):
                        setattr(self.network, key, value)
            
            # Configuration de sécurité
            if 'security' in config_data:
                security_config = config_data['security']
                for key, value in security_config.items():
                    if hasattr(self.security, key):
                        setattr(self.security, key, value)
            
            # Configuration de logging
            if 'logging' in config_data:
                logging_config = config_data['logging']
                for key, value in logging_config.items():
                    if hasattr(self.logging, key):
                        setattr(self.logging, key, value)
            
            # Paramètres généraux
            general_params = ['debug', 'version', 'environment']
            for param in general_params:
                if param in config_data:
                    setattr(self, param, config_data[param])
                    
        except Exception as e:
            raise ConfigurationError(f"Error applying configuration: {e}")
    
    def save_to_file(self, config_file: str, format: str = 'json') -> bool:
        """
        Sauvegarde la configuration dans un fichier
        
        Args:
            config_file: Chemin vers le fichier de configuration
            format: Format de sauvegarde ('json' ou 'yaml')
        
        Returns:
            bool: True si succès, False sinon
        """
        try:
            config_data = self.to_dict()
            config_path = Path(config_file)
            
            # Création du répertoire parent si nécessaire
            config_path.parent.mkdir(parents=True, exist_ok=True)
            
            if format.lower() == 'json':
                with open(config_path, 'w', encoding='utf-8') as f:
                    json.dump(config_data, f, indent=2, ensure_ascii=False)
            elif format.lower() == 'yaml':
                import yaml
                with open(config_path, 'w', encoding='utf-8') as f:
                    yaml.dump(config_data, f, default_flow_style=False, allow_unicode=True)
            else:
                raise ValueError(f"Unsupported format: {format}")
            
            logger.info(f"Configuration saved to {config_path}")
            return True
            
        except Exception as e:
            logger.error(f"Error saving configuration: {e}")
            return False
    
    def to_dict(self) -> Dict[str, Any]:
        """Convertit la configuration en dictionnaire"""
        return {
            'network': {
                'host': self.network.host,
                'port': self.network.port,
                'use_ssl': self.network.use_ssl,
                'ssl_cert_file': self.network.ssl_cert_file,
                'ssl_key_file': self.network.ssl_key_file,
                'ssl_ca_file': self.network.ssl_ca_file,
                'socket_timeout': self.network.socket_timeout,
                'connection_timeout': self.network.connection_timeout,
                'max_connections': self.network.max_connections
            },
            'security': {
                'max_file_size': self.security.max_file_size,
                'max_keylog_duration': self.security.max_keylog_duration,
                'max_webcam_duration': self.security.max_webcam_duration,
                'max_audio_duration': self.security.max_audio_duration,
                'max_screenshot_size': self.security.max_screenshot_size,
                'allowed_extensions': self.security.allowed_extensions,
                'dangerous_commands': self.security.dangerous_commands,
                'enable_command_filtering': self.security.enable_command_filtering,
                'enable_file_filtering': self.security.enable_file_filtering,
                'log_security_events': self.security.log_security_events
            },
            'logging': {
                'level': self.logging.level,
                'enable_console': self.logging.enable_console,
                'enable_file': self.logging.enable_file,
                'enable_json': self.logging.enable_json,
                'log_dir': self.logging.log_dir,
                'max_file_size': self.logging.max_file_size,
                'backup_count': self.logging.backup_count,
                'enable_colors': self.logging.enable_colors,
                'log_format': self.logging.log_format,
                'date_format': self.logging.date_format
            },
            'debug': self.debug,
            'version': self.version,
            'environment': self.environment
        }
    
    def validate(self) -> bool:
        """
        Valide la configuration complète
        
        Returns:
            bool: True si valide, False sinon
        
        Raises:
            ConfigurationError: Si la configuration est invalide
        """
        all_errors = []
        
        # Validation des sous-configurations
        all_errors.extend(self.network.validate())
        all_errors.extend(self.security.validate())
        all_errors.extend(self.logging.validate())
        
        if all_errors:
            error_message = "Configuration validation failed:\n" + "\n".join(all_errors)
            raise ConfigurationError(error_message)
        
        return True
    
    def get_summary(self) -> str:
        """Retourne un résumé de la configuration"""
        return f"""
Configuration Summary:
  Network: {self.network.host}:{self.network.port} (SSL: {self.network.use_ssl})
  Security: File size limit: {self.security.max_file_size // (1024*1024)}MB
  Logging: Level: {self.logging.level}, Console: {self.logging.enable_console}
  Debug: {self.debug}
  Environment: {self.environment}
        """.strip()
    
    def update_from_env(self, prefix: str = "RAT_"):
        """Met à jour la configuration depuis les variables d'environnement"""
        env_mappings = {
            f"{prefix}HOST": ("network", "host"),
            f"{prefix}PORT": ("network", "port"),
            f"{prefix}USE_SSL": ("network", "use_ssl"),
            f"{prefix}DEBUG": ("debug",),
            f"{prefix}LOG_LEVEL": ("logging", "level"),
            f"{prefix}MAX_FILE_SIZE": ("security", "max_file_size")
        }
        
        for env_var, config_path in env_mappings.items():
            if env_var in os.environ:
                value = os.environ[env_var]
                
                # Conversion de type si nécessaire
                if env_var.endswith("_PORT") or env_var.endswith("_SIZE"):
                    try:
                        value = int(value)
                    except ValueError:
                        logger.warning(f"Invalid integer value for {env_var}: {value}")
                        continue
                elif env_var.endswith("_SSL") or env_var == f"{prefix}DEBUG":
                    value = value.lower() in ('true', '1', 'yes', 'on')
                
                # Application de la valeur
                try:
                    if len(config_path) == 1:
                        setattr(self, config_path[0], value)
                    elif len(config_path) == 2:
                        section = getattr(self, config_path[0])
                        setattr(section, config_path[1], value)
                    
                    logger.info(f"Configuration updated from environment: {env_var}")
                except Exception as e:
                    logger.warning(f"Failed to apply environment variable {env_var}: {e}")

class ConfigManager:
    """Gestionnaire de configuration avec support de profils"""
    
    def __init__(self, config_dir: str = "config"):
        self.config_dir = Path(config_dir)
        self.config_dir.mkdir(parents=True, exist_ok=True)
        self.profiles = {}
        self.current_profile = None
    
    def create_profile(self, name: str, config: BaseConfig) -> bool:
        """Crée un profil de configuration"""
        try:
            profile_file = self.config_dir / f"{name}.json"
            if config.save_to_file(str(profile_file)):
                self.profiles[name] = config
                logger.info(f"Profile '{name}' created")
                return True
        except Exception as e:
            logger.error(f"Failed to create profile '{name}': {e}")
        
        return False
    
    def load_profile(self, name: str) -> Optional[BaseConfig]:
        """Charge un profil de configuration"""
        try:
            profile_file = self.config_dir / f"{name}.json"
            if profile_file.exists():
                config = BaseConfig(str(profile_file))
                self.profiles[name] = config
                self.current_profile = name
                logger.info(f"Profile '{name}' loaded")
                return config
        except Exception as e:
            logger.error(f"Failed to load profile '{name}': {e}")
        
        return None
    
    def list_profiles(self) -> List[str]:
        """Liste les profils disponibles"""
        profiles = []
        for config_file in self.config_dir.glob("*.json"):
            profiles.append(config_file.stem)
        return profiles
    
    def delete_profile(self, name: str) -> bool:
        """Supprime un profil"""
        try:
            profile_file = self.config_dir / f"{name}.json"
            if profile_file.exists():
                profile_file.unlink()
                if name in self.profiles:
                    del self.profiles[name]
                if self.current_profile == name:
                    self.current_profile = None
                logger.info(f"Profile '{name}' deleted")
                return True
        except Exception as e:
            logger.error(f"Failed to delete profile '{name}': {e}")
        
        return False
    
    def get_current_config(self) -> Optional[BaseConfig]:
        """Retourne la configuration du profil courant"""
        if self.current_profile and self.current_profile in self.profiles:
            return self.profiles[self.current_profile]
        return None

# === FONCTIONS UTILITAIRES ===

def create_default_config(config_type: str = "development") -> BaseConfig:
    """Crée une configuration par défaut selon le type"""
    config = BaseConfig()
    
    if config_type == "production":
        config.debug = False
        config.logging.level = "WARNING"
        config.logging.enable_console = False
        config.security.log_security_events = True
        config.environment = "production"
    elif config_type == "testing":
        config.debug = True
        config.logging.level = "DEBUG"
        config.logging.enable_json = True
        config.environment = "testing"
    else:  # development
        config.debug = True
        config.logging.level = "DEBUG"
        config.logging.enable_colors = True
        config.environment = "development"
    
    return config

def merge_configs(base_config: BaseConfig, override_config: Dict[str, Any]) -> BaseConfig:
    """Fusionne une configuration de base avec des overrides"""
    # Sauvegarde temporaire de la config de base
    temp_file = "/tmp/temp_config.json"
    base_config.save_to_file(temp_file)
    
    # Chargement et modification
    merged_config = BaseConfig(temp_file)
    merged_config._apply_config_data(override_config)
    
    # Nettoyage
    try:
        os.unlink(temp_file)
    except:
        pass
    
    return merged_config

def validate_config_file(config_file: str) -> List[str]:
    """Valide un fichier de configuration"""
    errors = []
    
    try:
        config = BaseConfig(config_file)
        config.validate()
    except ConfigurationError as e:
        errors.append(str(e))
    except Exception as e:
        errors.append(f"Failed to load configuration: {e}")
    
    return errors