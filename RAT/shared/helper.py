"""
Helpers - Fonctions utilitaires partagées
Fonctions d'aide communes utilisées dans tout le projet
"""

import os
import sys
import time
import hashlib
import base64
import uuid
import platform
import socket
import struct
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, Any, List, Optional, Union, Tuple
import logging
import json
import re

logger = logging.getLogger(__name__)

# === UTILITAIRES SYSTÈME ===

def get_system_info() -> Dict[str, str]:
    """Récupère les informations système de base"""
    return {
        'platform': platform.platform(),
        'system': platform.system(),
        'release': platform.release(),
        'version': platform.version(),
        'machine': platform.machine(),
        'processor': platform.processor(),
        'architecture': platform.architecture()[0],
        'hostname': platform.node(),
        'python_version': platform.python_version()
    }

def is_admin() -> bool:
    """Vérifie si le processus a des privilèges administrateur"""
    try:
        if platform.system().lower() == 'windows':
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        else:
            return os.geteuid() == 0
    except Exception:
        return False

def get_current_user() -> str:
    """Récupère le nom d'utilisateur courant"""
    try:
        import getpass
        return getpass.getuser()
    except Exception:
        return os.environ.get('USER', os.environ.get('USERNAME', 'unknown'))

def get_local_ip() -> str:
    """Récupère l'adresse IP locale"""
    try:
        # Méthode fiable pour obtenir l'IP locale
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"

def get_mac_address() -> str:
    """Récupère l'adresse MAC"""
    try:
        mac = uuid.getnode()
        return ':'.join(['{:02x}'.format((mac >> i) & 0xff) for i in range(0, 48, 8)][::-1])
    except Exception:
        return "00:00:00:00:00:00"

def is_virtual_machine() -> bool:
    """Détecte si on est dans une machine virtuelle"""
    try:
        system_info = platform.platform().lower()
        vm_indicators = ['virtualbox', 'vmware', 'qemu', 'xen', 'hyper-v']
        return any(indicator in system_info for indicator in vm_indicators)
    except Exception:
        return False

def get_process_list() -> List[Dict[str, Any]]:
    """Récupère la liste des processus en cours"""
    processes = []
    try:
        import psutil
        for proc in psutil.process_iter(['pid', 'name', 'username', 'cpu_percent', 'memory_percent']):
            try:
                processes.append(proc.info)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
    except ImportError:
        logger.warning("psutil not available for process listing")
    except Exception as e:
        logger.error(f"Error getting process list: {e}")
    
    return processes

# === UTILITAIRES RÉSEAU ===

def is_port_open(host: str, port: int, timeout: int = 3) -> bool:
    """Vérifie si un port est ouvert"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        sock.close()
        return result == 0
    except Exception:
        return False

def get_network_interfaces() -> Dict[str, List[str]]:
    """Récupère la liste des interfaces réseau"""
    interfaces = {}
    try:
        import psutil
        for interface, addresses in psutil.net_if_addrs().items():
            interface_ips = []
            for addr in addresses:
                if addr.family == socket.AF_INET:
                    interface_ips.append(addr.address)
            if interface_ips:
                interfaces[interface] = interface_ips
    except ImportError:
        logger.warning("psutil not available for network interface listing")
    except Exception as e:
        logger.error(f"Error getting network interfaces: {e}")
    
    return interfaces

def ping_host(host: str, timeout: int = 3) -> bool:
    """Ping un host (méthode portable)"""
    try:
        import subprocess
        
        if platform.system().lower() == 'windows':
            cmd = ['ping', '-n', '1', '-w', str(timeout * 1000), host]
        else:
            cmd = ['ping', '-c', '1', '-W', str(timeout), host]
        
        result = subprocess.run(cmd, capture_output=True, timeout=timeout + 1)
        return result.returncode == 0
    except Exception:
        return False

def resolve_hostname(hostname: str) -> Optional[str]:
    """Résout un nom d'hôte en adresse IP"""
    try:
        return socket.gethostbyname(hostname)
    except Exception:
        return None

# === UTILITAIRES FICHIERS ===

def safe_path_join(*paths) -> str:
    """Joint des chemins de manière sécurisée"""
    # Normalise et joint les chemins en évitant les attaques de traversée
    result = os.path.normpath(os.path.join(*paths))
    
    # Vérification contre les tentatives de traversée
    if '..' in result or result.startswith('/'):
        raise ValueError("Unsafe path detected")
    
    return result

def get_file_hash(file_path: str, algorithm: str = 'sha256') -> Optional[str]:
    """Calcule le hash d'un fichier"""
    try:
        hash_func = hashlib.new(algorithm)
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_func.update(chunk)
        return hash_func.hexdigest()
    except Exception as e:
        logger.error(f"Error calculating file hash: {e}")
        return None

def get_file_info(file_path: str) -> Dict[str, Any]:
    """Récupère les informations détaillées d'un fichier"""
    try:
        path = Path(file_path)
        stat = path.stat()
        
        return {
            'name': path.name,
            'path': str(path.absolute()),
            'size': stat.st_size,
            'is_file': path.is_file(),
            'is_dir': path.is_dir(),
            'modified': datetime.fromtimestamp(stat.st_mtime).isoformat(),
            'created': datetime.fromtimestamp(stat.st_ctime).isoformat(),
            'accessed': datetime.fromtimestamp(stat.st_atime).isoformat(),
            'permissions': oct(stat.st_mode)[-3:],
            'extension': path.suffix.lower(),
            'readable': os.access(file_path, os.R_OK),
            'writable': os.access(file_path, os.W_OK),
            'executable': os.access(file_path, os.X_OK)
        }
    except Exception as e:
        logger.error(f"Error getting file info: {e}")
        return {'error': str(e)}

def sanitize_filename(filename: str) -> str:
    """Nettoie un nom de fichier pour le rendre sécurisé"""
    # Supprime les caractères dangereux
    dangerous_chars = '<>:"/\\|?*'
    for char in dangerous_chars:
        filename = filename.replace(char, '_')
    
    # Limite la longueur
    if len(filename) > 255:
        name, ext = os.path.splitext(filename)
        filename = name[:255-len(ext)] + ext
    
    return filename

def find_files(directory: str, pattern: str, max_results: int = 100) -> List[str]:
    """Recherche des fichiers selon un pattern"""
    found_files = []
    try:
        for root, dirs, files in os.walk(directory):
            for file in files:
                if pattern.lower() in file.lower():
                    found_files.append(os.path.join(root, file))
                    if len(found_files) >= max_results:
                        return found_files
    except Exception as e:
        logger.error(f"Error searching files: {e}")
    
    return found_files

# === UTILITAIRES CRYPTOGRAPHIQUES ===

def generate_random_key(length: int = 32) -> bytes:
    """Génère une clé aléatoire"""
    return os.urandom(length)

def encode_base64(data: Union[str, bytes]) -> str:
    """Encode des données en base64"""
    if isinstance(data, str):
        data = data.encode('utf-8')
    return base64.b64encode(data).decode('ascii')

def decode_base64(data: str) -> bytes:
    """Décode des données base64"""
    return base64.b64decode(data.encode('ascii'))

def hash_string(data: str, algorithm: str = 'sha256') -> str:
    """Hash une chaîne de caractères"""
    hash_func = hashlib.new(algorithm)
    hash_func.update(data.encode('utf-8'))
    return hash_func.hexdigest()

def generate_session_id() -> str:
    """Génère un ID de session unique"""
    return f"agent_{uuid.uuid4().hex[:8]}"

def encrypt_xor(data: bytes, key: bytes) -> bytes:
    """Chiffrement XOR simple (pour usage éducatif uniquement)"""
    return bytes(a ^ b for a, b in zip(data, key * (len(data) // len(key) + 1)))

def decrypt_xor(data: bytes, key: bytes) -> bytes:
    """Déchiffrement XOR simple"""
    return encrypt_xor(data, key)  # XOR est symétrique

# === UTILITAIRES TEMPORELS ===

def get_timestamp() -> float:
    """Récupère le timestamp courant"""
    return time.time()

def get_formatted_time(timestamp: Optional[float] = None, format: str = "%Y-%m-%d %H:%M:%S") -> str:
    """Formate un timestamp"""
    if timestamp is None:
        timestamp = time.time()
    return datetime.fromtimestamp(timestamp).strftime(format)

def time_ago(timestamp: float) -> str:
    """Convertit un timestamp en format 'il y a X'"""
    now = time.time()
    diff = int(now - timestamp)
    
    if diff < 60:
        return f"{diff}s ago"
    elif diff < 3600:
        return f"{diff // 60}m ago"
    elif diff < 86400:
        return f"{diff // 3600}h ago"
    else:
        return f"{diff // 86400}d ago"

def parse_duration(duration_str: str) -> int:
    """Parse une durée (ex: '5m', '2h', '30s') en secondes"""
    match = re.match(r'^(\d+)([smhd])$', duration_str.lower())
    if not match:
        raise ValueError(f"Invalid duration format: {duration_str}")
    
    value, unit = match.groups()
    value = int(value)
    
    multipliers = {'s': 1, 'm': 60, 'h': 3600, 'd': 86400}
    return value * multipliers[unit]

# === UTILITAIRES DATA ===

def format_bytes(bytes_count: int) -> str:
    """Formate une taille en bytes de manière lisible"""
    units = ['B', 'KB', 'MB', 'GB', 'TB']
    size = float(bytes_count)
    
    for unit in units:
        if size < 1024.0:
            return f"{size:.1f} {unit}"
        size /= 1024.0
    
    return f"{size:.1f} PB"

def truncate_string(text: str, max_length: int = 100, suffix: str = "...") -> str:
    """Tronque une chaîne si elle est trop longue"""
    if len(text) <= max_length:
        return text
    return text[:max_length-len(suffix)] + suffix

def sanitize_data(data: Any, max_depth: int = 5) -> Any:
    """Nettoie des données pour éviter les fuites sensibles"""
    if max_depth <= 0:
        return "[MAX_DEPTH_REACHED]"
    
    if isinstance(data, dict):
        sanitized = {}
        for key, value in data.items():
            # Masque les clés sensibles
            if any(keyword in key.lower() for keyword in ['password', 'token', 'key', 'secret']):
                sanitized[key] = "[MASKED]"
            else:
                sanitized[key] = sanitize_data(value, max_depth - 1)
        return sanitized
    
    elif isinstance(data, list):
        return [sanitize_data(item, max_depth - 1) for item in data[:10]]  # Limite à 10 éléments
    
    elif isinstance(data, str):
        # Limite la longueur des chaînes
        if len(data) > 1000:
            return data[:1000] + "[TRUNCATED]"
        return data
    
    else:
        return data

def deep_merge_dicts(dict1: dict, dict2: dict) -> dict:
    """Fusionne récursivement deux dictionnaires"""
    result = dict1.copy()
    
    for key, value in dict2.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = deep_merge_dicts(result[key], value)
        else:
            result[key] = value
    
    return result

# === UTILITAIRES VALIDATION ===

def is_valid_ip(ip: str) -> bool:
    """Valide une adresse IP"""
    try:
        socket.inet_aton(ip)
        return True
    except socket.error:
        return False

def is_valid_port(port: Union[int, str]) -> bool:
    """Valide un numéro de port"""
    try:
        port_int = int(port)
        return 1 <= port_int <= 65535
    except (ValueError, TypeError):
        return False

def is_valid_filename(filename: str) -> bool:
    """Valide un nom de fichier"""
    if not filename or len(filename) > 255:
        return False
    
    invalid_chars = '<>:"/\\|?*'
    return not any(char in filename for char in invalid_chars)

def validate_json(json_str: str) -> Tuple[bool, Optional[dict]]:
    """Valide et parse une chaîne JSON"""
    try:
        data = json.loads(json_str)
        return True, data
    except json.JSONDecodeError:
        return False, None

# === UTILITAIRES LOGGING ===

def log_function_call(func):
    """Décorateur pour logger les appels de fonction"""
    def wrapper(*args, **kwargs):
        logger.debug(f"Calling {func.__name__} with args={args}, kwargs={kwargs}")
        try:
            result = func(*args, **kwargs)
            logger.debug(f"Function {func.__name__} completed successfully")
            return result
        except Exception as e:
            logger.error(f"Function {func.__name__} failed: {e}")
            raise
    return wrapper

def create_audit_log(event: str, details: Dict[str, Any], user: str = None) -> Dict[str, Any]:
    """Crée un log d'audit structuré"""
    return {
        'timestamp': get_timestamp(),
        'event': event,
        'details': sanitize_data(details),
        'user': user or get_current_user(),
        'system': get_system_info()['hostname'],
        'ip': get_local_ip()
    }

# === UTILITAIRES PERFORMANCE ===

class Timer:
    """Context manager pour mesurer le temps d'exécution"""
    
    def __init__(self, name: str = "Operation"):
        self.name = name
        self.start_time = None
        self.end_time = None
    
    def __enter__(self):
        self.start_time = time.time()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.end_time = time.time()
        duration = self.end_time - self.start_time
        logger.debug(f"{self.name} took {duration:.3f} seconds")
    
    @property
    def elapsed(self) -> float:
        """Temps écoulé en secondes"""
        if self.start_time is None:
            return 0
        end = self.end_time or time.time()
        return end - self.start_time

def retry_on_failure(max_attempts: int = 3, delay: float = 1.0, backoff: float = 2.0):
    """Décorateur pour réessayer une fonction en cas d'échec"""
    def decorator(func):
        def wrapper(*args, **kwargs):
            attempt = 1
            current_delay = delay
            
            while attempt <= max_attempts:
                try:
                    return func(*args, **kwargs)
                except Exception as e:
                    if attempt == max_attempts:
                        raise
                    
                    logger.warning(f"Attempt {attempt} failed for {func.__name__}: {e}")
                    time.sleep(current_delay)
                    current_delay *= backoff
                    attempt += 1
            
        return wrapper
    return decorator

# === UTILITAIRES SÉCURITÉ ===

def is_safe_path(path: str, base_path: str = ".") -> bool:
    """Vérifie qu'un chemin est sécurisé (pas de traversée)"""
    try:
        # Résolution des chemins absolus
        abs_path = os.path.abspath(path)
        abs_base = os.path.abspath(base_path)
        
        # Vérification que le chemin est dans le répertoire de base
        return abs_path.startswith(abs_base)
    except Exception:
        return False

def escape_shell_arg(arg: str) -> str:
    """Échapper un argument pour utilisation en shell"""
    # Méthode simple mais efficace
    dangerous_chars = ['&', '|', ';', '$', '`', '\\', '"', "'", ' ', '\t', '\n']
    
    if any(char in arg for char in dangerous_chars):
        # Encadrement par des guillemets et échappement des guillemets internes
        return '"' + arg.replace('"', '\\"') + '"'
    
    return arg

def filter_dangerous_commands(command: str) -> bool:
    """Filtre les commandes dangereuses"""
    dangerous_patterns = [
        'rm -rf', 'del /s', 'format', 'dd if=', 'mkfs',
        '>/dev/', 'shutdown', 'reboot', 'halt'
    ]
    
    command_lower = command.lower()
    return any(pattern in command_lower for pattern in dangerous_patterns)

# === UTILITAIRES CONFIGURATION ===

def load_config_from_env(prefix: str = "RAT_") -> Dict[str, Any]:
    """Charge la configuration depuis les variables d'environnement"""
    config = {}
    
    for key, value in os.environ.items():
        if key.startswith(prefix):
            config_key = key[len(prefix):].lower()
            
            # Conversion de type basique
            if value.lower() in ('true', 'false'):
                config[config_key] = value.lower() == 'true'
            elif value.isdigit():
                config[config_key] = int(value)
            else:
                config[config_key] = value
    
    return config

def get_config_value(config: dict, key: str, default: Any = None) -> Any:
    """Récupère une valeur de configuration avec support des clés imbriquées"""
    keys = key.split('.')
    value = config
    
    try:
        for k in keys:
            value = value[k]
        return value
    except (KeyError, TypeError):
        return default

# === TESTS ET DIAGNOSTICS ===

def run_system_diagnostics() -> Dict[str, Any]:
    """Exécute des diagnostics système de base"""
    diagnostics = {
        'timestamp': get_formatted_time(),
        'system_info': get_system_info(),
        'network': {
            'local_ip': get_local_ip(),
            'interfaces': get_network_interfaces(),
            'internet_access': ping_host('8.8.8.8')
        },
        'permissions': {
            'is_admin': is_admin(),
            'current_user': get_current_user()
        },
        'environment': {
            'is_vm': is_virtual_machine(),
            'python_path': sys.executable,
            'working_directory': os.getcwd()
        }
    }
    
    return diagnostics