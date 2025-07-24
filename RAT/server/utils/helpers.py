"""
Server Helpers - Fonctions utilitaires pour le serveur RAT
Fonctions communes et utilitaires pour le serveur
"""

import os
import sys
import time
import json
import hashlib
import platform
import ipaddress
import subprocess
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple, Union
import logging

logger = logging.getLogger(__name__)

# === UTILITAIRES SYSTÈME ===

def get_system_info() -> Dict[str, Any]:
    """Récupère les informations système du serveur"""
    try:
        import psutil
        
        # Informations de base
        info = {
            'hostname': platform.node(),
            'platform': platform.platform(),
            'system': platform.system(),
            'release': platform.release(),
            'version': platform.version(),
            'machine': platform.machine(),
            'processor': platform.processor(),
            'python_version': platform.python_version(),
            'python_executable': sys.executable,
            'current_directory': os.getcwd(),
            'server_start_time': datetime.now().isoformat()
        }
        
        # Informations réseau
        try:
            hostname = platform.node()
            local_ip = get_local_ip()
            info.update({
                'hostname': hostname,
                'local_ip': local_ip,
                'network_interfaces': get_network_interfaces()
            })
        except Exception as e:
            logger.warning(f"Erreur récupération info réseau: {e}")
        
        # Informations matérielles avec psutil
        try:
            # CPU
            info['cpu'] = {
                'physical_cores': psutil.cpu_count(logical=False),
                'total_cores': psutil.cpu_count(logical=True),
                'usage_percent': psutil.cpu_percent(interval=1)
            }
            
            # Mémoire
            memory = psutil.virtual_memory()
            info['memory'] = {
                'total_gb': round(memory.total / (1024**3), 2),
                'available_gb': round(memory.available / (1024**3), 2),
                'used_percent': memory.percent
            }
            
            # Disque
            disk = psutil.disk_usage('/')
            info['disk'] = {
                'total_gb': round(disk.total / (1024**3), 2),
                'free_gb': round(disk.free / (1024**3), 2),
                'used_percent': round((disk.used / disk.total) * 100, 1)
            }
            
        except ImportError:
            logger.warning("psutil non disponible - informations matérielles limitées")
        except Exception as e:
            logger.warning(f"Erreur récupération info matérielle: {e}")
        
        return info
        
    except Exception as e:
        logger.error(f"Erreur récupération info système: {e}")
        return {'error': str(e)}

def get_local_ip() -> str:
    """Récupère l'adresse IP locale principale"""
    try:
        import socket
        
        # Méthode fiable pour obtenir l'IP locale
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        
        return local_ip
        
    except Exception:
        try:
            # Fallback avec hostname
            import socket
            return socket.gethostbyname(socket.gethostname())
        except Exception:
            return "127.0.0.1"

def get_network_interfaces() -> List[Dict[str, Any]]:
    """Récupère la liste des interfaces réseau"""
    try:
        import psutil
        
        interfaces = []
        
        # Récupération des interfaces avec psutil
        net_if_addrs = psutil.net_if_addrs()
        net_if_stats = psutil.net_if_stats()
        
        for interface_name, addresses in net_if_addrs.items():
            interface_info = {
                'name': interface_name,
                'addresses': [],
                'is_up': False,
                'speed': 0
            }
            
            # Informations de statut
            if interface_name in net_if_stats:
                stats = net_if_stats[interface_name]
                interface_info['is_up'] = stats.isup
                interface_info['speed'] = stats.speed
            
            # Adresses IP
            for addr in addresses:
                if addr.family == 2:  # AF_INET (IPv4)
                    interface_info['addresses'].append({
                        'type': 'IPv4',
                        'address': addr.address,
                        'netmask': addr.netmask,
                        'broadcast': addr.broadcast
                    })
                elif addr.family == 10:  # AF_INET6 (IPv6)
                    interface_info['addresses'].append({
                        'type': 'IPv6',
                        'address': addr.address,
                        'netmask': addr.netmask
                    })
            
            if interface_info['addresses']:  # Seulement si l'interface a des adresses
                interfaces.append(interface_info)
        
        return interfaces
        
    except ImportError:
        logger.warning("psutil non disponible pour les interfaces réseau")
        return []
    except Exception as e:
        logger.error(f"Erreur récupération interfaces: {e}")
        return []

# === UTILITAIRES FICHIERS ===

def ensure_directory(directory: Union[str, Path]) -> bool:
    """
    S'assure qu'un répertoire existe
    
    Args:
        directory: Chemin du répertoire
    
    Returns:
        bool: True si le répertoire existe ou a été créé
    """
    try:
        Path(directory).mkdir(parents=True, exist_ok=True)
        return True
    except Exception as e:
        logger.error(f"Impossible de créer le répertoire {directory}: {e}")
        return False

def safe_file_write(filepath: Union[str, Path], content: Union[str, bytes], 
                   encoding: str = 'utf-8', backup: bool = True) -> bool:
    """
    Écriture sécurisée de fichier avec sauvegarde optionnelle
    
    Args:
        filepath: Chemin du fichier
        content: Contenu à écrire
        encoding: Encodage pour les chaînes
        backup: Créer une sauvegarde si le fichier existe
    
    Returns:
        bool: True si l'écriture a réussi
    """
    try:
        filepath = Path(filepath)
        
        # Création du répertoire parent si nécessaire
        ensure_directory(filepath.parent)
        
        # Sauvegarde de l'ancien fichier
        if backup and filepath.exists():
            backup_path = filepath.with_suffix(filepath.suffix + '.backup')
            filepath.rename(backup_path)
            logger.debug(f"Sauvegarde créée: {backup_path}")
        
        # Écriture du nouveau contenu
        if isinstance(content, str):
            with open(filepath, 'w', encoding=encoding) as f:
                f.write(content)
        else:
            with open(filepath, 'wb') as f:
                f.write(content)
        
        logger.debug(f"Fichier écrit: {filepath}")
        return True
        
    except Exception as e:
        logger.error(f"Erreur écriture fichier {filepath}: {e}")
        return False

def safe_file_read(filepath: Union[str, Path], 
                  encoding: str = 'utf-8') -> Optional[Union[str, bytes]]:
    """
    Lecture sécurisée de fichier
    
    Args:
        filepath: Chemin du fichier
        encoding: Encodage pour la lecture texte (None pour binaire)
    
    Returns:
        Contenu du fichier ou None si erreur
    """
    try:
        filepath = Path(filepath)
        
        if not filepath.exists():
            logger.warning(f"Fichier non trouvé: {filepath}")
            return None
        
        if encoding:
            with open(filepath, 'r', encoding=encoding) as f:
                return f.read()
        else:
            with open(filepath, 'rb') as f:
                return f.read()
                
    except Exception as e:
        logger.error(f"Erreur lecture fichier {filepath}: {e}")
        return None

def calculate_file_hash(filepath: Union[str, Path], algorithm: str = 'sha256') -> Optional[str]:
    """
    Calcule le hash d'un fichier
    
    Args:
        filepath: Chemin du fichier
        algorithm: Algorithme de hash (sha256, sha1, md5)
    
    Returns:
        Hash hexadécimal ou None si erreur
    """
    try:
        filepath = Path(filepath)
        
        if not filepath.exists():
            return None
        
        # Sélection de l'algorithme
        if algorithm == 'sha256':
            hasher = hashlib.sha256()
        elif algorithm == 'sha1':
            hasher = hashlib.sha1()
        elif algorithm == 'md5':
            hasher = hashlib.md5()
        else:
            raise ValueError(f"Algorithme non supporté: {algorithm}")
        
        # Lecture par chunks pour les gros fichiers
        with open(filepath, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hasher.update(chunk)
        
        return hasher.hexdigest()
        
    except Exception as e:
        logger.error(f"Erreur calcul hash {filepath}: {e}")
        return None

def get_file_info(filepath: Union[str, Path]) -> Dict[str, Any]:
    """
    Récupère les informations détaillées d'un fichier
    
    Args:
        filepath: Chemin du fichier
    
    Returns:
        Dict avec les informations du fichier
    """
    try:
        filepath = Path(filepath)
        
        if not filepath.exists():
            return {'exists': False, 'error': 'File not found'}
        
        stat = filepath.stat()
        
        info = {
            'exists': True,
            'name': filepath.name,
            'path': str(filepath.absolute()),
            'size': stat.st_size,
            'size_human': format_bytes(stat.st_size),
            'is_file': filepath.is_file(),
            'is_dir': filepath.is_dir(),
            'created': datetime.fromtimestamp(stat.st_ctime).isoformat(),
            'modified': datetime.fromtimestamp(stat.st_mtime).isoformat(),
            'accessed': datetime.fromtimestamp(stat.st_atime).isoformat(),
            'permissions': oct(stat.st_mode)[-3:],
            'owner_readable': os.access(filepath, os.R_OK),
            'owner_writable': os.access(filepath, os.W_OK),
            'owner_executable': os.access(filepath, os.X_OK)
        }
        
        # Informations spécifiques aux fichiers
        if filepath.is_file():
            info['extension'] = filepath.suffix.lower()
            
            # Type MIME si possible
            import mimetypes
            mime_type, encoding = mimetypes.guess_type(str(filepath))
            info['mime_type'] = mime_type
            info['encoding'] = encoding
            
            # Hash du fichier pour les petits fichiers
            if stat.st_size < 10 * 1024 * 1024:  # < 10MB
                info['sha256'] = calculate_file_hash(filepath, 'sha256')
        
        return info
        
    except Exception as e:
        logger.error(f"Erreur info fichier {filepath}: {e}")
        return {'exists': False, 'error': str(e)}

# === UTILITAIRES RÉSEAU ===

def is_valid_ip(ip_address: str) -> bool:
    """
    Vérifie si une adresse IP est valide
    
    Args:
        ip_address: Adresse IP à vérifier
    
    Returns:
        bool: True si l'IP est valide
    """
    try:
        ipaddress.ip_address(ip_address)
        return True
    except ValueError:
        return False

def is_private_ip(ip_address: str) -> bool:
    """
    Vérifie si une adresse IP est privée
    
    Args:
        ip_address: Adresse IP à vérifier
    
    Returns:
        bool: True si l'IP est privée
    """
    try:
        ip = ipaddress.ip_address(ip_address)
        return ip.is_private
    except ValueError:
        return False

def check_port_availability(host: str, port: int) -> bool:
    """
    Vérifie si un port est disponible
    
    Args:
        host: Adresse d'hôte
        port: Numéro de port
    
    Returns:
        bool: True si le port est disponible
    """
    try:
        import socket
        
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        
        result = sock.connect_ex((host, port))
        sock.close()
        
        return result != 0  # 0 = connexion réussie = port occupé
        
    except Exception as e:
        logger.error(f"Erreur vérification port {host}:{port}: {e}")
        return False

def get_available_port(host: str = "127.0.0.1", start_port: int = 8000) -> Optional[int]:
    """
    Trouve un port disponible
    
    Args:
        host: Adresse d'hôte
        start_port: Port de départ pour la recherche
    
    Returns:
        Port disponible ou None
    """
    try:
        import socket
        
        for port in range(start_port, start_port + 1000):
            if check_port_availability(host, port):
                return port
        
        return None
        
    except Exception as e:
        logger.error(f"Erreur recherche port disponible: {e}")
        return None

# === UTILITAIRES FORMATAGE ===

def format_bytes(bytes_count: int) -> str:
    """
    Formate une taille en bytes de manière lisible
    
    Args:
        bytes_count: Nombre de bytes
    
    Returns:
        Taille formatée (ex: "1.2 MB")
    """
    try:
        for unit in ['B', 'KB', 'MB', 'GB', 'TB', 'PB']:
            if bytes_count < 1024.0:
                if unit == 'B':
                    return f"{int(bytes_count)} {unit}"
                return f"{bytes_count:.1f} {unit}"
            bytes_count /= 1024.0
        return f"{bytes_count:.1f} PB"
    except Exception:
        return "0 B"

def format_duration(seconds: float) -> str:
    """
    Formate une durée en secondes de manière lisible
    
    Args:
        seconds: Durée en secondes
    
    Returns:
        Durée formatée (ex: "1h 23m 45s")
    """
    try:
        if seconds < 60:
            return f"{seconds:.1f}s"
        
        minutes = int(seconds // 60)
        remaining_seconds = int(seconds % 60)
        
        if minutes < 60:
            return f"{minutes}m {remaining_seconds}s"
        
        hours = int(minutes // 60)
        remaining_minutes = int(minutes % 60)
        
        if hours < 24:
            return f"{hours}h {remaining_minutes}m {remaining_seconds}s"
        
        days = int(hours // 24)
        remaining_hours = int(hours % 24)
        
        return f"{days}d {remaining_hours}h {remaining_minutes}m"
        
    except Exception:
        return "0s"

def format_timestamp(timestamp: Optional[float] = None, 
                    format_str: str = "%Y-%m-%d %H:%M:%S") -> str:
    """
    Formate un timestamp Unix
    
    Args:
        timestamp: Timestamp Unix (None = maintenant)
        format_str: Format de sortie
    
    Returns:
        Timestamp formaté
    """
    try:
        if timestamp is None:
            timestamp = time.time()
        
        dt = datetime.fromtimestamp(timestamp)
        return dt.strftime(format_str)
        
    except Exception:
        return "Invalid timestamp"

# === UTILITAIRES JSON ===

def safe_json_load(filepath: Union[str, Path]) -> Optional[Dict[str, Any]]:
    """
    Charge un fichier JSON de manière sécurisée
    
    Args:
        filepath: Chemin du fichier JSON
    
    Returns:
        Dict des données ou None si erreur
    """
    try:
        content = safe_file_read(filepath, encoding='utf-8')
        if content is None:
            return None
        
        return json.loads(content)
        
    except json.JSONDecodeError as e:
        logger.error(f"Erreur JSON dans {filepath}: {e}")
        return None
    except Exception as e:
        logger.error(f"Erreur chargement JSON {filepath}: {e}")
        return None

def safe_json_save(data: Dict[str, Any], filepath: Union[str, Path], 
                  indent: int = 2, backup: bool = True) -> bool:
    """
    Sauvegarde des données JSON de manière sécurisée
    
    Args:
        data: Données à sauvegarder
        filepath: Chemin du fichier JSON
        indent: Indentation JSON
        backup: Créer une sauvegarde
    
    Returns:
        bool: True si la sauvegarde a réussi
    """
    try:
        json_content = json.dumps(data, indent=indent, ensure_ascii=False)
        return safe_file_write(filepath, json_content, backup=backup)
        
    except Exception as e:
        logger.error(f"Erreur sauvegarde JSON {filepath}: {e}")
        return False

# === UTILITAIRES PROCESSUS ===

def run_command(command: List[str], timeout: int = 30, 
               capture_output: bool = True) -> Dict[str, Any]:
    """
    Exécute une commande système de manière sécurisée
    
    Args:
        command: Liste des arguments de commande
        timeout: Timeout en secondes
        capture_output: Capturer stdout/stderr
    
    Returns:
        Dict avec le résultat de la commande
    """
    try:
        start_time = time.time()
        
        result = subprocess.run(
            command,
            timeout=timeout,
            capture_output=capture_output,
            text=True,
            check=False
        )
        
        execution_time = time.time() - start_time
        
        return {
            'success': result.returncode == 0,
            'return_code': result.returncode,
            'stdout': result.stdout if capture_output else '',
            'stderr': result.stderr if capture_output else '',
            'execution_time': execution_time,
            'command': ' '.join(command)
        }
        
    except subprocess.TimeoutExpired:
        return {
            'success': False,
            'return_code': -1,
            'stdout': '',
            'stderr': 'Command timed out',
            'execution_time': timeout,
            'command': ' '.join(command),
            'timeout': True
        }
    except Exception as e:
        return {
            'success': False,
            'return_code': -1,
            'stdout': '',
            'stderr': str(e),
            'execution_time': 0,
            'command': ' '.join(command),
            'error': str(e)
        }

def is_process_running(process_name: str) -> bool:
    """
    Vérifie si un processus est en cours d'exécution
    
    Args:
        process_name: Nom du processus
    
    Returns:
        bool: True si le processus est actif
    """
    try:
        system = platform.system().lower()
        
        if system == 'windows':
            result = run_command(['tasklist'], timeout=10)
            if result['success']:
                return process_name.lower() in result['stdout'].lower()
        else:
            result = run_command(['ps', 'aux'], timeout=10)
            if result['success']:
                return process_name.lower() in result['stdout'].lower()
        
        return False
        
    except Exception as e:
        logger.error(f"Erreur vérification processus {process_name}: {e}")
        return False

# === UTILITAIRES SÉCURITÉ ===

def sanitize_filename(filename: str, replacement: str = '_') -> str:
    """
    Nettoie un nom de fichier pour le rendre sûr
    
    Args:
        filename: Nom de fichier à nettoyer
        replacement: Caractère de remplacement
    
    Returns:
        Nom de fichier nettoyé
    """
    import re
    
    # Caractères interdits dans les noms de fichiers
    forbidden_chars = r'[<>:"/\\|?*\x00-\x1f]'
    
    # Remplacement des caractères interdits
    clean_name = re.sub(forbidden_chars, replacement, filename)
    
    # Suppression des espaces en début/fin
    clean_name = clean_name.strip()
    
    # Limitation de la longueur
    if len(clean_name) > 255:
        name, ext = os.path.splitext(clean_name)
        clean_name = name[:255-len(ext)] + ext
    
    # Vérification que le nom n'est pas vide
    if not clean_name or clean_name in ['.', '..']:
        clean_name = 'unnamed_file'
    
    return clean_name

def is_safe_path(base_path: Union[str, Path], 
                target_path: Union[str, Path]) -> bool:
    """
    Vérifie qu'un chemin est sûr (pas de directory traversal)
    
    Args:
        base_path: Chemin de base autorisé
        target_path: Chemin cible à vérifier
    
    Returns:
        bool: True si le chemin est sûr
    """
    try:
        base_path = Path(base_path).resolve()
        target_path = Path(target_path).resolve()
        
        # Vérification que le chemin cible est dans le chemin de base
        return str(target_path).startswith(str(base_path))
        
    except Exception as e:
        logger.error(f"Erreur vérification chemin sûr: {e}")
        return False

def generate_session_id() -> str:
    """
    Génère un ID de session unique
    
    Returns:
        ID de session unique
    """
    import uuid
    return str(uuid.uuid4())

def generate_random_string(length: int = 16, 
                          charset: str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789") -> str:
    """
    Génère une chaîne aléatoire
    
    Args:
        length: Longueur de la chaîne
        charset: Jeu de caractères à utiliser
    
    Returns:
        Chaîne aléatoire
    """
    import random
    import os
    
    # Utilisation d'une source de randomness sécurisée
    random.seed(int.from_bytes(os.urandom(16), byteorder='big'))
    
    return ''.join(random.choice(charset) for _ in range(length))

# === UTILITAIRES DE DEBUGGING ===

def debug_log_function_call(func_name: str, args: Tuple = (), 
                           kwargs: Dict[str, Any] = None) -> None:
    """
    Log un appel de fonction pour le debugging
    
    Args:
        func_name: Nom de la fonction
        args: Arguments positionnels
        kwargs: Arguments nommés
    """
    if kwargs is None:
        kwargs = {}
    
    logger.debug(f"Function call: {func_name}(args={args}, kwargs={kwargs})")

def create_debug_info() -> Dict[str, Any]:
    """
    Crée des informations de debug complètes
    
    Returns:
        Dict avec les informations de debug
    """
    try:
        debug_info = {
            'timestamp': datetime.now().isoformat(),
            'system': get_system_info(),
            'python_path': sys.path,
            'environment_variables': dict(os.environ),
            'current_working_directory': os.getcwd(),
            'memory_usage': {}
        }
        
        # Informations de mémoire si psutil disponible
        try:
            import psutil
            process = psutil.Process()
            memory_info = process.memory_info()
            
            debug_info['memory_usage'] = {
                'rss': memory_info.rss,
                'vms': memory_info.vms,
                'rss_human': format_bytes(memory_info.rss),
                'vms_human': format_bytes(memory_info.vms),
                'percent': process.memory_percent()
            }
        except ImportError:
            pass
        
        return debug_info
        
    except Exception as e:
        logger.error(f"Erreur création debug info: {e}")
        return {'error': str(e)}

# === UTILITAIRES DE VALIDATION ===

def validate_config_dict(config: Dict[str, Any], 
                        required_keys: List[str], 
                        optional_keys: List[str] = None) -> Tuple[bool, List[str]]:
    """
    Valide un dictionnaire de configuration
    
    Args:
        config: Configuration à valider
        required_keys: Clés obligatoires
        optional_keys: Clés optionnelles
    
    Returns:
        Tuple (is_valid, errors)
    """
    if optional_keys is None:
        optional_keys = []
    
    errors = []
    
    # Vérification des clés obligatoires
    for key in required_keys:
        if key not in config:
            errors.append(f"Clé manquante: {key}")
    
    # Vérification des clés inconnues
    all_valid_keys = set(required_keys + optional_keys)
    for key in config:
        if key not in all_valid_keys:
            errors.append(f"Clé inconnue: {key}")
    
    return len(errors) == 0, errors

def cleanup_old_files(directory: Union[str, Path], 
                     max_age_days: int, 
                     pattern: str = "*") -> int:
    """
    Nettoie les anciens fichiers dans un répertoire
    
    Args:
        directory: Répertoire à nettoyer
        max_age_days: Âge maximum en jours
        pattern: Pattern de fichiers (glob)
    
    Returns:
        Nombre de fichiers supprimés
    """
    try:
        directory = Path(directory)
        
        if not directory.exists():
            return 0
        
        cutoff_time = time.time() - (max_age_days * 24 * 3600)
        deleted_count = 0
        
        for file_path in directory.glob(pattern):
            if file_path.is_file():
                try:
                    file_stat = file_path.stat()
                    if file_stat.st_mtime < cutoff_time:
                        file_path.unlink()
                        deleted_count += 1
                        logger.debug(f"Fichier ancien supprimé: {file_path}")
                except Exception as e:
                    logger.warning(f"Impossible de supprimer {file_path}: {e}")
        
        return deleted_count
        
    except Exception as e:
        logger.error(f"Erreur nettoyage répertoire {directory}: {e}")
        return 0