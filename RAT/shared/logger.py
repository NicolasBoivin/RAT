"""
Logger - Configuration du système de logging
Système de logging unifié pour serveur et client avec différents niveaux
"""

import logging
import logging.handlers
import os
import sys
from datetime import datetime
from pathlib import Path
from typing import Optional, Dict, Any
import threading
import json

class ColoredFormatter(logging.Formatter):
    """Formatter avec couleurs pour la console"""
    
    # Codes couleur ANSI
    COLORS = {
        'DEBUG': '\033[36m',     # Cyan
        'INFO': '\033[32m',      # Vert
        'WARNING': '\033[33m',   # Jaune
        'ERROR': '\033[31m',     # Rouge
        'CRITICAL': '\033[35m',  # Magenta
        'RESET': '\033[0m'       # Reset
    }
    
    def format(self, record):
        # Ajout de couleur au niveau de log
        if record.levelname in self.COLORS:
            record.levelname = (
                f"{self.COLORS[record.levelname]}{record.levelname}"
                f"{self.COLORS['RESET']}"
            )
        
        return super().format(record)

class JSONFormatter(logging.Formatter):
    """Formatter JSON pour les logs structurés"""
    
    def format(self, record):
        log_entry = {
            'timestamp': datetime.fromtimestamp(record.created).isoformat(),
            'level': record.levelname,
            'logger': record.name,
            'message': record.getMessage(),
            'module': record.module,
            'function': record.funcName,
            'line': record.lineno
        }
        
        # Ajout d'informations additionnelles si présentes
        if hasattr(record, 'session_id'):
            log_entry['session_id'] = record.session_id
        
        if hasattr(record, 'client_ip'):
            log_entry['client_ip'] = record.client_ip
        
        if hasattr(record, 'command'):
            log_entry['command'] = record.command
        
        if record.exc_info:
            log_entry['exception'] = self.formatException(record.exc_info)
        
        return json.dumps(log_entry, ensure_ascii=False)

class RATLogger:
    """Gestionnaire de logging pour le projet RAT"""
    
    def __init__(self, name: str, config: Dict[str, Any] = None):
        self.name = name
        self.config = config or {}
        self.logger = logging.getLogger(name)
        self.handlers = {}
        self._lock = threading.Lock()
        
        # Configuration par défaut
        self.default_config = {
            'level': 'INFO',
            'format': '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            'date_format': '%Y-%m-%d %H:%M:%S',
            'enable_console': True,
            'enable_file': True,
            'enable_json': False,
            'log_dir': 'logs',
            'max_file_size': 10 * 1024 * 1024,  # 10MB
            'backup_count': 5,
            'enable_colors': True
        }
        
        # Fusion avec la configuration fournie
        self.config = {**self.default_config, **self.config}
        
        self._setup_logger()
    
    def _setup_logger(self):
        """Configure le logger avec les handlers appropriés"""
        with self._lock:
            # Nettoyage des handlers existants
            self.logger.handlers.clear()
            
            # Définition du niveau
            level = getattr(logging, self.config['level'].upper(), logging.INFO)
            self.logger.setLevel(level)
            
            # Handler console
            if self.config['enable_console']:
                self._add_console_handler()
            
            # Handler fichier
            if self.config['enable_file']:
                self._add_file_handler()
            
            # Handler JSON
            if self.config['enable_json']:
                self._add_json_handler()
            
            # Éviter la propagation vers le root logger
            self.logger.propagate = False
    
    def _add_console_handler(self):
        """Ajoute un handler pour la console"""
        console_handler = logging.StreamHandler(sys.stdout)
        
        if self.config['enable_colors'] and sys.stdout.isatty():
            formatter = ColoredFormatter(
                fmt=self.config['format'],
                datefmt=self.config['date_format']
            )
        else:
            formatter = logging.Formatter(
                fmt=self.config['format'],
                datefmt=self.config['date_format']
            )
        
        console_handler.setFormatter(formatter)
        self.logger.addHandler(console_handler)
        self.handlers['console'] = console_handler
    
    def _add_file_handler(self):
        """Ajoute un handler pour les fichiers avec rotation"""
        # Création du répertoire de logs
        log_dir = Path(self.config['log_dir'])
        log_dir.mkdir(parents=True, exist_ok=True)
        
        # Fichier de log principal
        log_file = log_dir / f"{self.name}.log"
        
        # Handler avec rotation
        file_handler = logging.handlers.RotatingFileHandler(
            log_file,
            maxBytes=self.config['max_file_size'],
            backupCount=self.config['backup_count'],
            encoding='utf-8'
        )
        
        formatter = logging.Formatter(
            fmt=self.config['format'],
            datefmt=self.config['date_format']
        )
        
        file_handler.setFormatter(formatter)
        self.logger.addHandler(file_handler)
        self.handlers['file'] = file_handler
    
    def _add_json_handler(self):
        """Ajoute un handler JSON pour les logs structurés"""
        log_dir = Path(self.config['log_dir'])
        log_dir.mkdir(parents=True, exist_ok=True)
        
        json_file = log_dir / f"{self.name}_structured.log"
        
        json_handler = logging.handlers.RotatingFileHandler(
            json_file,
            maxBytes=self.config['max_file_size'],
            backupCount=self.config['backup_count'],
            encoding='utf-8'
        )
        
        json_handler.setFormatter(JSONFormatter())
        self.logger.addHandler(json_handler)
        self.handlers['json'] = json_handler
    
    def get_logger(self) -> logging.Logger:
        """Retourne l'instance du logger"""
        return self.logger
    
    def log_session_event(self, session_id: str, event: str, details: str = None):
        """Log un événement de session"""
        extra = {'session_id': session_id}
        message = f"Session {event}: {session_id}"
        if details:
            message += f" - {details}"
        
        self.logger.info(message, extra=extra)
    
    def log_command_execution(self, session_id: str, command: str, status: str, output: str = None):
        """Log l'exécution d'une commande"""
        extra = {
            'session_id': session_id,
            'command': command
        }
        
        message = f"Command executed - Status: {status}, Command: {command}"
        if output and len(output) < 200:  # Limite pour éviter les logs trop longs
            message += f", Output: {output[:200]}"
        
        if status == 'success':
            self.logger.info(message, extra=extra)
        else:
            self.logger.warning(message, extra=extra)
    
    def log_file_operation(self, session_id: str, operation: str, file_path: str, status: str):
        """Log une opération de fichier"""
        extra = {'session_id': session_id}
        message = f"File {operation}: {file_path} - Status: {status}"
        
        if status == 'success':
            self.logger.info(message, extra=extra)
        else:
            self.logger.error(message, extra=extra)
    
    def log_security_event(self, event_type: str, details: str, session_id: str = None):
        """Log un événement de sécurité"""
        extra = {}
        if session_id:
            extra['session_id'] = session_id
        
        message = f"SECURITY EVENT - {event_type}: {details}"
        self.logger.warning(message, extra=extra)
    
    def log_network_event(self, event_type: str, client_ip: str, details: str = None):
        """Log un événement réseau"""
        extra = {'client_ip': client_ip}
        message = f"Network {event_type}: {client_ip}"
        if details:
            message += f" - {details}"
        
        self.logger.info(message, extra=extra)
    
    def set_level(self, level: str):
        """Change le niveau de logging"""
        log_level = getattr(logging, level.upper(), logging.INFO)
        self.logger.setLevel(log_level)
        self.config['level'] = level.upper()
    
    def enable_debug(self):
        """Active le mode debug"""
        self.set_level('DEBUG')
    
    def disable_debug(self):
        """Désactive le mode debug"""
        self.set_level('INFO')
    
    def close(self):
        """Ferme tous les handlers"""
        with self._lock:
            for handler in self.logger.handlers:
                handler.close()
            self.logger.handlers.clear()
            self.handlers.clear()

# === FONCTIONS UTILITAIRES ===

def setup_server_logger(debug: bool = False, log_dir: str = "logs") -> RATLogger:
    """Configure le logger pour le serveur"""
    config = {
        'level': 'DEBUG' if debug else 'INFO',
        'log_dir': log_dir,
        'enable_console': True,
        'enable_file': True,
        'enable_json': True,
        'enable_colors': True
    }
    
    return RATLogger('rat_server', config)

def setup_client_logger(debug: bool = False, stealth_mode: bool = False, log_dir: str = "logs") -> RATLogger:
    """Configure le logger pour le client"""
    config = {
        'level': 'DEBUG' if debug else 'CRITICAL',  # Mode silencieux par défaut
        'log_dir': log_dir,
        'enable_console': not stealth_mode,  # Pas de console en mode furtif
        'enable_file': not stealth_mode,     # Pas de fichiers en mode furtif
        'enable_json': False,
        'enable_colors': not stealth_mode
    }
    
    return RATLogger('rat_client', config)

def get_logger(name: str) -> logging.Logger:
    """Récupère un logger par son nom"""
    return logging.getLogger(name)

# === CONTEXTE MANAGERS ===

class LogContext:
    """Context manager pour ajouter des informations contextuelles aux logs"""
    
    def __init__(self, logger: logging.Logger, **context):
        self.logger = logger
        self.context = context
        self.old_factory = None
    
    def __enter__(self):
        self.old_factory = logging.getLogRecordFactory()
        
        def record_factory(*args, **kwargs):
            record = self.old_factory(*args, **kwargs)
            for key, value in self.context.items():
                setattr(record, key, value)
            return record
        
        logging.setLogRecordFactory(record_factory)
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        logging.setLogRecordFactory(self.old_factory)

# === DÉCORATEURS DE LOGGING ===

def log_method_calls(logger: logging.Logger):
    """Décorateur pour logger les appels de méthodes"""
    def decorator(func):
        def wrapper(*args, **kwargs):
            func_name = func.__name__
            class_name = args[0].__class__.__name__ if args else 'Unknown'
            
            logger.debug(f"Calling {class_name}.{func_name}")
            
            try:
                result = func(*args, **kwargs)
                logger.debug(f"Completed {class_name}.{func_name}")
                return result
            except Exception as e:
                logger.error(f"Error in {class_name}.{func_name}: {str(e)}")
                raise
        return wrapper
    return decorator

def log_exceptions(logger: logging.Logger):
    """Décorateur pour logger les exceptions"""
    def decorator(func):
        def wrapper(*args, **kwargs):
            try:
                return func(*args, **kwargs)
            except Exception as e:
                logger.error(f"Exception in {func.__name__}: {str(e)}", exc_info=True)
                raise
        return wrapper
    return decorator

# === ANALYSE DES LOGS ===

class LogAnalyzer:
    """Analyseur de logs pour statistiques et monitoring"""
    
    def __init__(self, log_file: str):
        self.log_file = Path(log_file)
    
    def get_error_count(self, time_period: int = 3600) -> int:
        """Compte les erreurs dans une période donnée (en secondes)"""
        if not self.log_file.exists():
            return 0
        
        error_count = 0
        current_time = datetime.now()
        
        try:
            with open(self.log_file, 'r', encoding='utf-8') as f:
                for line in f:
                    if 'ERROR' in line or 'CRITICAL' in line:
                        # Extraction simple du timestamp (améliorer si nécessaire)
                        if self._is_recent_log(line, current_time, time_period):
                            error_count += 1
        except Exception:
            pass
        
        return error_count
    
    def get_session_stats(self) -> Dict[str, int]:
        """Récupère les statistiques de sessions"""
        stats = {
            'sessions_created': 0,
            'sessions_closed': 0,
            'commands_executed': 0,
            'file_operations': 0
        }
        
        if not self.log_file.exists():
            return stats
        
        try:
            with open(self.log_file, 'r', encoding='utf-8') as f:
                for line in f:
                    if 'Session created' in line:
                        stats['sessions_created'] += 1
                    elif 'Session closed' in line:
                        stats['sessions_closed'] += 1
                    elif 'Command executed' in line:
                        stats['commands_executed'] += 1
                    elif 'File ' in line and (' download' in line or ' upload' in line):
                        stats['file_operations'] += 1
        except Exception:
            pass
        
        return stats
    
    def _is_recent_log(self, log_line: str, current_time: datetime, period: int) -> bool:
        """Vérifie si une ligne de log est récente"""
        # Implémentation simple - à améliorer pour un parsing plus robuste
        try:
            # Extraction du timestamp du début de la ligne
            if log_line.startswith('20'):  # Format YYYY-MM-DD
                timestamp_str = log_line.split(' - ')[0]
                log_time = datetime.fromisoformat(timestamp_str.replace(',', '.'))
                return (current_time - log_time).total_seconds() <= period
        except Exception:
            pass
        
        return False

# === CONFIGURATION GLOBALE ===

def configure_logging(config: Dict[str, Any]):
    """Configure le logging global pour l'application"""
    
    # Désactivation des logs de bibliothèques tierces en mode production
    if not config.get('debug', False):
        logging.getLogger('urllib3').setLevel(logging.WARNING)
        logging.getLogger('requests').setLevel(logging.WARNING)
        logging.getLogger('PIL').setLevel(logging.WARNING)
    
    # Configuration du format par défaut
    logging.basicConfig(
        level=logging.DEBUG if config.get('debug') else logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )