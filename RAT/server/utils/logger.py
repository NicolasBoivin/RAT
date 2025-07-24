"""
Server Logger - Configuration du logging côté serveur
Spécialisé pour les besoins du serveur RAT
"""

import logging
import logging.handlers
import sys
from pathlib import Path
from typing import Optional

from shared.logger import RATLogger, ColoredFormatter

def setup_logger(name: str = "rat_server", debug: bool = False, log_dir: str = "logs") -> logging.Logger:
    """
    Configure le logger pour le serveur RAT
    
    Args:
        name: Nom du logger
        debug: Mode debug
        log_dir: Répertoire des logs
    
    Returns:
        logging.Logger: Logger configuré
    """
    # Configuration du logger RAT
    config = {
        'level': 'DEBUG' if debug else 'INFO',
        'log_dir': log_dir,
        'enable_console': True,
        'enable_file': True,
        'enable_json': True,  # JSON pour analyse
        'enable_colors': True,
        'format': '%(asctime)s - %(name)s - %(levelname)s - [%(module)s:%(funcName)s:%(lineno)d] - %(message)s'
    }
    
    rat_logger = RATLogger(name, config)
    logger = rat_logger.get_logger()
    
    # Configuration spécialisée pour le serveur
    _setup_server_specific_logging(logger, debug)
    
    return logger

def _setup_server_specific_logging(logger: logging.Logger, debug: bool):
    """Configuration spécifique au serveur"""
    
    # Handler pour les événements de sécurité
    security_handler = logging.handlers.RotatingFileHandler(
        'logs/security.log',
        maxBytes=10*1024*1024,  # 10MB
        backupCount=5,
        encoding='utf-8'
    )
    
    security_formatter = logging.Formatter(
        '%(asctime)s - SECURITY - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    security_handler.setFormatter(security_formatter)
    security_handler.setLevel(logging.WARNING)
    
    # Filtre pour les messages de sécurité uniquement
    class SecurityFilter(logging.Filter):
        def filter(self, record):
            return 'SECURITY' in record.getMessage() or record.levelno >= logging.ERROR
    
    security_handler.addFilter(SecurityFilter())
    logger.addHandler(security_handler)
    
    # Handler pour les audits de commandes
    audit_handler = logging.handlers.RotatingFileHandler(
        'logs/commands.log',
        maxBytes=5*1024*1024,  # 5MB
        backupCount=10,
        encoding='utf-8'
    )
    
    audit_formatter = logging.Formatter(
        '%(asctime)s - %(session_id)s - %(command)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    audit_handler.setFormatter(audit_formatter)
    
    # Filtre pour les commandes uniquement
    class CommandFilter(logging.Filter):
        def filter(self, record):
            return hasattr(record, 'command') and hasattr(record, 'session_id')
    
    audit_handler.addFilter(CommandFilter())
    logger.addHandler(audit_handler)
    
    # Désactivation des logs verbeux en production
    if not debug:
        logging.getLogger('urllib3').setLevel(logging.WARNING)
        logging.getLogger('requests').setLevel(logging.WARNING)

def get_server_logger(name: str = "rat_server") -> logging.Logger:
    """Récupère le logger serveur"""
    return logging.getLogger(name)

class ServerLoggerMixin:
    """Mixin pour ajouter le logging aux classes serveur"""
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.logger = get_server_logger(self.__class__.__name__)
    
    def log_session_event(self, session_id: str, event: str, details: str = None):
        """Log un événement de session"""
        extra = {'session_id': session_id}
        message = f"Session {event}: {session_id}"
        if details:
            message += f" - {details}"
        self.logger.info(message, extra=extra)
    
    def log_command_execution(self, session_id: str, command: str, status: str):
        """Log l'exécution d'une commande"""
        extra = {'session_id': session_id, 'command': command}
        message = f"Command: {command} - Status: {status}"
        self.logger.info(message, extra=extra)
    
    def log_security_event(self, event_type: str, details: str, session_id: str = None):
        """Log un événement de sécurité"""
        extra = {}
        if session_id:
            extra['session_id'] = session_id
        message = f"SECURITY EVENT - {event_type}: {details}"
        self.logger.warning(message, extra=extra)