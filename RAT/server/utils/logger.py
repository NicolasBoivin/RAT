"""
Logger Setup - Configuration du système de logs pour le serveur RAT
Système de logging avec rotation et niveaux multiples
"""

import logging
import logging.handlers
import os
import sys
from datetime import datetime
from typing import Optional

def setup_logger(name: str = "RAT_Server", 
                log_file: str = "server/data/logs/rat_server.log",
                log_level: str = "INFO",
                debug: bool = False,
                max_size: int = 10 * 1024 * 1024,  # 10MB
                backup_count: int = 5) -> logging.Logger:
    """
    Configure et retourne un logger pour le serveur RAT
    
    Args:
        name: Nom du logger
        log_file: Chemin du fichier de log
        log_level: Niveau de log (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        debug: Mode debug (affichage console)
        max_size: Taille maximale du fichier de log
        backup_count: Nombre de fichiers de sauvegarde
    
    Returns:
        logging.Logger: Logger configuré
    """
    
    # Création du logger principal
    logger = logging.getLogger(name)
    
    # Éviter la duplication des handlers
    if logger.handlers:
        return logger
    
    # Configuration du niveau
    if debug:
        level = logging.DEBUG
    else:
        level = getattr(logging, log_level.upper(), logging.INFO)
    
    logger.setLevel(level)
    
    # Format des messages
    formatter = logging.Formatter(
        fmt='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    # Format pour la console (plus coloré si possible)
    console_formatter = logging.Formatter(
        fmt='[%(asctime)s] %(levelname)-8s | %(message)s',
        datefmt='%H:%M:%S'
    )
    
    # === HANDLER FICHIER AVEC ROTATION ===
    try:
        # Création du répertoire de logs
        os.makedirs(os.path.dirname(log_file), exist_ok=True)
        
        # Handler avec rotation automatique
        file_handler = logging.handlers.RotatingFileHandler(
            filename=log_file,
            maxBytes=max_size,
            backupCount=backup_count,
            encoding='utf-8'
        )
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
        
    except Exception as e:
        print(f"Erreur création du fichier de log: {e}")
    
    # === HANDLER CONSOLE ===
    if debug or log_level.upper() == 'DEBUG':
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(logging.DEBUG if debug else level)
        console_handler.setFormatter(console_formatter)
        logger.addHandler(console_handler)
    
    # === HANDLER ERREURS CRITIQUES ===
    try:
        error_file = log_file.replace('.log', '_errors.log')
        error_handler = logging.handlers.RotatingFileHandler(
            filename=error_file,
            maxBytes=max_size,
            backupCount=backup_count,
            encoding='utf-8'
        )
        error_handler.setLevel(logging.ERROR)
        error_handler.setFormatter(formatter)
        logger.addHandler(error_handler)
        
    except Exception as e:
        print(f"Erreur création du fichier d'erreurs: {e}")
    
    # === HANDLER SYSLOG (Linux uniquement) ===
    try:
        if sys.platform.startswith('linux'):
            syslog_handler = logging.handlers.SysLogHandler(address='/dev/log')
            syslog_handler.setLevel(logging.WARNING)
            syslog_formatter = logging.Formatter(
                'RAT_Server[%(process)d]: %(levelname)s - %(message)s'
            )
            syslog_handler.setFormatter(syslog_formatter)
            logger.addHandler(syslog_handler)
    except Exception:
        pass  # Syslog optionnel
    
    # Message de démarrage
    logger.info("=== RAT SERVER LOGGER INITIALIZED ===")
    logger.info(f"Log Level: {log_level}")
    logger.info(f"Log File: {log_file}")
    logger.info(f"Debug Mode: {debug}")
    
    return logger

def setup_audit_logger(audit_file: str = "server/data/logs/rat_audit.log") -> logging.Logger:
    """
    Configure un logger spécial pour l'audit des actions sensibles
    
    Args:
        audit_file: Chemin du fichier d'audit
    
    Returns:
        logging.Logger: Logger d'audit
    """
    
    # Logger séparé pour l'audit
    audit_logger = logging.getLogger("RAT_Audit")
    
    if audit_logger.handlers:
        return audit_logger
    
    audit_logger.setLevel(logging.INFO)
    
    # Format spécial pour l'audit
    audit_formatter = logging.Formatter(
        fmt='%(asctime)s | %(levelname)s | %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    try:
        # Création du répertoire
        os.makedirs(os.path.dirname(audit_file), exist_ok=True)
        
        # Handler d'audit avec rotation
        audit_handler = logging.handlers.RotatingFileHandler(
            filename=audit_file,
            maxBytes=50 * 1024 * 1024,  # 50MB pour l'audit
            backupCount=10,
            encoding='utf-8'
        )
        audit_handler.setLevel(logging.INFO)
        audit_handler.setFormatter(audit_formatter)
        audit_logger.addHandler(audit_handler)
        
        # Message d'initialisation
        audit_logger.info("=== RAT AUDIT LOGGER INITIALIZED ===")
        
    except Exception as e:
        print(f"Erreur création du logger d'audit: {e}")
    
    return audit_logger

def log_client_action(logger: logging.Logger, 
                     session_id: str, 
                     client_ip: str, 
                     action: str, 
                     details: str = ""):
    """
    Log une action client avec format standardisé
    
    Args:
        logger: Logger à utiliser
        session_id: ID de la session client
        client_ip: Adresse IP du client
        action: Action effectuée
        details: Détails supplémentaires
    """
    message = f"CLIENT_ACTION | {session_id} | {client_ip} | {action}"
    if details:
        message += f" | {details}"
    
    logger.info(message)

def log_security_event(logger: logging.Logger,
                      event_type: str,
                      source: str,
                      severity: str,
                      details: str):
    """
    Log un événement de sécurité
    
    Args:
        logger: Logger à utiliser
        event_type: Type d'événement (INTRUSION, MALWARE, etc.)
        source: Source de l'événement
        severity: Sévérité (LOW, MEDIUM, HIGH, CRITICAL)
        details: Détails de l'événement
    """
    message = f"SECURITY_EVENT | {event_type} | {source} | {severity} | {details}"
    
    if severity in ['HIGH', 'CRITICAL']:
        logger.error(message)
    elif severity == 'MEDIUM':
        logger.warning(message)
    else:
        logger.info(message)

def log_file_operation(logger: logging.Logger,
                      session_id: str,
                      operation: str,
                      file_path: str,
                      size: int = 0,
                      success: bool = True):
    """
    Log une opération sur fichier
    
    Args:
        logger: Logger à utiliser
        session_id: ID de la session
        operation: Type d'opération (DOWNLOAD, UPLOAD, DELETE, etc.)
        file_path: Chemin du fichier
        size: Taille du fichier
        success: Succès de l'opération
    """
    status = "SUCCESS" if success else "FAILED"
    message = f"FILE_OPERATION | {session_id} | {operation} | {file_path} | {size} bytes | {status}"
    
    if success:
        logger.info(message)
    else:
        logger.warning(message)

def setup_performance_logger(perf_file: str = "server/data/logs/rat_performance.log") -> logging.Logger:
    """
    Configure un logger pour les métriques de performance
    
    Args:
        perf_file: Chemin du fichier de performance
    
    Returns:
        logging.Logger: Logger de performance
    """
    
    perf_logger = logging.getLogger("RAT_Performance")
    
    if perf_logger.handlers:
        return perf_logger
    
    perf_logger.setLevel(logging.INFO)
    
    # Format CSV pour faciliter l'analyse
    perf_formatter = logging.Formatter(
        fmt='%(asctime)s,%(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    try:
        os.makedirs(os.path.dirname(perf_file), exist_ok=True)
        
        perf_handler = logging.handlers.RotatingFileHandler(
            filename=perf_file,
            maxBytes=20 * 1024 * 1024,  # 20MB
            backupCount=5,
            encoding='utf-8'
        )
        perf_handler.setLevel(logging.INFO)
        perf_handler.setFormatter(perf_formatter)
        perf_logger.addHandler(perf_handler)
        
        # En-tête CSV
        perf_logger.info("timestamp,metric_name,value,unit,session_id")
        
    except Exception as e:
        print(f"Erreur création du logger de performance: {e}")
    
    return perf_logger

def log_performance_metric(logger: logging.Logger,
                          metric_name: str,
                          value: float,
                          unit: str = "",
                          session_id: str = ""):
    """
    Log une métrique de performance
    
    Args:
        logger: Logger de performance
        metric_name: Nom de la métrique
        value: Valeur de la métrique
        unit: Unité de mesure
        session_id: ID de session associé
    """
    message = f"{metric_name},{value},{unit},{session_id}"
    logger.info(message)

class ContextFilter(logging.Filter):
    """Filtre pour ajouter du contexte aux logs"""
    
    def __init__(self, context: dict):
        super().__init__()
        self.context = context
    
    def filter(self, record):
        for key, value in self.context.items():
            setattr(record, key, value)
        return True

def add_context_to_logger(logger: logging.Logger, context: dict):
    """
    Ajoute un contexte à tous les messages d'un logger
    
    Args:
        logger: Logger à modifier
        context: Dictionnaire de contexte
    """
    context_filter = ContextFilter(context)
    logger.addFilter(context_filter)

# Fonction utilitaire pour la configuration rapide
def get_logger(name: str, debug: bool = False) -> logging.Logger:
    """
    Récupère un logger configuré rapidement
    
    Args:
        name: Nom du logger
        debug: Mode debug
    
    Returns:
        logging.Logger: Logger configuré
    """
    return setup_logger(name=name, debug=debug)