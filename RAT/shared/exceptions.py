"""
Exceptions - Exceptions personnalisées pour le projet RAT
Définit toutes les exceptions spécifiques au projet
"""

class RATException(Exception):
    """Exception de base pour toutes les erreurs RAT"""
    
    def __init__(self, message: str, error_code: int = None):
        super().__init__(message)
        self.message = message
        self.error_code = error_code
        
    def __str__(self):
        if self.error_code:
            return f"[{self.error_code}] {self.message}"
        return self.message

class ConnectionError(RATException):
    """Erreurs de connexion réseau"""
    pass

class AuthenticationError(RATException):
    """Erreurs d'authentification"""
    pass

class ProtocolError(RATException):
    """Erreurs de protocole de communication"""
    pass

class EncryptionError(RATException):
    """Erreurs de chiffrement/déchiffrement"""
    pass

class CommandExecutionError(RATException):
    """Erreurs d'exécution de commande"""
    
    def __init__(self, message: str, command: str = None, return_code: int = None):
        super().__init__(message)
        self.command = command
        self.return_code = return_code

class FileOperationError(RATException):
    """Erreurs d'opérations sur les fichiers"""
    
    def __init__(self, message: str, file_path: str = None, operation: str = None):
        super().__init__(message)
        self.file_path = file_path
        self.operation = operation

class SessionError(RATException):
    """Erreurs de gestion de session"""
    
    def __init__(self, message: str, session_id: str = None):
        super().__init__(message)
        self.session_id = session_id

class SecurityError(RATException):
    """Erreurs de sécurité (commandes dangereuses, etc.)"""
    
    def __init__(self, message: str, security_rule: str = None):
        super().__init__(message)
        self.security_rule = security_rule

class ResourceError(RATException):
    """Erreurs de ressources système"""
    
    def __init__(self, message: str, resource_type: str = None):
        super().__init__(message)
        self.resource_type = resource_type

class TimeoutError(RATException):
    """Erreurs de timeout"""
    
    def __init__(self, message: str, timeout_duration: int = None):
        super().__init__(message)
        self.timeout_duration = timeout_duration

class ConfigurationError(RATException):
    """Erreurs de configuration"""
    
    def __init__(self, message: str, config_key: str = None):
        super().__init__(message)
        self.config_key = config_key

class ModuleError(RATException):
    """Erreurs dans les modules fonctionnels"""
    
    def __init__(self, message: str, module_name: str = None):
        super().__init__(message)
        self.module_name = module_name

class PermissionError(RATException):
    """Erreurs de permissions"""
    
    def __init__(self, message: str, required_permission: str = None):
        super().__init__(message)
        self.required_permission = required_permission

class NetworkError(RATException):
    """Erreurs réseau spécifiques"""
    
    def __init__(self, message: str, host: str = None, port: int = None):
        super().__init__(message)
        self.host = host
        self.port = port

class DataValidationError(RATException):
    """Erreurs de validation de données"""
    
    def __init__(self, message: str, data_field: str = None, expected_type: str = None):
        super().__init__(message)
        self.data_field = data_field
        self.expected_type = expected_type

# === EXCEPTIONS SPÉCIFIQUES AUX MODULES ===

class ScreenshotError(ModuleError):
    """Erreurs de capture d'écran"""
    pass

class KeyloggerError(ModuleError):
    """Erreurs du keylogger"""
    pass

class WebcamError(ModuleError):
    """Erreurs de webcam"""
    pass

class AudioRecordingError(ModuleError):
    """Erreurs d'enregistrement audio"""
    pass

class SystemInfoError(ModuleError):
    """Erreurs de collecte d'informations système"""
    pass

class ShellExecutionError(CommandExecutionError):
    """Erreurs d'exécution shell spécifiques"""
    pass

# === FACTORY FUNCTIONS ===

def create_connection_error(message: str, host: str = None, port: int = None) -> ConnectionError:
    """Crée une erreur de connexion avec contexte"""
    if host and port:
        full_message = f"{message} (Host: {host}:{port})"
    else:
        full_message = message
    return ConnectionError(full_message)

def create_file_error(message: str, file_path: str, operation: str) -> FileOperationError:
    """Crée une erreur de fichier avec contexte"""
    full_message = f"{operation} failed on '{file_path}': {message}"
    return FileOperationError(full_message, file_path, operation)

def create_security_error(message: str, rule: str) -> SecurityError:
    """Crée une erreur de sécurité avec la règle violée"""
    full_message = f"Security violation [{rule}]: {message}"
    return SecurityError(full_message, rule)

def create_timeout_error(operation: str, duration: int) -> TimeoutError:
    """Crée une erreur de timeout avec contexte"""
    message = f"Operation '{operation}' timed out after {duration} seconds"
    return TimeoutError(message, duration)

# === GESTIONNAIRE D'EXCEPTIONS ===

class ExceptionHandler:
    """Gestionnaire centralisé des exceptions"""
    
    @staticmethod
    def handle_exception(exc: Exception, context: str = None) -> dict:
        """
        Gère une exception et retourne un dictionnaire formaté
        
        Args:
            exc: Exception à traiter
            context: Contexte additionnel
        
        Returns:
            dict: Information formatée sur l'erreur
        """
        error_info = {
            'error': True,
            'type': type(exc).__name__,
            'message': str(exc),
            'context': context or 'Unknown'
        }
        
        # Ajout d'informations spécifiques selon le type d'exception
        if isinstance(exc, RATException):
            error_info['error_code'] = getattr(exc, 'error_code', None)
            
        if isinstance(exc, FileOperationError):
            error_info['file_path'] = getattr(exc, 'file_path', None)
            error_info['operation'] = getattr(exc, 'operation', None)
            
        if isinstance(exc, CommandExecutionError):
            error_info['command'] = getattr(exc, 'command', None)
            error_info['return_code'] = getattr(exc, 'return_code', None)
            
        if isinstance(exc, NetworkError):
            error_info['host'] = getattr(exc, 'host', None)
            error_info['port'] = getattr(exc, 'port', None)
        
        return error_info
    
    @staticmethod
    def format_error_message(exc: Exception, include_traceback: bool = False) -> str:
        """
        Formate un message d'erreur pour l'affichage
        
        Args:
            exc: Exception à formater
            include_traceback: Inclure la stack trace
        
        Returns:
            str: Message formaté
        """
        base_message = f"[{type(exc).__name__}] {str(exc)}"
        
        if include_traceback:
            import traceback
            base_message += "\n" + traceback.format_exc()
        
        return base_message

# === VALIDATEURS ===

def validate_session_id(session_id: str) -> None:
    """Valide un ID de session"""
    if not session_id or not isinstance(session_id, str):
        raise DataValidationError("Session ID must be a non-empty string", "session_id", "str")
    
    if not session_id.startswith("agent_"):
        raise DataValidationError("Invalid session ID format", "session_id", "agent_*")

def validate_file_path(file_path: str) -> None:
    """Valide un chemin de fichier"""
    if not file_path or not isinstance(file_path, str):
        raise DataValidationError("File path must be a non-empty string", "file_path", "str")
    
    # Vérifications de sécurité basiques
    dangerous_patterns = ['..', '|', ';', '&', '$']
    if any(pattern in file_path for pattern in dangerous_patterns):
        raise SecurityError("Dangerous characters in file path", "PATH_TRAVERSAL")

def validate_command(command: str) -> None:
    """Valide une commande avant exécution"""
    if not command or not isinstance(command, str):
        raise DataValidationError("Command must be a non-empty string", "command", "str")
    
    command_lower = command.lower()
    dangerous_commands = ['format', 'del /s', 'rm -rf /', 'dd if=']
    
    if any(dangerous in command_lower for dangerous in dangerous_commands):
        raise SecurityError("Dangerous command detected", "DANGEROUS_COMMAND")

def validate_network_params(host: str, port: int) -> None:
    """Valide les paramètres réseau"""
    if not host or not isinstance(host, str):
        raise DataValidationError("Host must be a non-empty string", "host", "str")
    
    if not isinstance(port, int) or not (1 <= port <= 65535):
        raise DataValidationError("Port must be an integer between 1 and 65535", "port", "int")

# === DÉCORATEURS D'EXCEPTION ===

def handle_rat_exceptions(func):
    """Décorateur pour gérer les exceptions RAT"""
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except RATException:
            raise  # Re-raise les exceptions RAT
        except Exception as e:
            # Convertir les autres exceptions en RATException
            raise RATException(f"Unexpected error in {func.__name__}: {str(e)}")
    return wrapper

def handle_file_operations(func):
    """Décorateur pour gérer les opérations sur les fichiers"""
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except (IOError, OSError) as e:
            raise FileOperationError(f"File operation failed: {str(e)}")
        except PermissionError as e:
            raise PermissionError(f"Permission denied: {str(e)}")
    return wrapper

def handle_network_operations(func):
    """Décorateur pour gérer les opérations réseau"""
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except (ConnectionError, OSError) as e:
            raise NetworkError(f"Network operation failed: {str(e)}")
        except TimeoutError as e:
            raise TimeoutError(f"Network timeout: {str(e)}")
    return wrapper