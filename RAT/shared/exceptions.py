"""
Exceptions personnalisées pour le projet RAT
Définit les exceptions spécifiques au système
"""

class RATException(Exception):
    """Exception de base pour le système RAT"""
    
    def __init__(self, message: str, error_code: str = None):
        super().__init__(message)
        self.message = message
        self.error_code = error_code
    
    def __str__(self):
        if self.error_code:
            return f"[{self.error_code}] {self.message}"
        return self.message

class ConnectionException(RATException):
    """Exception pour les erreurs de connexion"""
    pass

class AuthenticationException(RATException):
    """Exception pour les erreurs d'authentification"""
    pass

class ProtocolException(RATException):
    """Exception pour les erreurs de protocole"""
    pass

class CommandException(RATException):
    """Exception pour les erreurs de commandes"""
    pass

class FileOperationException(RATException):
    """Exception pour les erreurs d'opérations fichiers"""
    pass

class MediaException(RATException):
    """Exception pour les erreurs de médias"""
    pass

class SecurityException(RATException):
    """Exception pour les erreurs de sécurité"""
    pass

class ConfigurationException(RATException):
    """Exception pour les erreurs de configuration"""
    pass