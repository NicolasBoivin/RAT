"""
Server Crypto - Gestion du chiffrement côté serveur
SSL/TLS et chiffrement des communications
"""

import ssl
import socket
import os
from pathlib import Path
from typing import Optional, Dict, Any
import logging

from server.utils.config import ServerConfig
from shared.exceptions import EncryptionError

logger = logging.getLogger(__name__)

class SSLContextManager:
    """Gestionnaire du contexte SSL pour le serveur"""
    
    def __init__(self, config: ServerConfig):
        self.config = config
        self.ssl_context = None
        self._setup_ssl_context()
    
    def _setup_ssl_context(self):
        """Configure le contexte SSL"""
        try:
            # Création du contexte SSL côté serveur
            self.ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            
            # Configuration des certificats
            ssl_config = self.config.get_ssl_config()
            cert_file = ssl_config['cert_file']
            key_file = ssl_config['key_file']
            
            # Vérification de l'existence des fichiers
            if not Path(cert_file).exists():
                raise EncryptionError(f"Certificat SSL non trouvé: {cert_file}")
            
            if not Path(key_file).exists():
                raise EncryptionError(f"Clé privée SSL non trouvée: {key_file}")
            
            # Chargement des certificats
            self.ssl_context.load_cert_chain(cert_file, key_file)
            
            # Configuration de sécurité
            self.ssl_context.minimum_version = ssl.TLSVersion.TLSv1_2
            self.ssl_context.maximum_version = ssl.TLSVersion.TLSv1_3
            
            # Désactivation de la vérification du nom d'hôte (environnement de test)
            if self.config.debug:
                self.ssl_context.check_hostname = False
                self.ssl_context.verify_mode = ssl.CERT_NONE
            
            # Configuration des ciphers sécurisés
            self.ssl_context.set_ciphers('ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20:!aNULL:!MD5:!DSS')
            
            logger.info("Contexte SSL configuré avec succès")
            
        except Exception as e:
            logger.error(f"Erreur configuration SSL: {e}")
            raise EncryptionError(f"Impossible de configurer SSL: {e}")
    
    def wrap_socket(self, socket_obj: socket.socket) -> ssl.SSLSocket:
        """
        Enveloppe une socket avec SSL
        
        Args:
            socket_obj: Socket à envelopper
            
        Returns:
            ssl.SSLSocket: Socket SSL
        """
        try:
            if not self.ssl_context:
                raise EncryptionError("Contexte SSL non initialisé")
            
            ssl_socket = self.ssl_context.wrap_socket(
                socket_obj,
                server_side=True,
                do_handshake_on_connect=False
            )
            
            return ssl_socket
            
        except Exception as e:
            logger.error(f"Erreur enveloppement SSL: {e}")
            raise EncryptionError(f"Impossible d'envelopper la socket: {e}")
    
    def wrap_client_socket(self, client_socket: socket.socket) -> ssl.SSLSocket:
        """
        Enveloppe une socket client avec SSL et effectue le handshake
        
        Args:
            client_socket: Socket client à envelopper
            
        Returns:
            ssl.SSLSocket: Socket SSL client
        """
        try:
            ssl_client = self.wrap_socket(client_socket)
            
            # Handshake SSL
            ssl_client.do_handshake()
            
            # Informations sur la connexion SSL
            cipher = ssl_client.cipher()
            if cipher:
                logger.debug(f"Connexion SSL établie: {cipher[0]} ({cipher[1]} bits)")
            
            return ssl_client
            
        except ssl.SSLError as e:
            logger.error(f"Erreur SSL handshake: {e}")
            raise EncryptionError(f"Échec du handshake SSL: {e}")
        except Exception as e:
            logger.error(f"Erreur enveloppement client SSL: {e}")
            raise EncryptionError(f"Impossible d'envelopper la socket client: {e}")
    
    def get_ssl_info(self) -> Dict[str, Any]:
        """Retourne les informations SSL"""
        try:
            if not self.ssl_context:
                return {'error': 'Contexte SSL non initialisé'}
            
            ssl_config = self.config.get_ssl_config()
            
            return {
                'ssl_enabled': True,
                'cert_file': ssl_config['cert_file'],
                'key_file': ssl_config['key_file'],
                'ca_file': ssl_config.get('ca_file'),
                'minimum_version': str(self.ssl_context.minimum_version),
                'maximum_version': str(self.ssl_context.maximum_version),
                'verify_mode': str(self.ssl_context.verify_mode),
                'check_hostname': self.ssl_context.check_hostname
            }
            
        except Exception as e:
            logger.error(f"Erreur récupération info SSL: {e}")
            return {'error': str(e)}
    
    def validate_certificates(self) -> Dict[str, bool]:
        """Valide les certificats SSL"""
        try:
            ssl_config = self.config.get_ssl_config()
            validation_results = {}
            
            # Vérification des fichiers
            cert_file = Path(ssl_config['cert_file'])
            key_file = Path(ssl_config['key_file'])
            ca_file = Path(ssl_config.get('ca_file', ''))
            
            validation_results['cert_exists'] = cert_file.exists()
            validation_results['key_exists'] = key_file.exists()
            validation_results['ca_exists'] = ca_file.exists() if ssl_config.get('ca_file') else True
            
            # Vérification de la validité des certificats
            if validation_results['cert_exists'] and validation_results['key_exists']:
                try:
                    # Test de chargement des certificats
                    test_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
                    test_context.load_cert_chain(str(cert_file), str(key_file))
                    validation_results['cert_valid'] = True
                except Exception as e:
                    logger.warning(f"Certificat invalide: {e}")
                    validation_results['cert_valid'] = False
            else:
                validation_results['cert_valid'] = False
            
            return validation_results
            
        except Exception as e:
            logger.error(f"Erreur validation certificats: {e}")
            return {'error': str(e)}

class ServerCryptoManager:
    """Gestionnaire de chiffrement pour le serveur"""
    
    def __init__(self, config: ServerConfig):
        self.config = config
        self.ssl_manager = None
        
        if config.network.use_ssl:
            self.ssl_manager = SSLContextManager(config)
    
    def is_ssl_enabled(self) -> bool:
        """Vérifie si SSL est activé"""
        return self.ssl_manager is not None
    
    def wrap_server_socket(self, server_socket: socket.socket) -> socket.socket:
        """Enveloppe la socket serveur avec SSL si activé"""
        if self.ssl_manager:
            return self.ssl_manager.wrap_socket(server_socket)
        return server_socket
    
    def wrap_client_connection(self, client_socket: socket.socket) -> socket.socket:
        """Enveloppe une connexion client avec SSL si activé"""
        if self.ssl_manager:
            return self.ssl_manager.wrap_client_socket(client_socket)
        return client_socket
    
    def get_crypto_info(self) -> Dict[str, Any]:
        """Retourne les informations de chiffrement"""
        info = {
            'ssl_enabled': self.is_ssl_enabled(),
            'encryption_type': 'SSL/TLS' if self.is_ssl_enabled() else 'None'
        }
        
        if self.ssl_manager:
            info.update(self.ssl_manager.get_ssl_info())
        
        return info
    
    def validate_crypto_config(self) -> Dict[str, Any]:
        """Valide la configuration de chiffrement"""
        if not self.is_ssl_enabled():
            return {
                'valid': True,
                'warnings': ['SSL désactivé - communications non chiffrées']
            }
        
        validation = self.ssl_manager.validate_certificates()
        warnings = []
        errors = []
        
        if not validation.get('cert_exists', False):
            errors.append('Fichier certificat manquant')
        
        if not validation.get('key_exists', False):
            errors.append('Fichier clé privée manquant')
        
        if not validation.get('cert_valid', False):
            errors.append('Certificat ou clé privée invalide')
        
        if self.config.debug:
            warnings.append('Mode debug actif - vérifications SSL allégées')
        
        return {
            'valid': len(errors) == 0,
            'errors': errors,
            'warnings': warnings,
            'validation_details': validation
        }

def generate_ssl_certificates(output_dir: str = "server/data/ssl") -> bool:
    """
    Génère des certificats SSL auto-signés pour le développement
    
    Args:
        output_dir: Répertoire de sortie
        
    Returns:
        bool: True si succès
    """
    try:
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from datetime import datetime, timedelta
        import ipaddress
        
        # Création du répertoire
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)
        
        # Génération de la clé privée
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        
        # Informations du certificat
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "FR"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Ile-de-France"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "Paris"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "RAT Project Dev"),
            x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
        ])
        
        # Création du certificat
        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            private_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.utcnow()
        ).not_valid_after(
            datetime.utcnow() + timedelta(days=365)
        ).add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName("localhost"),
                x509.DNSName("127.0.0.1"),
                x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
                x509.IPAddress(ipaddress.IPv4Address("0.0.0.0")),
            ]),
            critical=False,
        ).sign(private_key, hashes.SHA256())
        
        # Sauvegarde de la clé privée
        key_file = output_path / "server-private-key.pem"
        with open(key_file, "wb") as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))
        
        # Sauvegarde du certificat
        cert_file = output_path / "server-certificate.pem"
        with open(cert_file, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
        
        # Sauvegarde du certificat CA (même certificat pour le développement)
        ca_file = output_path / "ca-certificate.pem"
        with open(ca_file, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
        
        logger.info(f"Certificats SSL générés dans: {output_path}")
        return True
        
    except ImportError:
        logger.error("Module cryptography requis pour générer les certificats")
        return False
    except Exception as e:
        logger.error(f"Erreur génération certificats: {e}")
        return False

def test_ssl_connection(host: str = "localhost", port: int = 8888, timeout: int = 5) -> Dict[str, Any]:
    """
    Test une connexion SSL
    
    Args:
        host: Hôte à tester
        port: Port à tester
        timeout: Timeout en secondes
        
    Returns:
        Dict: Résultats du test
    """
    try:
        # Création du contexte SSL client
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        # Test de connexion
        with socket.create_connection((host, port), timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                # Informations sur la connexion
                cipher = ssock.cipher()
                cert = ssock.getpeercert()
                
                return {
                    'success': True,
                    'cipher': cipher[0] if cipher else None,
                    'protocol': ssock.version(),
                    'certificate_subject': cert.get('subject') if cert else None
                }
                
    except socket.timeout:
        return {'success': False, 'error': 'Timeout de connexion'}
    except ssl.SSLError as e:
        return {'success': False, 'error': f'Erreur SSL: {e}'}
    except Exception as e:
        return {'success': False, 'error': f'Erreur: {e}'}