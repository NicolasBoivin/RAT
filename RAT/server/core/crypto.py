"""
SSL Context Manager - Gestionnaire SSL/TLS pour le serveur RAT
Gestion des certificats et contextes SSL sécurisés
"""

import ssl
import os
import socket
from pathlib import Path
from typing import Optional, Dict, Any, Tuple
import logging

try:
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization, hashes
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
    from datetime import datetime, timedelta
    CRYPTOGRAPHY_AVAILABLE = True
except ImportError:
    CRYPTOGRAPHY_AVAILABLE = False

from server.utils.config import ServerConfig
from shared.exceptions import SecurityException

logger = logging.getLogger(__name__)

class SSLContextManager:
    """Gestionnaire de contexte SSL pour le serveur"""
    
    def __init__(self, config: ServerConfig):
        self.config = config
        self.ssl_context = None
        self.certificates_info = {}
        
        # Configuration SSL si activé
        if config.USE_SSL:
            self._setup_ssl_context()
        
        logger.info("SSLContextManager initialisé")
    
    def _setup_ssl_context(self):
        """Configure le contexte SSL du serveur"""
        try:
            # Création du contexte SSL serveur
            self.ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            
            # Configuration des protocoles sécurisés
            self.ssl_context.minimum_version = ssl.TLSVersion.TLSv1_2
            self.ssl_context.maximum_version = ssl.TLSVersion.TLSv1_3
            
            # Configuration des ciphers sécurisés
            self.ssl_context.set_ciphers([
                'ECDHE+AESGCM',
                'ECDHE+CHACHA20',
                'DHE+AESGCM',
                'DHE+CHACHA20',
                '!aNULL',
                '!MD5',
                '!DSS',
                '!RC4'
            ])
            
            # Chargement des certificats
            if not self._load_certificates():
                raise SecurityException("Impossible de charger les certificats SSL")
            
            # Configuration de la vérification client si demandée
            if self.config.SSL_VERIFY_CLIENT:
                self.ssl_context.verify_mode = ssl.CERT_REQUIRED
                if self.config.SSL_CA_FILE and os.path.exists(self.config.SSL_CA_FILE):
                    self.ssl_context.load_verify_locations(self.config.SSL_CA_FILE)
            else:
                self.ssl_context.verify_mode = ssl.CERT_NONE
            
            # Configuration des options SSL
            self.ssl_context.options |= ssl.OP_NO_SSLv2
            self.ssl_context.options |= ssl.OP_NO_SSLv3
            self.ssl_context.options |= ssl.OP_NO_COMPRESSION
            self.ssl_context.options |= ssl.OP_CIPHER_SERVER_PREFERENCE
            
            # Désactivation du renegotiation pour la sécurité
            self.ssl_context.options |= getattr(ssl, 'OP_NO_RENEGOTIATION', 0)
            
            logger.info("Contexte SSL serveur configuré avec succès")
            
        except Exception as e:
            logger.error(f"Erreur configuration SSL: {e}")
            raise SecurityException(f"Impossible de configurer SSL: {e}")
    
    def _load_certificates(self) -> bool:
        """Charge les certificats SSL"""
        try:
            # Vérification de la présence des fichiers requis
            if not self.config.SSL_CERT_FILE or not os.path.exists(self.config.SSL_CERT_FILE):
                logger.error(f"Certificat SSL non trouvé: {self.config.SSL_CERT_FILE}")
                
                # Tentative de génération automatique
                if self._auto_generate_certificates():
                    logger.info("Certificats auto-générés utilisés")
                else:
                    return False
            
            if not self.config.SSL_KEY_FILE or not os.path.exists(self.config.SSL_KEY_FILE):
                logger.error(f"Clé privée SSL non trouvée: {self.config.SSL_KEY_FILE}")
                return False
            
            # Chargement des certificats dans le contexte SSL
            self.ssl_context.load_cert_chain(
                certfile=self.config.SSL_CERT_FILE,
                keyfile=self.config.SSL_KEY_FILE
            )
            
            # Lecture des informations des certificats
            self._read_certificate_info()
            
            logger.info("Certificats SSL chargés avec succès")
            return True
            
        except Exception as e:
            logger.error(f"Erreur chargement certificats: {e}")
            return False
    
    def _auto_generate_certificates(self) -> bool:
        """Génère automatiquement des certificats auto-signés"""
        try:
            if not CRYPTOGRAPHY_AVAILABLE:
                logger.error("Cryptography non disponible - impossible de générer les certificats")
                return False
            
            logger.info("Génération automatique des certificats SSL...")
            
            # Génération de la clé privée
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
            )
            
            # Création du certificat auto-signé
            subject = issuer = x509.Name([
                x509.NameAttribute(NameOID.COUNTRY_NAME, "FR"),
                x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Ile-de-France"),
                x509.NameAttribute(NameOID.LOCALITY_NAME, "Paris"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "RAT Project Academic"),
                x509.NameAttribute(NameOID.COMMON_NAME, "RAT Server"),
            ])
            
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
                    x509.DNSName("rat-server"),
                    x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
                    x509.IPAddress(ipaddress.IPv4Address("0.0.0.0")),
                ]),
                critical=False,
            ).sign(private_key, hashes.SHA256())
            
            # Création du répertoire SSL
            ssl_dir = Path(self.config.DATA_DIR) / "ssl"
            ssl_dir.mkdir(parents=True, exist_ok=True)
            
            # Sauvegarde de la clé privée
            key_file = ssl_dir / "server-key.pem"
            with open(key_file, "wb") as f:
                f.write(private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                ))
            
            # Sauvegarde du certificat
            cert_file = ssl_dir / "server-cert.pem"
            with open(cert_file, "wb") as f:
                f.write(cert.public_bytes(serialization.Encoding.PEM))
            
            # Mise à jour de la configuration
            self.config.SSL_CERT_FILE = str(cert_file)
            self.config.SSL_KEY_FILE = str(key_file)
            
            # Importation d'ipaddress pour l'utilisation ci-dessus
            import ipaddress  
            
            logger.info(f"Certificats générés: {cert_file}, {key_file}")
            return True
            
        except Exception as e:
            logger.error(f"Erreur génération certificats: {e}")
            return False
    
    def _read_certificate_info(self):
        """Lit les informations des certificats chargés"""
        try:
            if not CRYPTOGRAPHY_AVAILABLE:
                return
            
            # Lecture du certificat
            with open(self.config.SSL_CERT_FILE, 'rb') as f:
                cert_data = f.read()
                cert = x509.load_pem_x509_certificate(cert_data)
            
            # Extraction des informations
            self.certificates_info = {
                'subject': cert.subject.rfc4514_string(),
                'issuer': cert.issuer.rfc4514_string(),
                'serial_number': str(cert.serial_number),
                'not_valid_before': cert.not_valid_before.isoformat(),
                'not_valid_after': cert.not_valid_after.isoformat(),
                'signature_algorithm': cert.signature_algorithm_oid._name,
                'version': cert.version.name,
                'is_ca': False
            }
            
            # Vérification si c'est un certificat CA
            try:
                basic_constraints = cert.extensions.get_extension_for_oid(
                    x509.oid.ExtensionOID.BASIC_CONSTRAINTS
                ).value
                self.certificates_info['is_ca'] = basic_constraints.ca
            except x509.ExtensionNotFound:
                pass
            
            # Extraction des noms alternatifs
            try:
                san = cert.extensions.get_extension_for_oid(
                    x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME
                ).value
                alt_names = []
                for name in san:
                    alt_names.append(str(name))
                self.certificates_info['alternative_names'] = alt_names
            except x509.ExtensionNotFound:
                self.certificates_info['alternative_names'] = []
            
            # Vérification de l'expiration
            now = datetime.utcnow()
            self.certificates_info['is_expired'] = cert.not_valid_after < now
            self.certificates_info['expires_soon'] = (cert.not_valid_after - now).days < 30
            
            logger.debug("Informations de certificat lues")
            
        except Exception as e:
            logger.error(f"Erreur lecture certificat: {e}")
    
    def wrap_client_socket(self, client_socket: socket.socket) -> ssl.SSLSocket:
        """
        Enveloppe un socket client avec SSL
        
        Args:
            client_socket: Socket client à envelopper
        
        Returns:
            ssl.SSLSocket: Socket SSL
        """
        try:
            if not self.ssl_context:
                raise SecurityException("Contexte SSL non configuré")
            
            # Enveloppement SSL côté serveur
            ssl_socket = self.ssl_context.wrap_socket(
                client_socket,
                server_side=True
            )
            
            logger.debug("Socket client enveloppé avec SSL")
            return ssl_socket
            
        except Exception as e:
            logger.error(f"Erreur enveloppement SSL client: {e}")
            raise SecurityException(f"Impossible d'établir la connexion SSL: {e}")
    
    def get_ssl_info(self) -> Dict[str, Any]:
        """
        Récupère les informations SSL du serveur
        
        Returns:
            Dict: Informations SSL
        """
        try:
            info = {
                'ssl_enabled': self.config.USE_SSL,
                'ssl_context_configured': self.ssl_context is not None,
                'cert_file': self.config.SSL_CERT_FILE,
                'key_file': self.config.SSL_KEY_FILE,
                'ca_file': self.config.SSL_CA_FILE,
                'verify_client': self.config.SSL_VERIFY_CLIENT
            }
            
            if self.ssl_context:
                info.update({
                    'minimum_version': str(self.ssl_context.minimum_version),
                    'maximum_version': str(self.ssl_context.maximum_version),
                    'verify_mode': str(self.ssl_context.verify_mode),
                    'ciphers': self._get_available_ciphers()
                })
            
            if self.certificates_info:
                info['certificate'] = self.certificates_info
            
            return info
            
        except Exception as e:
            logger.error(f"Erreur récupération info SSL: {e}")
            return {'error': str(e)}
    
    def _get_available_ciphers(self) -> List[str]:
        """Récupère la liste des ciphers disponibles"""
        try:
            if self.ssl_context:
                # Création d'un socket temporaire pour tester les ciphers
                temp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                temp_socket.bind(('localhost', 0))
                temp_socket.listen(1)
                
                try:
                    ssl_socket = self.ssl_context.wrap_socket(temp_socket, server_side=True)
                    ciphers = ssl_socket.cipher()
                    return [ciphers] if ciphers else []
                finally:
                    temp_socket.close()
            
            return []
            
        except Exception:
            return []
    
    def validate_certificates(self) -> Dict[str, Any]:
        """
        Valide les certificats SSL
        
        Returns:
            Dict: Résultat de la validation
        """
        try:
            validation_result = {
                'valid': True,
                'errors': [],
                'warnings': [],
                'certificate_info': self.certificates_info
            }
            
            if not self.certificates_info:
                validation_result['valid'] = False
                validation_result['errors'].append("Aucune information de certificat disponible")
                return validation_result
            
            # Vérification de l'expiration
            if self.certificates_info.get('is_expired'):
                validation_result['valid'] = False
                validation_result['errors'].append("Le certificat a expiré")
            elif self.certificates_info.get('expires_soon'):
                validation_result['warnings'].append("Le certificat expire dans moins de 30 jours")
            
            # Vérification de la taille de clé (si possible)
            if CRYPTOGRAPHY_AVAILABLE:
                try:
                    with open(self.config.SSL_CERT_FILE, 'rb') as f:
                        cert_data = f.read()
                        cert = x509.load_pem_x509_certificate(cert_data)
                        
                        public_key = cert.public_key()
                        if hasattr(public_key, 'key_size'):
                            key_size = public_key.key_size
                            if key_size < 2048:
                                validation_result['warnings'].append(f"Taille de clé faible: {key_size} bits")
                            validation_result['key_size'] = key_size
                except Exception as e:
                    validation_result['warnings'].append(f"Impossible de vérifier la taille de clé: {e}")
            
            # Vérification des algorithmes
            if 'signature_algorithm' in self.certificates_info:
                sig_alg = self.certificates_info['signature_algorithm']
                weak_algorithms = ['md5', 'sha1']
                
                if any(weak_alg in sig_alg.lower() for weak_alg in weak_algorithms):
                    validation_result['warnings'].append(f"Algorithme de signature faible: {sig_alg}")
            
            return validation_result
            
        except Exception as e:
            logger.error(f"Erreur validation certificats: {e}")
            return {
                'valid': False,
                'errors': [f"Erreur lors de la validation: {e}"],
                'warnings': []
            }
    
    def renew_certificates(self) -> bool:
        """
        Renouvelle les certificats SSL (génère de nouveaux certificats auto-signés)
        
        Returns:
            bool: True si le renouvellement a réussi
        """
        try:
            logger.info("Renouvellement des certificats SSL...")
            
            # Sauvegarde des anciens certificats
            if os.path.exists(self.config.SSL_CERT_FILE):
                backup_cert = self.config.SSL_CERT_FILE + '.backup'
                shutil.copy2(self.config.SSL_CERT_FILE, backup_cert)
                logger.info(f"Ancien certificat sauvegardé: {backup_cert}")
            
            if os.path.exists(self.config.SSL_KEY_FILE):
                backup_key = self.config.SSL_KEY_FILE + '.backup'
                shutil.copy2(self.config.SSL_KEY_FILE, backup_key)
                logger.info(f"Ancienne clé sauvegardée: {backup_key}")
            
            # Génération de nouveaux certificats
            if self._auto_generate_certificates():
                # Rechargement du contexte SSL
                self._setup_ssl_context()
                logger.info("Certificats renouvelés avec succès")
                return True
            else:
                logger.error("Échec du renouvellement des certificats")
                return False
                
        except Exception as e:
            logger.error(f"Erreur renouvellement certificats: {e}")
            return False
    
    def test_ssl_configuration(self) -> Dict[str, Any]:
        """
        Teste la configuration SSL
        
        Returns:
            Dict: Résultat du test
        """
        try:
            test_result = {
                'success': False,
                'ssl_context': self.ssl_context is not None,
                'certificates_loaded': bool(self.certificates_info),
                'errors': []
            }
            
            if not self.ssl_context:
                test_result['errors'].append("Contexte SSL non configuré")
                return test_result
            
            # Test de création d'un socket SSL
            try:
                test_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                test_socket.bind(('localhost', 0))
                test_socket.listen(1)
                
                # Test d'enveloppement SSL
                ssl_socket = self.ssl_context.wrap_socket(test_socket, server_side=True)
                
                test_result['bind_port'] = test_socket.getsockname()[1]
                test_result['success'] = True
                
                ssl_socket.close()
                test_socket.close()
                
            except Exception as e:
                test_result['errors'].append(f"Erreur test socket SSL: {e}")
            
            # Validation des certificats
            cert_validation = self.validate_certificates()
            test_result['certificate_validation'] = cert_validation
            
            if not cert_validation['valid']:
                test_result['errors'].extend(cert_validation['errors'])
            
            return test_result
            
        except Exception as e:
            logger.error(f"Erreur test SSL: {e}")
            return {
                'success': False,
                'errors': [f"Erreur lors du test: {e}"]
            }
    
    def get_connection_info(self, ssl_socket: ssl.SSLSocket) -> Dict[str, Any]:
        """
        Récupère les informations d'une connexion SSL
        
        Args:
            ssl_socket: Socket SSL connecté
        
        Returns:
            Dict: Informations de connexion
        """
        try:
            return {
                'cipher': ssl_socket.cipher(),
                'peer_certificate': ssl_socket.getpeercert(),
                'peer_certificate_chain': ssl_socket.getpeercert_chain(),
                'ssl_version': ssl_socket.version(),
                'server_side': ssl_socket.server_side,
                'do_handshake_on_connect': ssl_socket.do_handshake_on_connect
            }
            
        except Exception as e:
            logger.error(f"Erreur récupération info connexion: {e}")
            return {'error': str(e)}
    
    def cleanup(self):
        """Nettoyage des ressources SSL"""
        try:
            if self.ssl_context:
                self.ssl_context = None
            
            self.certificates_info.clear()
            
            logger.debug("Nettoyage SSL effectué")
            
        except Exception as e:
            logger.error(f"Erreur nettoyage SSL: {e}")
    
    def __del__(self):
        """Destructeur - nettoyage automatique"""
        try:
            self.cleanup()
        except:
            pass