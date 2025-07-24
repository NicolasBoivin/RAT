"""
Client Crypto - Gestion du chiffrement côté client
SSL/TLS et chiffrement des communications client
"""

import ssl
import socket
import os
from pathlib import Path
from typing import Optional, Dict, Any
import logging

from client.utils.config import ClientConfig
from shared.exceptions import EncryptionError

logger = logging.getLogger(__name__)

class ClientSSLManager:
    """Gestionnaire SSL côté client"""
    
    def __init__(self, config: ClientConfig):
        self.config = config
        self.ssl_context = None
        
        if config.USE_SSL:
            self._setup_ssl_context()
    
    def _setup_ssl_context(self):
        """Configure le contexte SSL client"""
        try:
            # Création du contexte SSL client
            self.ssl_context = ssl.create_default_context()
            
            # Configuration pour environnement de développement/test
            if self.config.DEBUG:
                # Désactivation de la vérification pour les certificats auto-signés
                self.ssl_context.check_hostname = False
                self.ssl_context.verify_mode = ssl.CERT_NONE
                logger.debug("SSL configuré en mode développement (vérifications désactivées)")
            else:
                # Configuration plus stricte pour la production
                self.ssl_context.verify_mode = ssl.CERT_REQUIRED
                
                # Chargement du certificat CA si fourni
                if self.config.SSL_CA_FILE and Path(self.config.SSL_CA_FILE).exists():
                    self.ssl_context.load_verify_locations(self.config.SSL_CA_FILE)
                    logger.debug(f"Certificat CA chargé: {self.config.SSL_CA_FILE}")
            
            # Configuration des versions TLS
            self.ssl_context.minimum_version = ssl.TLSVersion.TLSv1_2
            self.ssl_context.maximum_version = ssl.TLSVersion.TLSv1_3
            
            # Configuration des ciphers sécurisés
            self.ssl_context.set_ciphers('ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20:!aNULL:!MD5:!DSS')
            
            logger.info("Contexte SSL client configuré")
            
        except Exception as e:
            logger.error(f"Erreur configuration SSL client: {e}")
            raise EncryptionError(f"Impossible de configurer SSL: {e}")
    
    def wrap_socket(self, socket_obj: socket.socket, hostname: str) -> ssl.SSLSocket:
        """
        Enveloppe une socket avec SSL
        
        Args:
            socket_obj: Socket à envelopper
            hostname: Nom d'hôte du serveur
            
        Returns:
            ssl.SSLSocket: Socket SSL
        """
        try:
            if not self.ssl_context:
                raise EncryptionError("Contexte SSL non initialisé")
            
            # Enveloppement de la socket
            ssl_socket = self.ssl_context.wrap_socket(
                socket_obj,
                server_hostname=hostname if not self.config.DEBUG else None
            )
            
            # Informations sur la connexion établie
            if self.config.DEBUG:
                cipher = ssl_socket.cipher()
                if cipher:
                    logger.debug(f"Connexion SSL établie: {cipher[0]} ({cipher[1]} bits)")
                
                # Informations sur le certificat serveur
                cert = ssl_socket.getpeercert()
                if cert:
                    subject = dict(x[0] for x in cert['subject'])
                    logger.debug(f"Certificat serveur: {subject.get('commonName', 'Inconnu')}")
            
            return ssl_socket
            
        except ssl.SSLError as e:
            logger.error(f"Erreur SSL: {e}")
            raise EncryptionError(f"Échec de la connexion SSL: {e}")
        except Exception as e:
            logger.error(f"Erreur enveloppement SSL: {e}")
            raise EncryptionError(f"Impossible d'envelopper la socket: {e}")
    
    def get_ssl_info(self) -> Dict[str, Any]:
        """Retourne les informations SSL"""
        try:
            if not self.ssl_context:
                return {'ssl_enabled': False}
            
            return {
                'ssl_enabled': True,
                'verify_mode': str(self.ssl_context.verify_mode),
                'check_hostname': self.ssl_context.check_hostname,
                'minimum_version': str(self.ssl_context.minimum_version),
                'maximum_version': str(self.ssl_context.maximum_version),
                'ca_file': self.config.SSL_CA_FILE,
                'debug_mode': self.config.DEBUG
            }
            
        except Exception as e:
            return {'error': str(e)}
    
    def test_ssl_connection(self, host: str, port: int, timeout: int = 5) -> Dict[str, Any]:
        """
        Teste une connexion SSL au serveur
        
        Args:
            host: Hôte serveur
            port: Port serveur
            timeout: Timeout en secondes
            
        Returns:
            Dict: Résultats du test
        """
        try:
            # Création de la socket de test
            test_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            test_socket.settimeout(timeout)
            
            # Connexion TCP
            test_socket.connect((host, port))
            
            # Enveloppement SSL
            ssl_socket = self.wrap_socket(test_socket, host)
            
            # Récupération des informations de connexion
            cipher = ssl_socket.cipher()
            protocol = ssl_socket.version()
            cert = ssl_socket.getpeercert()
            
            # Fermeture de la connexion de test
            ssl_socket.close()
            
            return {
                'success': True,
                'cipher': cipher[0] if cipher else None,
                'cipher_bits': cipher[1] if cipher else None,
                'protocol': protocol,
                'certificate_present': cert is not None,
                'certificate_subject': dict(x[0] for x in cert['subject']) if cert else None
            }
            
        except socket.timeout:
            return {'success': False, 'error': 'Timeout de connexion'}
        except ssl.SSLError as e:
            return {'success': False, 'error': f'Erreur SSL: {e}'}
        except ConnectionRefusedError:
            return {'success': False, 'error': 'Connexion refusée'}
        except Exception as e:
            return {'success': False, 'error': f'Erreur: {e}'}
        finally:
            try:
                test_socket.close()
            except:
                pass

class CryptoManager:
    """Gestionnaire de chiffrement principal pour le client"""
    
    def __init__(self, config: ClientConfig):
        self.config = config
        self.ssl_manager = None
        
        # Initialisation du gestionnaire SSL si activé
        if config.USE_SSL:
            self.ssl_manager = ClientSSLManager(config)
        
        # Autres gestionnaires de chiffrement peuvent être ajoutés ici
        self.symmetric_key = None
        if config.ENCRYPTION_KEY:
            self.symmetric_key = config.ENCRYPTION_KEY.encode() if isinstance(config.ENCRYPTION_KEY, str) else config.ENCRYPTION_KEY
    
    def is_ssl_enabled(self) -> bool:
        """Vérifie si SSL est activé"""
        return self.ssl_manager is not None
    
    def wrap_socket(self, socket_obj: socket.socket, hostname: str) -> socket.socket:
        """Enveloppe une socket avec SSL si activé"""
        if self.ssl_manager:
            return self.ssl_manager.wrap_socket(socket_obj, hostname)
        return socket_obj
    
    def encrypt_data(self, data: bytes) -> bytes:
        """
        Chiffre des données (en plus de SSL)
        
        Args:
            data: Données à chiffrer
            
        Returns:
            bytes: Données chiffrées
        """
        if not self.symmetric_key:
            return data  # Pas de chiffrement supplémentaire
        
        try:
            # Chiffrement XOR simple (pour démonstration éducative)
            return self._xor_encrypt(data, self.symmetric_key)
        except Exception as e:
            logger.error(f"Erreur chiffrement: {e}")
            return data  # Retourne les données non chiffrées en cas d'erreur
    
    def decrypt_data(self, data: bytes) -> bytes:
        """
        Déchiffre des données
        
        Args:
            data: Données à déchiffrer
            
        Returns:
            bytes: Données déchiffrées
        """
        if not self.symmetric_key:
            return data  # Pas de déchiffrement nécessaire
        
        try:
            # Déchiffrement XOR (symétrique)
            return self._xor_encrypt(data, self.symmetric_key)
        except Exception as e:
            logger.error(f"Erreur déchiffrement: {e}")
            return data  # Retourne les données telles quelles en cas d'erreur
    
    def _xor_encrypt(self, data: bytes, key: bytes) -> bytes:
        """Chiffrement/déchiffrement XOR simple"""
        return bytes(a ^ b for a, b in zip(data, key * (len(data) // len(key) + 1)))
    
    def generate_session_key(self) -> bytes:
        """Génère une clé de session aléatoire"""
        return os.urandom(32)  # 256 bits
    
    def get_crypto_status(self) -> Dict[str, Any]:
        """Retourne le statut du chiffrement"""
        status = {
            'ssl_enabled': self.is_ssl_enabled(),
            'symmetric_encryption': self.symmetric_key is not None,
            'encryption_layers': []
        }
        
        if self.is_ssl_enabled():
            status['encryption_layers'].append('SSL/TLS')
            status.update(self.ssl_manager.get_ssl_info())
        
        if self.symmetric_key:
            status['encryption_layers'].append('Symmetric (XOR)')
        
        if not status['encryption_layers']:
            status['encryption_layers'].append('None')
            status['warning'] = 'Aucun chiffrement actif'
        
        return status
    
    def test_connection_security(self, host: str, port: int) -> Dict[str, Any]:
        """Teste la sécurité de la connexion"""
        results = {
            'ssl_test': None,
            'overall_security': 'low',
            'recommendations': []
        }
        
        # Test SSL si activé
        if self.is_ssl_enabled():
            results['ssl_test'] = self.ssl_manager.test_ssl_connection(host, port)
            if results['ssl_test']['success']:
                results['overall_security'] = 'high'
            else:
                results['recommendations'].append('Vérifier la configuration SSL')
        else:
            results['recommendations'].append('Activer SSL pour sécuriser les communications')
        
        # Vérifications supplémentaires
        if not self.symmetric_key and not self.is_ssl_enabled():
            results['recommendations'].append('Aucun chiffrement actif - communications en clair')
        
        if self.config.DEBUG:
            results['recommendations'].append('Mode debug actif - sécurité réduite')
        
        return results

class StealthCrypto:
    """Fonctions de chiffrement pour le mode furtif"""
    
    @staticmethod
    def obfuscate_string(text: str, key: str = "stealth") -> str:
        """
        Obfusque une chaîne de caractères
        
        Args:
            text: Texte à obfusquer
            key: Clé d'obfuscation
            
        Returns:
            str: Texte obfusqué (base64)
        """
        try:
            import base64
            
            # XOR avec la clé
            key_bytes = key.encode() * (len(text) // len(key) + 1)
            xored = bytes(a ^ b for a, b in zip(text.encode(), key_bytes))
            
            # Encodage base64
            return base64.b64encode(xored).decode()
            
        except Exception:
            return text
    
    @staticmethod
    def deobfuscate_string(obfuscated: str, key: str = "stealth") -> str:
        """
        Désobfusque une chaîne de caractères
        
        Args:
            obfuscated: Texte obfusqué
            key: Clé de désobfuscation
            
        Returns:
            str: Texte original
        """
        try:
            import base64
            
            # Décodage base64
            xored = base64.b64decode(obfuscated.encode())
            
            # XOR avec la clé
            key_bytes = key.encode() * (len(xored) // len(key) + 1)
            original = bytes(a ^ b for a, b in zip(xored, key_bytes))
            
            return original.decode()
            
        except Exception:
            return obfuscated
    
    @staticmethod
    def generate_stealth_key() -> str:
        """Génère une clé furtive basée sur les caractéristiques système"""
        try:
            import hashlib
            import platform
            
            # Utilisation de caractéristiques système pour la clé
            system_info = f"{platform.node()}-{platform.machine()}"
            return hashlib.md5(system_info.encode()).hexdigest()[:16]
            
        except Exception:
            return "default_stealth_key"
    
    @staticmethod
    def hide_in_image(data: bytes, image_path: str, output_path: str) -> bool:
        """
        Cache des données dans une image (stéganographie basique)
        
        Args:
            data: Données à cacher
            image_path: Chemin de l'image source
            output_path: Chemin de l'image de sortie
            
        Returns:
            bool: True si succès
        """
        try:
            from PIL import Image
            import numpy as np
            
            # Chargement de l'image
            img = Image.open(image_path)
            img_array = np.array(img)
            
            # Conversion des données en bits
            data_bits = ''.join(format(byte, '08b') for byte in data)
            data_bits += '1111111111111110'  # Marqueur de fin
            
            # Vérification de la capacité
            if len(data_bits) > img_array.size:
                return False
            
            # Insertion des bits dans les LSB
            flat = img_array.flatten()
            for i, bit in enumerate(data_bits):
                flat[i] = (flat[i] & 0xFE) | int(bit)
            
            # Reconstruction et sauvegarde
            img_array = flat.reshape(img_array.shape)
            result_img = Image.fromarray(img_array)
            result_img.save(output_path)
            
            return True
            
        except ImportError:
            logger.warning("PIL non disponible pour la stéganographie")
            return False
        except Exception as e:
            logger.error(f"Erreur stéganographie: {e}")
            return False
    
    @staticmethod
    def extract_from_image(image_path: str) -> Optional[bytes]:
        """
        Extrait des données cachées dans une image
        
        Args:
            image_path: Chemin de l'image
            
        Returns:
            bytes ou None: Données extraites
        """
        try:
            from PIL import Image
            import numpy as np
            
            # Chargement de l'image
            img = Image.open(image_path)
            img_array = np.array(img)
            
            # Extraction des bits
            flat = img_array.flatten()
            bits = ''.join(str(pixel & 1) for pixel in flat)
            
            # Recherche du marqueur de fin
            marker = '1111111111111110'
            end_pos = bits.find(marker)
            
            if end_pos == -1:
                return None
            
            # Conversion en bytes
            data_bits = bits[:end_pos]
            if len(data_bits) % 8 != 0:
                return None
            
            data = bytearray()
            for i in range(0, len(data_bits), 8):
                byte = int(data_bits[i:i+8], 2)
                data.append(byte)
            
            return bytes(data)
            
        except ImportError:
            logger.warning("PIL non disponible pour l'extraction")
            return None
        except Exception as e:
            logger.error(f"Erreur extraction: {e}")
            return None

def create_secure_config(config: ClientConfig) -> Dict[str, Any]:
    """Crée une configuration sécurisée pour le client"""
    secure_config = {
        'use_ssl': True,
        'ssl_verify': not config.DEBUG,
        'encryption_enabled': True,
        'stealth_mode': config.STEALTH_MODE,
        'debug': config.DEBUG
    }
    
    # Recommandations de sécurité
    recommendations = []
    
    if not config.USE_SSL:
        recommendations.append("Activer SSL pour chiffrer les communications")
    
    if config.DEBUG:
        recommendations.append("Désactiver le mode debug en production")
    
    if not config.STEALTH_MODE:
        recommendations.append("Considérer l'activation du mode furtif")
    
    secure_config['security_recommendations'] = recommendations
    
    return secure_config

def validate_crypto_environment() -> Dict[str, Any]:
    """Valide l'environnement cryptographique"""
    validation = {
        'ssl_available': True,
        'cryptography_available': False,
        'pil_available': False,
        'issues': []
    }
    
    # Vérification des modules
    try:
        import ssl
        validation['ssl_version'] = ssl.OPENSSL_VERSION
    except ImportError:
        validation['ssl_available'] = False
        validation['issues'].append("Module SSL non disponible")
    
    try:
        import cryptography
        validation['cryptography_available'] = True
        validation['cryptography_version'] = cryptography.__version__
    except ImportError:
        validation['issues'].append("Module cryptography non disponible (recommandé)")
    
    try:
        from PIL import Image
        validation['pil_available'] = True
    except ImportError:
        validation['issues'].append("PIL non disponible (requis pour stéganographie)")
    
    # Vérification des algorithmes
    try:
        import hashlib
        validation['hash_algorithms'] = hashlib.algorithms_available
    except Exception:
        validation['issues'].append("Algorithmes de hash limités")
    
    return validation