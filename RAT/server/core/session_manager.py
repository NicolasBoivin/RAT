"""
Session Manager - Gestion des sessions clients
Inspiré de l'architecture multi-client de GUIShell
"""

import threading
import time
import uuid
from typing import Dict, Optional, List, Tuple
import socket
import logging

from shared.protocol import Protocol

logger = logging.getLogger(__name__)

class ClientSession:
    """Représente une session client connectée"""
    
    def __init__(self, socket_obj: socket.socket, address: Tuple[str, int]):
        self.id = self._generate_session_id()
        self.socket = socket_obj
        self.address = address
        self.connected_at = time.time()
        self.last_seen = time.time()
        self.is_active = True
        self.is_authenticated = False
        
        # Informations système du client
        self.system_info = {}
        self.current_directory = ""
        self.username = ""
        self.hostname = ""
        self.platform = ""
        
        # État de la session
        self.pending_commands = []
        self.lock = threading.Lock()
        
        logger.info(f"Nouvelle session créée: {self.id} depuis {address}")
    
    def _generate_session_id(self) -> str:
        """Génère un ID unique pour la session"""
        return f"agent_{str(uuid.uuid4())[:8]}"
    
    def send_message(self, message: dict) -> bool:
        """Envoie un message au client"""
        try:
            with self.lock:
                if not self.is_active:
                    return False
                
                encoded_message = Protocol.encode_message(message)
                self.socket.send(encoded_message)
                return True
                
        except Exception as e:
            logger.error(f"Erreur lors de l'envoi à {self.id}: {e}")
            self.mark_as_inactive()
            return False
    
    def mark_as_authenticated(self):
        """Marque la session comme authentifiée"""
        self.is_authenticated = True
        self.last_seen = time.time()
        logger.info(f"Session {self.id} authentifiée")
    
    def mark_as_inactive(self):
        """Marque la session comme inactive"""
        self.is_active = False
        logger.info(f"Session {self.id} marquée comme inactive")
    
    def update_last_seen(self):
        """Met à jour le timestamp de dernière activité"""
        self.last_seen = time.time()
    
    def get_info_summary(self) -> str:
        """Retourne un résumé des informations de la session"""
        uptime = int(time.time() - self.connected_at)
        last_seen_ago = int(time.time() - self.last_seen)
        
        return (
            f"ID: {self.id}\n"
            f"Address: {self.address[0]}:{self.address[1]}\n"
            f"Platform: {self.system_info.get('platform', 'Unknown')}\n"
            f"Username: {self.system_info.get('username', 'Unknown')}\n"
            f"Hostname: {self.system_info.get('hostname', 'Unknown')}\n"
            f"Connected: {uptime}s ago\n"
            f"Last Seen: {last_seen_ago}s ago\n"
            f"Status: {'Active' if self.is_active else 'Inactive'}"
        )
    
    def close(self):
        """Ferme la session proprement"""
        try:
            if self.socket:
                self.socket.close()
        except:
            pass
        
        self.is_active = False
        logger.info(f"Session {self.id} fermée")

class SessionManager:
    """Gestionnaire des sessions clients connectées"""
    
    def __init__(self):
        self.sessions: Dict[str, ClientSession] = {}
        self.current_session: Optional[str] = None
        self.lock = threading.RLock()
        
        # Statistiques
        self.total_sessions_created = 0
        self.start_time = time.time()
        
        logger.info("SessionManager initialisé")
    
    def create_session(self, socket_obj: socket.socket, address: Tuple[str, int]) -> ClientSession:
        """Crée une nouvelle session client"""
        session = ClientSession(socket_obj, address)
        
        with self.lock:
            self.sessions[session.id] = session
            self.total_sessions_created += 1
            
            # Si c'est la première session, la sélectionner automatiquement
            if len(self.sessions) == 1:
                self.current_session = session.id
        
        logger.info(f"Session créée: {session.id} - Total actif: {len(self.sessions)}")
        return session
    
    def get_session(self, session_id: str) -> Optional[ClientSession]:
        """Récupère une session par son ID"""
        with self.lock:
            return self.sessions.get(session_id)
    
    def get_current_session(self) -> Optional[ClientSession]:
        """Récupère la session actuellement sélectionnée"""
        if self.current_session:
            return self.get_session(self.current_session)
        return None
    
    def set_current_session(self, session_id: str) -> bool:
        """Définit la session courante"""
        with self.lock:
            if session_id in self.sessions and self.sessions[session_id].is_active:
                self.current_session = session_id
                logger.info(f"Session courante définie: {session_id}")
                return True
            return False
    
    def remove_session(self, session_id: str):
        """Supprime une session"""
        with self.lock:
            if session_id in self.sessions:
                session = self.sessions[session_id]
                session.close()
                del self.sessions[session_id]
                
                # Si c'est la session courante, la désélectionner
                if self.current_session == session_id:
                    self.current_session = None
                    # Sélectionner automatiquement une autre session active
                    active_sessions = self.get_active_sessions()
                    if active_sessions:
                        self.current_session = active_sessions[0].id
                
                logger.info(f"Session supprimée: {session_id}")
    
    def get_active_sessions(self) -> List[ClientSession]:
        """Retourne la liste des sessions actives"""
        with self.lock:
            return [
                session for session in self.sessions.values() 
                if session.is_active and session.is_authenticated
            ]
    
    def get_all_sessions(self) -> List[ClientSession]:
        """Retourne toutes les sessions"""
        with self.lock:
            return list(self.sessions.values())
    
    def get_session_count(self) -> int:
        """Retourne le nombre de sessions actives"""
        return len(self.get_active_sessions())
    
    def cleanup_inactive_sessions(self, timeout: int = 300):
        """Nettoie les sessions inactives (timeout en secondes)"""
        current_time = time.time()
        to_remove = []
        
        with self.lock:
            for session_id, session in self.sessions.items():
                if (current_time - session.last_seen) > timeout:
                    to_remove.append(session_id)
                    logger.info(f"Session {session_id} expirée (timeout: {timeout}s)")
        
        # Suppression des sessions expirées
        for session_id in to_remove:
            self.remove_session(session_id)
        
        return len(to_remove)
    
    def broadcast_message(self, message: dict, exclude_session: str = None):
        """Diffuse un message à toutes les sessions actives"""
        active_sessions = self.get_active_sessions()
        sent_count = 0
        
        for session in active_sessions:
            if exclude_session and session.id == exclude_session:
                continue
                
            if session.send_message(message):
                sent_count += 1
        
        logger.info(f"Message diffusé à {sent_count} sessions")
        return sent_count
    
    def get_statistics(self) -> Dict:
        """Retourne les statistiques du gestionnaire"""
        active_count = len(self.get_active_sessions())
        total_count = len(self.sessions)
        uptime = int(time.time() - self.start_time)
        
        return {
            'active_sessions': active_count,
            'total_sessions': total_count,
            'total_created': self.total_sessions_created,
            'uptime_seconds': uptime,
            'current_session': self.current_session
        }
    
    def list_sessions_formatted(self) -> str:
        """Retourne une liste formatée des sessions"""
        sessions = self.get_active_sessions()
        
        if not sessions:
            return "Aucune session active"
        
        output = f"Sessions actives ({len(sessions)}):\n"
        output += "-" * 60 + "\n"
        
        for i, session in enumerate(sessions, 1):
            marker = " -> " if session.id == self.current_session else "    "
            platform = session.system_info.get('platform', 'Unknown')[:15]
            username = session.system_info.get('username', 'Unknown')[:15]
            uptime = int(time.time() - session.connected_at)
            
            output += (
                f"{marker}{i:2d}. {session.id} - "
                f"{session.address[0]:15s} - "
                f"{platform:15s} - "
                f"{username:15s} - "
                f"{uptime:4d}s\n"
            )
        
        return output
    
    def close_all_sessions(self):
        """Ferme toutes les sessions"""
        with self.lock:
            session_ids = list(self.sessions.keys())
            
        for session_id in session_ids:
            self.remove_session(session_id)
        
        logger.info("Toutes les sessions ont été fermées")