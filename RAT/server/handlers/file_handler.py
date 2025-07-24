"""
File Handler - Gestionnaire des opérations de fichiers côté serveur
Gestion des téléchargements, uploads et opérations sur fichiers
"""

import os
import base64
import hashlib
import mimetypes
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, Optional
import logging

from server.utils.config import ServerConfig
from shared.protocol import Protocol, MessageType
from shared.exceptions import FileOperationException

logger = logging.getLogger(__name__)

class FileHandler:
    """Gestionnaire des opérations de fichiers du serveur"""
    
    def __init__(self, config: ServerConfig):
        self.config = config
        
        # Statistiques
        self.files_received = 0
        self.files_sent = 0
        self.bytes_received = 0
        self.bytes_sent = 0
        
        # Création des répertoires
        self._ensure_directories()
        
        logger.info("FileHandler initialisé")
    
    def _ensure_directories(self):
        """S'assure que tous les répertoires nécessaires existent"""
        directories = [
            self.config.DOWNLOADS_DIR,
            self.config.UPLOADS_DIR
        ]
        
        for directory in directories:
            try:
                os.makedirs(directory, exist_ok=True)
            except Exception as e:
                logger.error(f"Impossible de créer le répertoire {directory}: {e}")
    
    def handle_file_download(self, session, file_data: Dict[str, Any]) -> bool:
        """
        Traite la réception d'un fichier téléchargé depuis un agent
        
        Args:
            session: Session de l'agent
            file_data: Données du fichier reçu
        
        Returns:
            bool: True si succès
        """
        try:
            filename = file_data.get('filename', 'unknown_file')
            file_content = file_data.get('file_data', '')
            file_size = file_data.get('file_size', 0)
            file_hash = file_data.get('file_hash', '')
            original_path = file_data.get('file_path', '')
            
            # Validation de base
            if not file_content:
                logger.error("Données de fichier manquantes")
                return False
            
            # Décodage base64
            try:
                decoded_data = base64.b64decode(file_content)
            except Exception as e:
                logger.error(f"Erreur décodage base64: {e}")
                return False
            
            # Vérification de la taille
            if len(decoded_data) != file_size:
                logger.warning(f"Taille incohérente: attendu {file_size}, reçu {len(decoded_data)}")
            
            # Vérification du hash si fourni
            if file_hash:
                actual_hash = hashlib.sha256(decoded_data).hexdigest()
                if actual_hash != file_hash:
                    logger.error("Hash du fichier incorrect - possible corruption")
                    return False
            
            # Génération du nom de fichier sécurisé
            safe_filename = self._generate_safe_filename(session.id, filename)
            file_path = os.path.join(self.config.DOWNLOADS_DIR, safe_filename)
            
            # Sauvegarde du fichier
            try:
                with open(file_path, 'wb') as f:
                    f.write(decoded_data)
                
                # Vérification de l'écriture
                if os.path.exists(file_path) and os.path.getsize(file_path) == len(decoded_data):
                    # Sauvegarde des métadonnées
                    self._save_file_metadata(file_path, {
                        'session_id': session.id,
                        'agent_ip': session.address[0],
                        'original_filename': filename,
                        'original_path': original_path,
                        'download_time': datetime.now().isoformat(),
                        'file_size': len(decoded_data),
                        'file_hash': hashlib.sha256(decoded_data).hexdigest(),
                        'mime_type': mimetypes.guess_type(filename)[0]
                    })
                    
                    # Mise à jour des statistiques
                    self.files_received += 1
                    self.bytes_received += len(decoded_data)
                    
                    logger.info(f"Fichier reçu: {filename} ({len(decoded_data)} bytes) de {session.id}")
                    print(f"[+] Fichier téléchargé: {safe_filename}")
                    
                    return True
                else:
                    logger.error("Échec de la vérification après écriture")
                    return False
                    
            except Exception as e:
                logger.error(f"Erreur lors de l'écriture du fichier: {e}")
                return False
                
        except Exception as e:
            logger.error(f"Erreur traitement download: {e}")
            return False
    
    def upload_file_to_agent(self, session, local_file: str, remote_path: str) -> Optional[str]:
        """
        Upload un fichier vers un agent
        
        Args:
            session: Session de l'agent
            local_file: Chemin du fichier local
            remote_path: Chemin de destination sur l'agent
        
        Returns:
            str: Message de résultat
        """
        try:
            # Vérification de l'existence du fichier local
            if not os.path.exists(local_file):
                return f"Fichier local non trouvé: {local_file}"
            
            if not os.path.isfile(local_file):
                return f"Le chemin ne pointe pas vers un fichier: {local_file}"
            
            # Vérification de la taille
            file_size = os.path.getsize(local_file)
            if file_size > self.config.MAX_FILE_SIZE:
                return f"Fichier trop volumineux: {file_size} bytes (max: {self.config.MAX_FILE_SIZE})"
            
            # Lecture du fichier
            try:
                with open(local_file, 'rb') as f:
                    file_data = f.read()
            except Exception as e:
                return f"Erreur lecture fichier: {e}"
            
            # Encodage base64
            encoded_data = base64.b64encode(file_data).decode('utf-8')
            
            # Calcul du hash
            file_hash = hashlib.sha256(file_data).hexdigest()
            
            # Préparation du message d'upload
            upload_message = Protocol.create_message(
                MessageType.COMMAND,
                {
                    'command': 'upload',
                    'args': {
                        'file_data': encoded_data,
                        'destination_path': remote_path,
                        'filename': os.path.basename(local_file),
                        'file_size': file_size,
                        'file_hash': file_hash,
                        'upload_time': datetime.now().isoformat()
                    }
                }
            )
            
            # Envoi du message
            if session.send_message(upload_message):
                # Mise à jour des statistiques
                self.files_sent += 1
                self.bytes_sent += file_size
                
                logger.info(f"Fichier envoyé: {local_file} ({file_size} bytes) vers {session.id}")
                return f"Upload démarré: {os.path.basename(local_file)} -> {remote_path}"
            else:
                return "Erreur lors de l'envoi du fichier"
                
        except Exception as e:
            logger.error(f"Erreur upload fichier: {e}")
            return f"Erreur lors de l'upload: {e}"
    
    def list_downloaded_files(self, session_id: str = None) -> Dict[str, Any]:
        """
        Liste les fichiers téléchargés
        
        Args:
            session_id: ID de session (None = tous)
        
        Returns:
            Dict avec la liste des fichiers
        """
        try:
            files = []
            
            if not os.path.exists(self.config.DOWNLOADS_DIR):
                return {'files': [], 'count': 0}
            
            for filename in os.listdir(self.config.DOWNLOADS_DIR):
                file_path = os.path.join(self.config.DOWNLOADS_DIR, filename)
                
                if not os.path.isfile(file_path):
                    continue
                
                # Lecture des métadonnées si elles existent
                metadata = self._load_file_metadata(file_path)
                
                # Filtrage par session si demandé
                if session_id and metadata.get('session_id') != session_id:
                    continue
                
                file_info = {
                    'filename': filename,
                    'size': os.path.getsize(file_path),
                    'modified': datetime.fromtimestamp(os.path.getmtime(file_path)).isoformat(),
                    'path': file_path
                }
                
                # Ajout des métadonnées si disponibles
                if metadata:
                    file_info.update(metadata)
                
                files.append(file_info)
            
            # Tri par date de modification (plus récent en premier)
            files.sort(key=lambda x: x.get('modified', ''), reverse=True)
            
            return {
                'files': files,
                'count': len(files),
                'total_size': sum(f['size'] for f in files)
            }
            
        except Exception as e:
            logger.error(f"Erreur listing fichiers: {e}")
            return {'files': [], 'count': 0, 'error': str(e)}
    
    def delete_downloaded_file(self, filename: str) -> bool:
        """
        Supprime un fichier téléchargé
        
        Args:
            filename: Nom du fichier à supprimer
        
        Returns:
            bool: True si succès
        """
        try:
            file_path = os.path.join(self.config.DOWNLOADS_DIR, filename)
            
            if not os.path.exists(file_path):
                logger.warning(f"Fichier non trouvé: {filename}")
                return False
            
            # Suppression du fichier
            os.unlink(file_path)
            
            # Suppression des métadonnées
            metadata_path = file_path + '.meta'
            if os.path.exists(metadata_path):
                os.unlink(metadata_path)
            
            logger.info(f"Fichier supprimé: {filename}")
            return True
            
        except Exception as e:
            logger.error(f"Erreur suppression fichier {filename}: {e}")
            return False
    
    def get_file_stats(self) -> Dict[str, Any]:
        """Retourne les statistiques des fichiers"""
        return {
            'files_received': self.files_received,
            'files_sent': self.files_sent,
            'bytes_received': self.bytes_received,
            'bytes_sent': self.bytes_sent,
            'downloads_dir': self.config.DOWNLOADS_DIR,
            'uploads_dir': self.config.UPLOADS_DIR
        }
    
    def _generate_safe_filename(self, session_id: str, original_filename: str) -> str:
        """
        Génère un nom de fichier sécurisé avec timestamp et session
        
        Args:
            session_id: ID de la session
            original_filename: Nom de fichier original
        
        Returns:
            str: Nom de fichier sécurisé
        """
        # Nettoyage du nom de fichier original
        safe_name = "".join(c for c in original_filename if c.isalnum() or c in "._- ")
        safe_name = safe_name.strip()
        
        if not safe_name:
            safe_name = "unknown_file"
        
        # Ajout du timestamp et de l'ID de session
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        
        # Séparation du nom et de l'extension
        name, ext = os.path.splitext(safe_name)
        
        return f"{timestamp}_{session_id}_{name}{ext}"
    
    def _save_file_metadata(self, file_path: str, metadata: Dict[str, Any]):
        """
        Sauvegarde les métadonnées d'un fichier
        
        Args:
            file_path: Chemin du fichier
            metadata: Métadonnées à sauvegarder
        """
        try:
            import json
            
            metadata_path = file_path + '.meta'
            with open(metadata_path, 'w', encoding='utf-8') as f:
                json.dump(metadata, f, indent=2, ensure_ascii=False)
                
        except Exception as e:
            logger.warning(f"Impossible de sauvegarder les métadonnées: {e}")
    
    def _load_file_metadata(self, file_path: str) -> Dict[str, Any]:
        """
        Charge les métadonnées d'un fichier
        
        Args:
            file_path: Chemin du fichier
        
        Returns:
            Dict: Métadonnées ou dict vide
        """
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
    
    def cleanup_old_files(self, max_age_days: int = 30) -> int:
        """
        Nettoie les anciens fichiers téléchargés
        
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
            
            if not os.path.exists(self.config.DOWNLOADS_DIR):
                return 0
            
            for filename in os.listdir(self.config.DOWNLOADS_DIR):
                file_path = os.path.join(self.config.DOWNLOADS_DIR, filename)
                
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
                        logger.info(f"Ancien fichier supprimé: {filename}")
                        
                    except Exception as e:
                        logger.error(f"Erreur suppression {filename}: {e}")
            
            return deleted_count
            
        except Exception as e:
            logger.error(f"Erreur nettoyage fichiers: {e}")
            return 0