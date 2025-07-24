"""
File Handler - Gestionnaire des opérations de fichiers côté serveur
Gestion des téléchargements, uploads et transferts de fichiers
"""

import os
import base64
import hashlib
from pathlib import Path
from datetime import datetime
from typing import Dict, Any, Optional
import logging

from server.utils.config import ServerConfig
from shared.protocol import Protocol, MessageType
from shared.exceptions import FileOperationError
from shared.helpers import sanitize_filename, get_file_hash, format_bytes

logger = logging.getLogger(__name__)

class FileHandler:
    """Gestionnaire des opérations de fichiers pour le serveur"""
    
    def __init__(self, config: ServerConfig):
        self.config = config
        self.downloads_dir = Path(config.DOWNLOADS_DIR)
        self.uploads_dir = Path(config.UPLOADS_DIR)
        
        # Création des répertoires si nécessaire
        self.downloads_dir.mkdir(parents=True, exist_ok=True)
        self.uploads_dir.mkdir(parents=True, exist_ok=True)
        
        # Statistiques
        self.files_received = 0
        self.files_sent = 0
        self.bytes_transferred = 0
        
        logger.info("FileHandler initialisé")
    
    def handle_file_download(self, session, file_data: Dict[str, Any]) -> str:
        """
        Traite un fichier téléchargé depuis un agent
        
        Args:
            session: Session client
            file_data: Données du fichier reçu
            
        Returns:
            str: Message de résultat
        """
        try:
            # Extraction des informations du fichier
            filename = file_data.get('filename', 'unknown_file')
            encoded_data = file_data.get('file_data', '')
            file_size = file_data.get('file_size', 0)
            file_hash = file_data.get('file_hash', '')
            original_path = file_data.get('file_path', '')
            
            if not encoded_data:
                return "[!] Aucune donnée de fichier reçue"
            
            # Décodage des données
            try:
                file_content = base64.b64decode(encoded_data)
            except Exception as e:
                logger.error(f"Erreur décodage base64: {e}")
                return f"[!] Erreur de décodage: {e}"
            
            # Vérification de la taille
            if len(file_content) != file_size:
                logger.warning(f"Taille de fichier incohérente: attendu {file_size}, reçu {len(file_content)}")
            
            # Sanitisation du nom de fichier
            safe_filename = sanitize_filename(filename)
            
            # Création d'un nom unique pour éviter les collisions
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            session_prefix = session.id[:8]
            unique_filename = f"{session_prefix}_{timestamp}_{safe_filename}"
            
            # Chemin de destination
            dest_path = self.downloads_dir / unique_filename
            
            # Sauvegarde du fichier
            try:
                with open(dest_path, 'wb') as f:
                    f.write(file_content)
                
                # Vérification de l'intégrité si un hash est fourni
                if file_hash:
                    calculated_hash = get_file_hash(str(dest_path), 'sha256')
                    if calculated_hash != file_hash:
                        logger.warning(f"Hash de fichier incohérent pour {filename}")
                        return f"[!] Intégrité du fichier compromise: {filename}"
                
                # Mise à jour des statistiques
                self.files_received += 1
                self.bytes_transferred += len(file_content)
                
                # Création du fichier d'informations
                self._create_file_info(dest_path, {
                    'session_id': session.id,
                    'original_filename': filename,
                    'original_path': original_path,
                    'download_time': datetime.now().isoformat(),
                    'file_size': len(file_content),
                    'file_hash': calculated_hash or file_hash,
                    'client_info': session.system_info
                })
                
                logger.info(f"Fichier reçu: {filename} ({format_bytes(len(file_content))}) de {session.id}")
                
                return (
                    f"[+] Fichier téléchargé avec succès\\n"
                    f"    Nom: {filename}\\n"
                    f"    Taille: {format_bytes(len(file_content))}\\n"
                    f"    Sauvé sous: {unique_filename}\\n"
                    f"    Chemin: {dest_path}"
                )
                
            except PermissionError:
                return f"[!] Permissions insuffisantes pour écrire: {dest_path}"
            except OSError as e:
                return f"[!] Erreur système lors de l'écriture: {e}"
                
        except Exception as e:
            logger.error(f"Erreur dans handle_file_download: {e}")
            return f"[!] Erreur lors du traitement: {e}"
    
    def upload_file_to_agent(self, session, local_file: str, remote_path: str) -> str:
        """
        Upload un fichier vers un agent
        
        Args:
            session: Session client
            local_file: Chemin du fichier local
            remote_path: Chemin de destination sur l'agent
            
        Returns:
            str: Message de résultat
        """
        try:
            local_path = Path(local_file)
            
            # Vérifications de base
            if not local_path.exists():
                return f"[!] Fichier local non trouvé: {local_file}"
            
            if not local_path.is_file():
                return f"[!] Le chemin ne pointe pas vers un fichier: {local_file}"
            
            # Vérification de la taille
            file_size = local_path.stat().st_size
            if file_size > self.config.security.max_file_size:
                return f"[!] Fichier trop volumineux: {format_bytes(file_size)}"
            
            # Lecture du fichier
            try:
                with open(local_path, 'rb') as f:
                    file_content = f.read()
            except PermissionError:
                return f"[!] Permissions insuffisantes pour lire: {local_file}"
            except OSError as e:
                return f"[!] Erreur lors de la lecture: {e}"
            
            # Encodage base64
            encoded_content = base64.b64encode(file_content).decode('utf-8')
            
            # Calcul du hash pour vérification
            file_hash = hashlib.sha256(file_content).hexdigest()
            
            # Création du message d'upload
            upload_data = {
                'file_data': encoded_content,
                'destination_path': remote_path,
                'filename': local_path.name,
                'file_size': len(file_content),
                'file_hash': file_hash,
                'upload_time': datetime.now().isoformat()
            }
            
            upload_message = Protocol.create_message(
                MessageType.COMMAND,
                {'command': 'upload', 'args': upload_data}
            )
            
            # Envoi du message
            if session.send_message(upload_message):
                self.files_sent += 1
                self.bytes_transferred += len(file_content)
                
                logger.info(f"Fichier envoyé: {local_file} -> {remote_path} ({format_bytes(len(file_content))})")
                
                return (
                    f"[+] Upload initié\\n"
                    f"    Fichier local: {local_file}\\n"
                    f"    Destination: {remote_path}\\n"
                    f"    Taille: {format_bytes(len(file_content))}"
                )
            else:
                return "[!] Erreur lors de l'envoi du fichier"
                
        except Exception as e:
            logger.error(f"Erreur dans upload_file_to_agent: {e}")
            return f"[!] Erreur lors de l'upload: {e}"
    
    def _create_file_info(self, file_path: Path, metadata: Dict[str, Any]):
        """Crée un fichier d'informations pour un téléchargement"""
        try:
            info_file = file_path.with_suffix(file_path.suffix + '.info')
            
            with open(info_file, 'w', encoding='utf-8') as f:
                f.write("# File Download Information\n")
                f.write(f"# Generated on {datetime.now().isoformat()}\n\n")
                
                for key, value in metadata.items():
                    f.write(f"{key}: {value}\n")
                
        except Exception as e:
            logger.warning(f"Impossible de créer le fichier d'info: {e}")
    
    def list_downloaded_files(self, session_id: str = None) -> str:
        """
        Liste les fichiers téléchargés
        
        Args:
            session_id: ID de session pour filtrer (optionnel)
            
        Returns:
            str: Liste formatée des fichiers
        """
        try:
            files = []
            total_size = 0
            
            for file_path in self.downloads_dir.glob('*'):
                if file_path.is_file() and not file_path.name.endswith('.info'):
                    # Filtrage par session si demandé
                    if session_id and not file_path.name.startswith(session_id[:8]):
                        continue
                    
                    stat = file_path.stat()
                    files.append({
                        'name': file_path.name,
                        'size': stat.st_size,
                        'modified': datetime.fromtimestamp(stat.st_mtime),
                        'path': str(file_path)
                    })
                    total_size += stat.st_size
            
            if not files:
                return "Aucun fichier téléchargé"
            
            # Tri par date de modification (plus récent en premier)
            files.sort(key=lambda x: x['modified'], reverse=True)
            
            # Formatage de la liste
            output = f"Fichiers téléchargés ({len(files)} fichiers, {format_bytes(total_size)}):\n"
            output += "-" * 80 + "\n"
            
            for i, file_info in enumerate(files, 1):
                output += (
                    f"{i:3d}. {file_info['name'][:40]:40s} "
                    f"{format_bytes(file_info['size']):>10s} "
                    f"{file_info['modified'].strftime('%Y-%m-%d %H:%M')}\n"
                )
            
            return output
            
        except Exception as e:
            logger.error(f"Erreur dans list_downloaded_files: {e}")
            return f"[!] Erreur lors du listage: {e}"
    
    def delete_downloaded_file(self, filename: str) -> str:
        """
        Supprime un fichier téléchargé
        
        Args:
            filename: Nom du fichier à supprimer
            
        Returns:
            str: Message de résultat
        """
        try:
            file_path = self.downloads_dir / filename
            info_path = file_path.with_suffix(file_path.suffix + '.info')
            
            if not file_path.exists():
                return f"[!] Fichier non trouvé: {filename}"
            
            # Suppression du fichier principal
            file_size = file_path.stat().st_size
            file_path.unlink()
            
            # Suppression du fichier d'info s'il existe
            if info_path.exists():
                info_path.unlink()
            
            logger.info(f"Fichier supprimé: {filename}")
            
            return f"[+] Fichier supprimé: {filename} ({format_bytes(file_size)})"
            
        except Exception as e:
            logger.error(f"Erreur dans delete_downloaded_file: {e}")
            return f"[!] Erreur lors de la suppression: {e}"
    
    def get_file_info(self, filename: str) -> str:
        """
        Affiche les informations détaillées d'un fichier
        
        Args:
            filename: Nom du fichier
            
        Returns:
            str: Informations formatées
        """
        try:
            file_path = self.downloads_dir / filename
            info_path = file_path.with_suffix(file_path.suffix + '.info')
            
            if not file_path.exists():
                return f"[!] Fichier non trouvé: {filename}"
            
            # Informations de base
            stat = file_path.stat()
            file_hash = get_file_hash(str(file_path), 'sha256')
            
            output = f"Informations pour: {filename}\n"
            output += "=" * 50 + "\n"
            output += f"Taille: {format_bytes(stat.st_size)}\n"
            output += f"Modifié: {datetime.fromtimestamp(stat.st_mtime).isoformat()}\n"
            output += f"SHA256: {file_hash}\n"
            output += f"Chemin: {file_path}\n"
            
            # Informations additionnelles depuis le fichier .info
            if info_path.exists():
                output += "\nInformations de téléchargement:\n"
                try:
                    with open(info_path, 'r', encoding='utf-8') as f:
                        for line in f:
                            if line.startswith('#') or not line.strip():
                                continue
                            output += f"  {line.strip()}\n"
                except Exception as e:
                    output += f"  Erreur lecture info: {e}\n"
            
            return output
            
        except Exception as e:
            logger.error(f"Erreur dans get_file_info: {e}")
            return f"[!] Erreur lors de la récupération des infos: {e}"
    
    def cleanup_old_files(self, days: int = 30) -> str:
        """
        Nettoie les anciens fichiers téléchargés
        
        Args:
            days: Nombre de jours de rétention
            
        Returns:
            str: Résultat du nettoyage
        """
        try:
            cutoff_time = datetime.now().timestamp() - (days * 24 * 3600)
            cleaned_files = 0
            freed_space = 0
            
            for file_path in self.downloads_dir.glob('*'):
                if file_path.is_file():
                    stat = file_path.stat()
                    if stat.st_mtime < cutoff_time:
                        file_size = stat.st_size
                        
                        # Suppression du fichier principal
                        file_path.unlink()
                        
                        # Suppression du fichier .info associé
                        info_path = file_path.with_suffix(file_path.suffix + '.info')
                        if info_path.exists():
                            info_path.unlink()
                        
                        cleaned_files += 1
                        freed_space += file_size
                        
                        logger.info(f"Fichier ancien supprimé: {file_path.name}")
            
            if cleaned_files > 0:
                return (
                    f"[+] Nettoyage terminé\\n"
                    f"    Fichiers supprimés: {cleaned_files}\\n"
                    f"    Espace libéré: {format_bytes(freed_space)}"
                )
            else:
                return f"[*] Aucun fichier ancien trouvé (>{days} jours)"
                
        except Exception as e:
            logger.error(f"Erreur dans cleanup_old_files: {e}")
            return f"[!] Erreur lors du nettoyage: {e}"
    
    def get_handler_stats(self) -> Dict[str, Any]:
        """Retourne les statistiques du gestionnaire de fichiers"""
        try:
            # Calcul de l'espace utilisé
            total_size = 0
            file_count = 0
            
            for file_path in self.downloads_dir.glob('*'):
                if file_path.is_file() and not file_path.name.endswith('.info'):
                    total_size += file_path.stat().st_size
                    file_count += 1
            
            return {
                'files_received': self.files_received,
                'files_sent': self.files_sent,
                'bytes_transferred': self.bytes_transferred,
                'downloads_directory': str(self.downloads_dir),
                'uploads_directory': str(self.uploads_dir),
                'current_file_count': file_count,
                'current_total_size': total_size,
                'current_total_size_formatted': format_bytes(total_size)
            }
            
        except Exception as e:
            logger.error(f"Erreur dans get_handler_stats: {e}")
            return {'error': str(e)}