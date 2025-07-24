"""
File Operations Module - Opérations sur les fichiers
Gestion des téléchargements, uploads et recherches de fichiers
Inspiré des fonctionnalités de transfert des RATs modernes
"""

import os
import hashlib
import base64
import mimetypes
from pathlib import Path
from datetime import datetime
from typing import Dict, Any, List, Optional, Tuple
import logging

logger = logging.getLogger(__name__)

class FileOperations:
    """Module de gestion des opérations sur les fichiers"""
    
    def __init__(self):
        # Limitations de sécurité
        self.MAX_FILE_SIZE = 100 * 1024 * 1024  # 100MB
        self.MAX_SEARCH_RESULTS = 100
        self.MAX_SEARCH_DEPTH = 5
        self.CHUNK_SIZE = 64 * 1024  # 64KB par chunk
        
        # Extensions autorisées pour le téléchargement
        self.ALLOWED_EXTENSIONS = {
            '.txt', '.log', '.cfg', '.conf', '.ini', '.xml', '.json',
            '.jpg', '.jpeg', '.png', '.gif', '.bmp',
            '.pdf', '.doc', '.docx', '.xls', '.xlsx',
            '.zip', '.rar', '.7z', '.tar', '.gz'
        }
        
        # Répertoires sensibles à éviter
        self.SENSITIVE_DIRS = {
            'windows': [
                'windows/system32', 'windows/syswow64', 'program files',
                'program files (x86)', 'programdata', 'users/all users'
            ],
            'linux': [
                '/etc', '/usr/bin', '/usr/sbin', '/bin', '/sbin',
                '/root', '/var/log', '/proc', '/sys'
            ],
            'darwin': [
                '/system', '/usr/bin', '/usr/sbin', '/bin', '/sbin',
                '/library/system', '/var/log'
            ]
        }
        
        # Statistiques
        self.files_downloaded = 0
        self.files_uploaded = 0
        self.bytes_transferred = 0
        self.searches_performed = 0
    
    def download_file(self, file_path: str) -> Dict[str, Any]:
        """
        Télécharge un fichier vers le serveur
        
        Args:
            file_path: Chemin du fichier à télécharger
        
        Returns:
            Dict avec les informations du fichier et données encodées
        """
        try:
            if not file_path or not file_path.strip():
                return {
                    'status': 'error',
                    'output': 'Chemin de fichier non spécifié'
                }
            
            file_path = file_path.strip()
            
            # Vérifications de sécurité
            security_check = self._security_check_path(file_path)
            if not security_check['allowed']:
                return {
                    'status': 'error',
                    'output': f'Accès refusé: {security_check["reason"]}'
                }
            
            # Vérification de l'existence du fichier
            if not os.path.exists(file_path):
                return {
                    'status': 'error',
                    'output': f'Fichier non trouvé: {file_path}'
                }
            
            if not os.path.isfile(file_path):
                return {
                    'status': 'error',
                    'output': f'Le chemin ne pointe pas vers un fichier: {file_path}'
                }
            
            # Vérification de la taille
            file_size = os.path.getsize(file_path)
            if file_size > self.MAX_FILE_SIZE:
                return {
                    'status': 'error',
                    'output': f'Fichier trop volumineux: {file_size} bytes (max: {self.MAX_FILE_SIZE})'
                }
            
            # Vérification des permissions
            if not os.access(file_path, os.R_OK):
                return {
                    'status': 'error',
                    'output': f'Permissions insuffisantes pour lire: {file_path}'
                }
            
            # Lecture et encodage du fichier
            try:
                with open(file_path, 'rb') as f:
                    file_data = f.read()
                
                # Encodage base64
                encoded_data = base64.b64encode(file_data).decode('utf-8')
                
                # Calcul du hash pour vérification d'intégrité
                file_hash = hashlib.sha256(file_data).hexdigest()
                
                # Informations du fichier
                file_info = self._get_file_info(file_path)
                
                # Mise à jour des statistiques
                self.files_downloaded += 1
                self.bytes_transferred += file_size
                
                logger.info(f"Fichier téléchargé: {file_path} ({file_size} bytes)")
                
                return {
                    'status': 'success',
                    'output': f'Fichier téléchargé: {os.path.basename(file_path)} ({file_size} bytes)',
                    'file_data': encoded_data,
                    'filename': os.path.basename(file_path),
                    'file_path': file_path,
                    'file_size': file_size,
                    'file_hash': file_hash,
                    'file_info': file_info,
                    'timestamp': datetime.now().isoformat()
                }
                
            except PermissionError:
                return {
                    'status': 'error',
                    'output': f'Accès refusé lors de la lecture: {file_path}'
                }
            except IOError as e:
                return {
                    'status': 'error',
                    'output': f'Erreur I/O lors de la lecture: {str(e)}'
                }
                
        except Exception as e:
            logger.error(f"Erreur téléchargement fichier: {e}")
            return {
                'status': 'error',
                'output': f'Erreur lors du téléchargement: {str(e)}'
            }
    
    def upload_file(self, file_data: str, destination_path: str, filename: str = None) -> Dict[str, Any]:
        """
        Reçoit un fichier du serveur et l'enregistre
        
        Args:
            file_data: Données du fichier encodées en base64
            destination_path: Chemin de destination
            filename: Nom du fichier (optionnel)
        
        Returns:
            Dict avec le statut de l'opération
        """
        try:
            if not file_data:
                return {
                    'status': 'error',
                    'output': 'Données de fichier manquantes'
                }
            
            if not destination_path:
                return {
                    'status': 'error',
                    'output': 'Chemin de destination manquant'
                }
            
            # Décodage des données
            try:
                decoded_data = base64.b64decode(file_data)
            except Exception as e:
                return {
                    'status': 'error',
                    'output': f'Erreur de décodage base64: {str(e)}'
                }
            
            # Vérification de la taille
            if len(decoded_data) > self.MAX_FILE_SIZE:
                return {
                    'status': 'error',
                    'output': f'Fichier trop volumineux: {len(decoded_data)} bytes'
                }
            
            # Préparation du chemin de destination
            if filename:
                full_path = os.path.join(destination_path, filename)
            else:
                full_path = destination_path
            
            # Vérifications de sécurité
            security_check = self._security_check_path(full_path, for_write=True)
            if not security_check['allowed']:
                return {
                    'status': 'error',
                    'output': f'Écriture refusée: {security_check["reason"]}'
                }
            
            # Création du répertoire si nécessaire
            dir_path = os.path.dirname(full_path)
            if dir_path and not os.path.exists(dir_path):
                try:
                    os.makedirs(dir_path, exist_ok=True)
                except Exception as e:
                    return {
                        'status': 'error',
                        'output': f'Impossible de créer le répertoire: {str(e)}'
                    }
            
            # Vérification des permissions d'écriture
            if not os.access(dir_path or '.', os.W_OK):
                return {
                    'status': 'error',
                    'output': f'Permissions d\'écriture insuffisantes: {dir_path}'
                }
            
            # Écriture du fichier
            try:
                with open(full_path, 'wb') as f:
                    f.write(decoded_data)
                
                # Vérification de l'écriture
                if os.path.exists(full_path) and os.path.getsize(full_path) == len(decoded_data):
                    # Mise à jour des statistiques
                    self.files_uploaded += 1
                    self.bytes_transferred += len(decoded_data)
                    
                    logger.info(f"Fichier uploadé: {full_path} ({len(decoded_data)} bytes)")
                    
                    return {
                        'status': 'success',
                        'output': f'Fichier uploadé: {os.path.basename(full_path)} ({len(decoded_data)} bytes)',
                        'file_path': full_path,
                        'file_size': len(decoded_data),
                        'timestamp': datetime.now().isoformat()
                    }
                else:
                    return {
                        'status': 'error',
                        'output': 'Échec de la vérification après écriture'
                    }
                    
            except PermissionError:
                return {
                    'status': 'error',
                    'output': f'Accès refusé lors de l\'écriture: {full_path}'
                }
            except IOError as e:
                return {
                    'status': 'error',
                    'output': f'Erreur I/O lors de l\'écriture: {str(e)}'
                }
                
        except Exception as e:
            logger.error(f"Erreur upload fichier: {e}")
            return {
                'status': 'error',
                'output': f'Erreur lors de l\'upload: {str(e)}'
            }
    
    def search_file(self, pattern: str, search_path: str = None, case_sensitive: bool = False) -> Dict[str, Any]:
        """
        Recherche des fichiers selon un pattern
        
        Args:
            pattern: Pattern de recherche
            search_path: Chemin de recherche (défaut: répertoire courant)
            case_sensitive: Recherche sensible à la casse
        
        Returns:
            Dict avec la liste des fichiers trouvés
        """
        try:
            if not pattern or not pattern.strip():
                return {
                    'status': 'error',
                    'output': 'Pattern de recherche manquant'
                }
            
            pattern = pattern.strip()
            
            # Chemin de recherche par défaut
            if not search_path:
                search_path = os.getcwd()
            
            if not os.path.exists(search_path):
                return {
                    'status': 'error',
                    'output': f'Chemin de recherche invalide: {search_path}'
                }
            
            # Vérifications de sécurité
            security_check = self._security_check_path(search_path)
            if not security_check['allowed']:
                return {
                    'status': 'error',
                    'output': f'Recherche refusée: {security_check["reason"]}'
                }
            
            # Préparation du pattern
            if not case_sensitive:
                pattern = pattern.lower()
            
            found_files = []
            search_count = 0
            
            # Recherche récursive avec limitations
            for root, dirs, files in os.walk(search_path):
                # Limitation de la profondeur
                depth = root.replace(search_path, '').count(os.sep)
                if depth >= self.MAX_SEARCH_DEPTH:
                    dirs[:] = []  # Ne pas descendre plus profond
                    continue
                
                # Filtrage des répertoires sensibles
                dirs[:] = [d for d in dirs if not self._is_sensitive_dir(os.path.join(root, d))]
                
                # Recherche dans les fichiers
                for filename in files:
                    search_count += 1
                    
                    # Limitation du nombre de vérifications
                    if search_count > 10000:  # Max 10k fichiers vérifiés
                        break
                    
                    # Application du pattern
                    search_filename = filename if case_sensitive else filename.lower()
                    
                    if pattern in search_filename:
                        file_path = os.path.join(root, filename)
                        
                        try:
                            # Informations du fichier
                            file_info = self._get_file_info(file_path)
                            file_info['path'] = file_path
                            found_files.append(file_info)
                            
                            # Limitation du nombre de résultats
                            if len(found_files) >= self.MAX_SEARCH_RESULTS:
                                break
                                
                        except Exception:
                            # Ignorer les fichiers inaccessibles
                            continue
                
                if len(found_files) >= self.MAX_SEARCH_RESULTS:
                    break
            
            # Mise à jour des statistiques
            self.searches_performed += 1
            
            # Formatage du résultat
            if found_files:
                output = f"Recherche terminée: {len(found_files)} fichier(s) trouvé(s) pour '{pattern}'"
                if len(found_files) >= self.MAX_SEARCH_RESULTS:
                    output += f" (limité à {self.MAX_SEARCH_RESULTS} résultats)"
                
                # Tri par nom
                found_files.sort(key=lambda x: x.get('name', ''))
                
                return {
                    'status': 'success',
                    'output': output,
                    'pattern': pattern,
                    'search_path': search_path,
                    'results_count': len(found_files),
                    'files': found_files,
                    'limited': len(found_files) >= self.MAX_SEARCH_RESULTS
                }
            else:
                return {
                    'status': 'info',
                    'output': f"Aucun fichier trouvé pour le pattern '{pattern}' dans {search_path}",
                    'pattern': pattern,
                    'search_path': search_path,
                    'results_count': 0,
                    'files': []
                }
                
        except Exception as e:
            logger.error(f"Erreur recherche fichier: {e}")
            return {
                'status': 'error',
                'output': f'Erreur lors de la recherche: {str(e)}'
            }
    
    def list_directory(self, dir_path: str = None) -> Dict[str, Any]:
        """
        Liste le contenu d'un répertoire
        
        Args:
            dir_path: Chemin du répertoire (défaut: répertoire courant)
        
        Returns:
            Dict avec la liste des fichiers et dossiers
        """
        try:
            if not dir_path:
                dir_path = os.getcwd()
            
            if not os.path.exists(dir_path):
                return {
                    'status': 'error',
                    'output': f'Répertoire non trouvé: {dir_path}'
                }
            
            if not os.path.isdir(dir_path):
                return {
                    'status': 'error',
                    'output': f'Le chemin n\'est pas un répertoire: {dir_path}'
                }
            
            # Vérifications de sécurité
            security_check = self._security_check_path(dir_path)
            if not security_check['allowed']:
                return {
                    'status': 'error',
                    'output': f'Accès refusé: {security_check["reason"]}'
                }
            
            items = []
            
            try:
                # Listing du répertoire
                for item_name in os.listdir(dir_path):
                    item_path = os.path.join(dir_path, item_name)
                    
                    try:
                        item_info = self._get_file_info(item_path)
                        items.append(item_info)
                    except Exception:
                        # Ignorer les éléments inaccessibles
                        continue
                
                # Tri: dossiers d'abord, puis fichiers par nom
                items.sort(key=lambda x: (x['type'] != 'directory', x['name'].lower()))
                
                return {
                    'status': 'success',
                    'output': f'Répertoire listé: {dir_path} ({len(items)} éléments)',
                    'directory': dir_path,
                    'items_count': len(items),
                    'items': items
                }
                
            except PermissionError:
                return {
                    'status': 'error',
                    'output': f'Permissions insuffisantes pour lister: {dir_path}'
                }
                
        except Exception as e:
            logger.error(f"Erreur listing répertoire: {e}")
            return {
                'status': 'error',
                'output': f'Erreur lors du listing: {str(e)}'
            }
    
    def get_file_stats(self) -> Dict[str, Any]:
        """Retourne les statistiques des opérations fichiers"""
        return {
            'files_downloaded': self.files_downloaded,
            'files_uploaded': self.files_uploaded,
            'bytes_transferred': self.bytes_transferred,
            'searches_performed': self.searches_performed,
            'max_file_size': self.MAX_FILE_SIZE,
            'max_search_results': self.MAX_SEARCH_RESULTS,
            'allowed_extensions': list(self.ALLOWED_EXTENSIONS)
        }
    
    def _get_file_info(self, file_path: str) -> Dict[str, Any]:
        """Récupère les informations détaillées d'un fichier"""
        try:
            stat = os.stat(file_path)
            
            info = {
                'name': os.path.basename(file_path),
                'path': file_path,
                'size': stat.st_size,
                'type': 'directory' if os.path.isdir(file_path) else 'file',
                'modified': datetime.fromtimestamp(stat.st_mtime).isoformat(),
                'created': datetime.fromtimestamp(stat.st_ctime).isoformat(),
                'accessed': datetime.fromtimestamp(stat.st_atime).isoformat(),
                'permissions': oct(stat.st_mode)[-3:],
                'readable': os.access(file_path, os.R_OK),
                'writable': os.access(file_path, os.W_OK),
                'executable': os.access(file_path, os.X_OK)
            }
            
            # Information MIME pour les fichiers
            if info['type'] == 'file':
                mime_type, _ = mimetypes.guess_type(file_path)
                info['mime_type'] = mime_type
                info['extension'] = os.path.splitext(file_path)[1].lower()
            
            return info
            
        except Exception as e:
            return {
                'name': os.path.basename(file_path),
                'path': file_path,
                'error': str(e)
            }
    
    def _security_check_path(self, file_path: str, for_write: bool = False) -> Dict[str, Any]:
        """
        Effectue des vérifications de sécurité sur un chemin
        
        Args:
            file_path: Chemin à vérifier
            for_write: True si c'est pour une opération d'écriture
        
        Returns:
            Dict avec 'allowed' (bool) et 'reason' (str)
        """
        try:
            # Normalisation du chemin
            normalized_path = os.path.normpath(os.path.abspath(file_path)).lower()
            
            # Vérification des répertoires sensibles
            if self._is_sensitive_dir(normalized_path):
                return {
                    'allowed': False,
                    'reason': 'Répertoire système sensible'
                }
            
            # Vérification de l'extension pour les téléchargements
            if not for_write and os.path.isfile(file_path):
                _, ext = os.path.splitext(file_path)
                if ext.lower() not in self.ALLOWED_EXTENSIONS:
                    return {
                        'allowed': False,
                        'reason': f'Extension non autorisée: {ext}'
                    }
            
            # Vérification des caractères dangereux
            dangerous_patterns = ['../', '..\\', '$', '|', ';', '&', '`']
            if any(pattern in file_path for pattern in dangerous_patterns):
                return {
                    'allowed': False,
                    'reason': 'Caractères dangereux dans le chemin'
                }
            
            return {'allowed': True, 'reason': 'OK'}
            
        except Exception:
            return {
                'allowed': False,
                'reason': 'Erreur lors de la vérification de sécurité'
            }
    
    def _is_sensitive_dir(self, dir_path: str) -> bool:
        """Vérifie si un répertoire est sensible"""
        try:
            import platform
            
            system = platform.system().lower()
            normalized_path = os.path.normpath(dir_path).lower()
            
            sensitive_dirs = self.SENSITIVE_DIRS.get(system, [])
            
            for sensitive_dir in sensitive_dirs:
                if sensitive_dir in normalized_path:
                    return True
            
            return False
            
        except Exception:
            return True  # En cas de doute, considérer comme sensible