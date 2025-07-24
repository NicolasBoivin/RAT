"""
Shell Executor Module - Exécution de commandes shell
Gestion sécurisée des commandes système avec limitations et filtrage
Inspiré des fonctionnalités shell des RATs modernes
"""

import subprocess
import threading
import time
import os
import signal
import platform
from typing import Dict, Any, List, Optional, Tuple
from datetime import datetime
import logging

logger = logging.getLogger(__name__)

class ShellExecutor:
    """Exécuteur de commandes shell avec sécurité renforcée"""
    
    def __init__(self):
        # Paramètres de sécurité
        self.MAX_EXECUTION_TIME = 30  # 30 secondes max par commande
        self.MAX_OUTPUT_SIZE = 1024 * 1024  # 1MB max de sortie
        self.MAX_CONCURRENT_COMMANDS = 3
        
        # Commandes interdites (protection de base)
        self.FORBIDDEN_COMMANDS = {
            'windows': [
                'format', 'del /s', 'rd /s', 'rmdir /s', 'deltree',
                'shutdown /f', 'taskkill /f', 'net user', 'net localgroup',
                'reg delete', 'wmic process', 'powershell -enc',
                'cmd /c echo', 'fsutil', 'cipher', 'schtasks /create'
            ],
            'linux': [
                'rm -rf /', 'rm -rf *', 'dd if=', 'mkfs', 'fdisk',
                'sudo rm', 'chmod 777', 'chown -R', '> /dev/',
                'kill -9', 'killall', 'pkill', 'halt', 'reboot',
                'iptables -F', 'ufw --force', 'passwd'
            ],
            'darwin': [
                'rm -rf /', 'rm -rf *', 'dd if=', 'diskutil',
                'sudo rm', 'chmod 777', 'chown -R', 'kill -9',
                'killall', 'halt', 'reboot', 'pfctl -F'
            ]
        }
        
        # Commandes avec restrictions spéciales
        self.RESTRICTED_COMMANDS = {
            'ping': {'max_count': 5, 'timeout': 10},
            'nslookup': {'timeout': 10},
            'tracert': {'max_hops': 15, 'timeout': 20},
            'traceroute': {'max_hops': 15, 'timeout': 20},
            'netstat': {'timeout': 5},
            'ipconfig': {'timeout': 5},
            'ifconfig': {'timeout': 5}
        }
        
        # État d'exécution
        self.active_processes = {}
        self.commands_executed = 0
        self.total_execution_time = 0
        self.process_lock = threading.Lock()
        
        # Détection du système
        self.system = platform.system().lower()
        
        # Shell par défaut selon l'OS
        if self.system == 'windows':
            self.default_shell = 'cmd.exe'
            self.shell_args = ['/c']
        else:
            self.default_shell = '/bin/bash'
            self.shell_args = ['-c']
    
    def execute_command(self, command: str, timeout: int = None, shell: str = None) -> Dict[str, Any]:
        """
        Exécute une commande shell avec sécurité
        
        Args:
            command: Commande à exécuter
            timeout: Timeout personnalisé (défaut: MAX_EXECUTION_TIME)
            shell: Shell spécifique à utiliser
        
        Returns:
            Dict avec le résultat de l'exécution
        """
        try:
            if not command or not command.strip():
                return {
                    'status': 'error',
                    'output': 'Commande vide'
                }
            
            command = command.strip()
            
            # Vérification du nombre de processus concurrent
            with self.process_lock:
                if len(self.active_processes) >= self.MAX_CONCURRENT_COMMANDS:
                    return {
                        'status': 'error',
                        'output': f'Limite de {self.MAX_CONCURRENT_COMMANDS} processus simultanés atteinte'
                    }
            
            # Vérifications de sécurité
            security_check = self._check_command_security(command)
            if not security_check['allowed']:
                return {
                    'status': 'error',
                    'output': f'Commande bloquée: {security_check["reason"]}'
                }
            
            # Application des restrictions spéciales
            restricted_command = self._apply_command_restrictions(command)
            if restricted_command != command:
                command = restricted_command
                logger.info(f"Commande restreinte modifiée: {command}")
            
            # Configuration du timeout
            if timeout is None:
                timeout = self.MAX_EXECUTION_TIME
            else:
                timeout = min(timeout, self.MAX_EXECUTION_TIME)  # Pas plus que le max
            
            # Exécution de la commande
            result = self._execute_subprocess(command, timeout, shell)
            
            # Mise à jour des statistiques
            self.commands_executed += 1
            self.total_execution_time += result.get('execution_time', 0)
            
            return result
            
        except Exception as e:
            logger.error(f"Erreur exécution commande: {e}")
            return {
                'status': 'error',
                'output': f'Erreur lors de l\'exécution: {str(e)}'
            }
    
    def _execute_subprocess(self, command: str, timeout: int, shell: str = None) -> Dict[str, Any]:
        """Exécute la commande via subprocess avec monitoring"""
        process_id = None
        start_time = time.time()
        
        try:
            # Préparation de la commande
            if shell is None:
                shell = self.default_shell
            
            # Construction des arguments
            if self.system == 'windows':
                cmd_args = [shell] + self.shell_args + [command]
                # Désactivation de la fenêtre sur Windows
                startupinfo = subprocess.STARTUPINFO()
                startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
                startupinfo.wShowWindow = subprocess.SW_HIDE
            else:
                cmd_args = [shell] + self.shell_args + [command]
                startupinfo = None
            
            # Lancement du processus
            process = subprocess.Popen(
                cmd_args,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                stdin=subprocess.PIPE,
                startupinfo=startupinfo,
                creationflags=subprocess.CREATE_NO_WINDOW if self.system == 'windows' else 0,
                text=True,
                bufsize=0
            )
            
            process_id = process.pid
            
            # Enregistrement du processus actif
            with self.process_lock:
                self.active_processes[process_id] = {
                    'process': process,
                    'command': command,
                    'start_time': start_time
                }
            
            try:
                # Attente avec timeout
                stdout, stderr = process.communicate(timeout=timeout)
                return_code = process.returncode
                
            except subprocess.TimeoutExpired:
                # Timeout atteint - terminer le processus
                logger.warning(f"Timeout pour la commande: {command}")
                
                try:
                    # Tentative de terminaison propre
                    process.terminate()
                    try:
                        process.wait(timeout=2)
                    except subprocess.TimeoutExpired:
                        # Forcer la terminaison
                        process.kill()
                        process.wait()
                except:
                    pass
                
                return {
                    'status': 'timeout',
                    'output': f'Commande interrompue après {timeout}s (timeout)',
                    'command': command,
                    'execution_time': timeout,
                    'return_code': -1
                }
            
            # Nettoyage du processus actif
            with self.process_lock:
                if process_id in self.active_processes:
                    del self.active_processes[process_id]
            
            execution_time = time.time() - start_time
            
            # Limitation de la taille de sortie
            if len(stdout) > self.MAX_OUTPUT_SIZE:
                stdout = stdout[:self.MAX_OUTPUT_SIZE] + "\\n\\n[SORTIE TRONQUÉE - TAILLE MAXIMALE ATTEINTE]"
            
            if len(stderr) > self.MAX_OUTPUT_SIZE:
                stderr = stderr[:self.MAX_OUTPUT_SIZE] + "\\n\\n[ERREUR TRONQUÉE - TAILLE MAXIMALE ATTEINTE]"
            
            # Construction de la sortie combinée
            combined_output = ""
            if stdout:
                combined_output += stdout
            if stderr:
                if combined_output:
                    combined_output += "\\n--- STDERR ---\\n"
                combined_output += stderr
            
            if not combined_output:
                combined_output = "[Aucune sortie]"
            
            # Détermination du statut
            status = 'success' if return_code == 0 else 'error'
            
            return {
                'status': status,
                'output': combined_output,
                'command': command,
                'return_code': return_code,
                'execution_time': round(execution_time, 2),
                'stdout': stdout,
                'stderr': stderr,
                'timestamp': datetime.now().isoformat()
            }
            
        except Exception as e:
            # Nettoyage en cas d'erreur
            if process_id:
                with self.process_lock:
                    if process_id in self.active_processes:
                        del self.active_processes[process_id]
            
            execution_time = time.time() - start_time
            
            return {
                'status': 'error',
                'output': f'Erreur subprocess: {str(e)}',
                'command': command,
                'execution_time': round(execution_time, 2),
                'error': str(e)
            }
    
    def _check_command_security(self, command: str) -> Dict[str, Any]:
        """
        Vérifie la sécurité d'une commande
        
        Args:
            command: Commande à vérifier
        
        Returns:
            Dict avec 'allowed' (bool) et 'reason' (str)
        """
        try:
            command_lower = command.lower().strip()
            
            # Vérification des commandes interdites
            forbidden_list = self.FORBIDDEN_COMMANDS.get(self.system, [])
            
            for forbidden in forbidden_list:
                if forbidden.lower() in command_lower:
                    return {
                        'allowed': False,
                        'reason': f'Commande interdite détectée: {forbidden}'
                    }
            
            # Vérification des patterns dangereux
            dangerous_patterns = [
                '&&', '||', ';', '|', '>', '>>', '<',  # Opérateurs de redirection/pipe
                '$(', '`', '${',  # Substitution de commandes
                'eval', 'exec',  # Exécution dynamique
                '/dev/null', '/dev/zero', '/dev/random',  # Devices spéciaux
                'while true', 'while 1', 'for(;;)',  # Boucles infinies
                'fork()', 'system(',  # Appels système dangereux
            ]
            
            for pattern in dangerous_patterns:
                if pattern in command_lower:
                    return {
                        'allowed': False,
                        'reason': f'Pattern dangereux détecté: {pattern}'
                    }
            
            # Vérification de la longueur (prévention de buffer overflow)
            if len(command) > 1000:
                return {
                    'allowed': False,
                    'reason': 'Commande trop longue (>1000 caractères)'
                }
            
            # Vérification des caractères de contrôle
            control_chars = ['\\x00', '\\x01', '\\x02', '\\x03', '\\x04']
            if any(char in command for char in control_chars):
                return {
                    'allowed': False,
                    'reason': 'Caractères de contrôle détectés'
                }
            
            return {'allowed': True, 'reason': 'OK'}
            
        except Exception as e:
            logger.error(f"Erreur vérification sécurité: {e}")
            return {
                'allowed': False,
                'reason': 'Erreur lors de la vérification de sécurité'
            }
    
    def _apply_command_restrictions(self, command: str) -> str:
        """
        Applique des restrictions à certaines commandes
        
        Args:
            command: Commande originale
        
        Returns:
            str: Commande modifiée si nécessaire
        """
        try:
            command_parts = command.strip().split()
            if not command_parts:
                return command
            
            base_command = command_parts[0].lower()
            
            # Vérification des commandes restreintes
            if base_command in self.RESTRICTED_COMMANDS:
                restrictions = self.RESTRICTED_COMMANDS[base_command]
                
                if base_command == 'ping':
                    # Limitation du nombre de pings
                    max_count = restrictions['max_count']
                    if '-n' not in command.lower() and '-c' not in command.lower():
                        if self.system == 'windows':
                            command += f' -n {max_count}'
                        else:
                            command += f' -c {max_count}'
                
                elif base_command in ['tracert', 'traceroute']:
                    # Limitation du nombre de hops
                    max_hops = restrictions['max_hops']
                    if '-h' not in command.lower() and '-m' not in command.lower():
                        if self.system == 'windows':
                            command += f' -h {max_hops}'
                        else:
                            command += f' -m {max_hops}'
            
            return command
            
        except Exception as e:
            logger.error(f"Erreur application restrictions: {e}")
            return command
    
    def kill_process(self, process_id: int = None) -> Dict[str, Any]:
        """
        Termine un processus en cours
        
        Args:
            process_id: ID du processus à terminer (None = tous)
        
        Returns:
            Dict avec le résultat de l'opération
        """
        try:
            with self.process_lock:
                if process_id is None:
                    # Terminer tous les processus
                    killed_count = 0
                    for pid, proc_info in list(self.active_processes.items()):
                        try:
                            proc_info['process'].terminate()
                            killed_count += 1
                            del self.active_processes[pid]
                        except:
                            pass
                    
                    return {
                        'status': 'success',
                        'output': f'{killed_count} processus terminés'
                    }
                
                else:
                    # Terminer un processus spécifique
                    if process_id in self.active_processes:
                        try:
                            self.active_processes[process_id]['process'].terminate()
                            del self.active_processes[process_id]
                            return {
                                'status': 'success',
                                'output': f'Processus {process_id} terminé'
                            }
                        except Exception as e:
                            return {
                                'status': 'error',
                                'output': f'Erreur lors de la terminaison: {str(e)}'
                            }
                    else:
                        return {
                            'status': 'error',
                            'output': f'Processus {process_id} non trouvé'
                        }
                        
        except Exception as e:
            return {
                'status': 'error',
                'output': f'Erreur: {str(e)}'
            }
    
    def list_active_processes(self) -> Dict[str, Any]:
        """Liste les processus shell actifs"""
        try:
            with self.process_lock:
                if not self.active_processes:
                    return {
                        'status': 'info',
                        'output': 'Aucun processus actif',
                        'processes': []
                    }
                
                processes = []
                current_time = time.time()
                
                for pid, proc_info in self.active_processes.items():
                    runtime = current_time - proc_info['start_time']
                    processes.append({
                        'pid': pid,
                        'command': proc_info['command'],
                        'runtime': round(runtime, 1),
                        'start_time': datetime.fromtimestamp(proc_info['start_time']).isoformat()
                    })
                
                return {
                    'status': 'success',
                    'output': f'{len(processes)} processus actifs',
                    'processes': processes
                }
                
        except Exception as e:
            return {
                'status': 'error',
                'output': f'Erreur: {str(e)}'
            }
    
    def get_shell_info(self) -> Dict[str, Any]:
        """Retourne les informations sur l'environnement shell"""
        try:
            info = {
                'system': self.system,
                'default_shell': self.default_shell,
                'current_directory': os.getcwd(),
                'environment_count': len(os.environ),
                'commands_executed': self.commands_executed,
                'total_execution_time': round(self.total_execution_time, 2),
                'active_processes': len(self.active_processes),
                'max_execution_time': self.MAX_EXECUTION_TIME,
                'max_output_size': self.MAX_OUTPUT_SIZE,
                'max_concurrent_commands': self.MAX_CONCURRENT_COMMANDS,
                'forbidden_commands_count': len(self.FORBIDDEN_COMMANDS.get(self.system, [])),
                'restricted_commands': list(self.RESTRICTED_COMMANDS.keys())
            }
            
            # Informations système supplémentaires
            try:
                import psutil
                info['system_info'] = {
                    'cpu_count': psutil.cpu_count(),
                    'memory_total': psutil.virtual_memory().total,
                    'disk_usage': psutil.disk_usage('/').total if self.system != 'windows' else psutil.disk_usage('C:').total
                }
            except:
                pass
            
            return {
                'status': 'success',
                'output': 'Informations shell récupérées',
                'data': info
            }
            
        except Exception as e:
            return {
                'status': 'error',
                'output': f'Erreur: {str(e)}'
            }
    
    def change_directory(self, path: str) -> Dict[str, Any]:
        """
        Change le répertoire de travail courant
        
        Args:
            path: Nouveau répertoire
        
        Returns:
            Dict avec le résultat de l'opération
        """
        try:
            if not path or not path.strip():
                return {
                    'status': 'error',
                    'output': 'Chemin manquant'
                }
            
            path = path.strip()
            
            # Vérifications de sécurité basiques
            if '..' in path and ('/' in path or '\\\\' in path):
                return {
                    'status': 'error',
                    'output': 'Navigation vers les répertoires parents interdite'
                }
            
            old_dir = os.getcwd()
            
            try:
                os.chdir(path)
                new_dir = os.getcwd()
                
                return {
                    'status': 'success',
                    'output': f'Répertoire changé: {old_dir} -> {new_dir}',
                    'old_directory': old_dir,
                    'new_directory': new_dir
                }
                
            except FileNotFoundError:
                return {
                    'status': 'error',
                    'output': f'Répertoire non trouvé: {path}'
                }
            except PermissionError:
                return {
                    'status': 'error',
                    'output': f'Permissions insuffisantes: {path}'
                }
            except OSError as e:
                return {
                    'status': 'error',
                    'output': f'Erreur système: {str(e)}'
                }
                
        except Exception as e:
            return {
                'status': 'error',
                'output': f'Erreur: {str(e)}'
            }