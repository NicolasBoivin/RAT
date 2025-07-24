"""
System Handler - Gestionnaire des informations système côté serveur
Traitement et analyse des informations système des agents
"""

import logging
import json
from datetime import datetime
from typing import Dict, Any, List, Optional
from pathlib import Path

from shared.helpers import format_bytes, sanitize_data

logger = logging.getLogger(__name__)

class SystemHandler:
    """Gestionnaire des informations système pour le serveur"""
    
    def __init__(self):
        # Base de données des systèmes connectés
        self.system_database = {}
        
        # Statistiques
        self.systems_analyzed = 0
        self.unique_platforms = set()
        self.unique_users = set()
        
        # Répertoire pour sauvegarder les informations
        self.data_dir = Path("server/data/system_info")
        self.data_dir.mkdir(parents=True, exist_ok=True)
        
        logger.info("SystemHandler initialisé")
    
    def handle_system_info(self, session, system_data: Dict[str, Any]) -> str:
        """
        Traite les informations système reçues d'un agent
        
        Args:
            session: Session client
            system_data: Données système reçues
            
        Returns:
            str: Résumé formaté des informations
        """
        try:
            # Stockage des informations dans la base
            self.system_database[session.id] = {
                'session_id': session.id,
                'system_data': system_data,
                'last_updated': datetime.now().isoformat(),
                'client_address': session.address
            }
            
            # Mise à jour des statistiques
            self._update_statistics(system_data)
            
            # Sauvegarde persistante
            self._save_system_info(session.id, system_data)
            
            # Analyse de sécurité basique
            security_notes = self._analyze_security(system_data)
            
            # Formatage du résumé
            return self._format_system_summary(session.id, system_data, security_notes)
            
        except Exception as e:
            logger.error(f"Erreur dans handle_system_info: {e}")
            return f"[!] Erreur lors du traitement des informations système: {e}"
    
    def handle_network_config(self, session, network_data: Dict[str, Any]) -> str:
        """
        Traite la configuration réseau reçue
        
        Args:
            session: Session client
            network_data: Données de configuration réseau
            
        Returns:
            str: Configuration réseau formatée
        """
        try:
            # Mise à jour des informations stockées
            if session.id in self.system_database:
                self.system_database[session.id]['network_config'] = network_data
                self.system_database[session.id]['last_updated'] = datetime.now().isoformat()
            
            # Extraction et formatage des données réseau
            if 'output' in network_data:
                network_output = network_data['output']
                
                # Analyse des informations réseau
                network_analysis = self._analyze_network_config(network_output)
                
                formatted_output = f"Configuration réseau de {session.id}:\\n"
                formatted_output += "=" * 50 + "\\n"
                formatted_output += network_output
                
                if network_analysis:
                    formatted_output += "\\n\\nAnalyse réseau:\\n"
                    formatted_output += "-" * 20 + "\\n"
                    for key, value in network_analysis.items():
                        formatted_output += f"{key}: {value}\\n"
                
                return formatted_output
            else:
                return "Aucune donnée de configuration réseau reçue"
                
        except Exception as e:
            logger.error(f"Erreur dans handle_network_config: {e}")
            return f"[!] Erreur lors du traitement de la configuration réseau: {e}"
    
    def _update_statistics(self, system_data: Dict[str, Any]):
        """Met à jour les statistiques globales"""
        try:
            self.systems_analyzed += 1
            
            # Collecte des plateformes uniques
            if 'platform' in system_data:
                self.unique_platforms.add(system_data['platform'])
            
            # Collecte des utilisateurs uniques
            if 'username' in system_data:
                self.unique_users.add(system_data['username'])
                
        except Exception as e:
            logger.warning(f"Erreur mise à jour statistiques: {e}")
    
    def _save_system_info(self, session_id: str, system_data: Dict[str, Any]):
        """Sauvegarde les informations système sur disque"""
        try:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"{session_id[:8]}_{timestamp}_sysinfo.json"
            file_path = self.data_dir / filename
            
            save_data = {
                'session_id': session_id,
                'timestamp': datetime.now().isoformat(),
                'system_data': sanitize_data(system_data),
                'analysis': self._analyze_security(system_data)
            }
            
            with open(file_path, 'w', encoding='utf-8') as f:
                json.dump(save_data, f, indent=2, ensure_ascii=False)
                
            logger.info(f"Informations système sauvegardées: {filename}")
            
        except Exception as e:
            logger.warning(f"Erreur sauvegarde informations système: {e}")
    
    def _analyze_security(self, system_data: Dict[str, Any]) -> Dict[str, str]:
        """Analyse de sécurité basique des informations système"""
        try:
            security_notes = {}
            
            # Vérification des privilèges
            if system_data.get('is_admin') or system_data.get('username') == 'root':
                security_notes['privileges'] = "⚠️ Privilèges administrateur détectés"
            else:
                security_notes['privileges'] = "✓ Utilisateur standard"
            
            # Vérification de l'antivirus (si disponible)
            if 'antivirus' in system_data:
                av_list = system_data['antivirus']
                if av_list and len(av_list) > 0:
                    security_notes['antivirus'] = f"✓ Antivirus détecté: {', '.join(av_list)}"
                else:
                    security_notes['antivirus'] = "⚠️ Aucun antivirus détecté"
            
            # Vérification du firewall (si disponible)
            if 'firewall' in system_data:
                fw_info = system_data['firewall']
                if isinstance(fw_info, dict) and fw_info.get('status') == 'enabled':
                    security_notes['firewall'] = "✓ Firewall activé"
                else:
                    security_notes['firewall'] = "⚠️ Firewall désactivé ou inconnu"
            
            # Vérification de l'UAC (Windows)
            if 'uac_enabled' in system_data:
                if system_data['uac_enabled']:
                    security_notes['uac'] = "✓ UAC activé"
                else:
                    security_notes['uac'] = "⚠️ UAC désactivé"
            
            # Analyse de la plateforme
            platform = system_data.get('platform', '').lower()
            if 'windows' in platform:
                security_notes['platform'] = f"Windows détecté: {system_data.get('platform')}"
            elif 'linux' in platform:
                security_notes['platform'] = f"Linux détecté: {system_data.get('platform')}"
            elif 'darwin' in platform or 'mac' in platform:
                security_notes['platform'] = f"macOS détecté: {system_data.get('platform')}"
            else:
                security_notes['platform'] = f"Plateforme: {system_data.get('platform', 'Inconnue')}"
            
            return security_notes
            
        except Exception as e:
            logger.warning(f"Erreur analyse sécurité: {e}")
            return {'error': 'Erreur lors de l\'analyse de sécurité'}
    
    def _analyze_network_config(self, network_output: str) -> Dict[str, str]:
        """Analyse basique de la configuration réseau"""
        try:
            analysis = {}
            
            # Recherche d'adresses IP
            import re
            ip_pattern = r'\\b(?:[0-9]{1,3}\\.){3}[0-9]{1,3}\\b'
            ips_found = re.findall(ip_pattern, network_output)
            
            if ips_found:
                # Filtrage des IPs privées et publiques
                private_ips = []
                public_ips = []
                
                for ip in set(ips_found):  # Suppression des doublons
                    parts = ip.split('.')
                    if len(parts) == 4:
                        first_octet = int(parts[0])
                        second_octet = int(parts[1])
                        
                        # Classification IP privée/publique (basique)
                        if (first_octet == 10 or 
                            (first_octet == 172 and 16 <= second_octet <= 31) or
                            (first_octet == 192 and second_octet == 168) or
                            ip.startswith('127.')):
                            private_ips.append(ip)
                        elif not ip.startswith('0.') and not ip.startswith('255.'):
                            public_ips.append(ip)
                
                if private_ips:
                    analysis['private_ips'] = ', '.join(private_ips)
                if public_ips:
                    analysis['public_ips'] = ', '.join(public_ips)
            
            # Recherche d'interfaces réseau
            if 'ethernet' in network_output.lower() or 'wifi' in network_output.lower():
                analysis['connectivity'] = "Connexions Ethernet/WiFi détectées"
            
            # Recherche de passerelles
            if 'gateway' in network_output.lower() or 'default' in network_output.lower():
                analysis['gateway'] = "Passerelle par défaut configurée"
            
            return analysis
            
        except Exception as e:
            logger.warning(f"Erreur analyse réseau: {e}")
            return {'error': 'Erreur lors de l\'analyse réseau'}
    
    def _format_system_summary(self, session_id: str, system_data: Dict[str, Any], security_notes: Dict[str, str]) -> str:
        """Formate un résumé des informations système"""
        try:
            summary = f"Informations système - {session_id}\\n"
            summary += "=" * 50 + "\\n"
            
            # Informations de base
            basic_info = [
                ('Nom d\'hôte', system_data.get('hostname', 'Inconnu')),
                ('Plateforme', system_data.get('platform', 'Inconnue')),
                ('Utilisateur', system_data.get('username', 'Inconnu')),
                ('Processeur', system_data.get('processor', 'Inconnu')),
                ('Architecture', system_data.get('machine', 'Inconnue'))
            ]
            
            for label, value in basic_info:
                summary += f"{label:15s}: {value}\\n"
            
            # Informations réseau
            if 'ip_address' in system_data:
                summary += f"{'Adresse IP':15s}: {system_data['ip_address']}\\n"
            
            if 'mac_address' in system_data:
                summary += f"{'Adresse MAC':15s}: {system_data['mac_address']}\\n"
            
            # Informations matérielles (si disponibles)
            if 'cpu' in system_data:
                cpu_info = system_data['cpu']
                if isinstance(cpu_info, dict):
                    cores = cpu_info.get('total_cores', 'Inconnu')
                    usage = cpu_info.get('usage', 'Inconnu')
                    summary += f"{'CPU Cores':15s}: {cores} (Usage: {usage})\\n"
            
            if 'memory' in system_data:
                memory_info = system_data['memory']
                if isinstance(memory_info, dict):
                    total = memory_info.get('total', 'Inconnu')
                    usage = memory_info.get('percentage', 'Inconnu')
                    summary += f"{'Mémoire':15s}: {total} (Usage: {usage})\\n"
            
            # Notes de sécurité
            if security_notes:
                summary += "\\nAnalyse de sécurité:\\n"
                summary += "-" * 20 + "\\n"
                for key, note in security_notes.items():
                    summary += f"{key:12s}: {note}\\n"
            
            return summary
            
        except Exception as e:
            logger.error(f"Erreur formatage résumé: {e}")
            return f"[!] Erreur lors du formatage du résumé: {e}"
    
    def list_connected_systems(self) -> str:
        """Liste tous les systèmes analysés"""
        try:
            if not self.system_database:
                return "Aucun système analysé"
            
            output = f"Systèmes analysés ({len(self.system_database)}):\\n"
            output += "=" * 80 + "\\n"
            
            for session_id, info in self.system_database.items():
                system_data = info['system_data']
                last_updated = info['last_updated']
                address = info['client_address']
                
                # Formatage des informations essentielles
                hostname = system_data.get('hostname', 'Inconnu')
                platform = system_data.get('platform', 'Inconnue')
                username = system_data.get('username', 'Inconnu')
                
                output += (
                    f"Session: {session_id}\\n"
                    f"  Adresse: {address[0]}:{address[1]}\\n"
                    f"  Hôte: {hostname} ({platform})\\n"
                    f"  Utilisateur: {username}\\n"
                    f"  Dernière MAJ: {last_updated.split('T')[0]}\\n"
                    f"\\n"
                )
            
            return output
            
        except Exception as e:
            logger.error(f"Erreur dans list_connected_systems: {e}")
            return f"[!] Erreur lors du listage: {e}"
    
    def get_system_details(self, session_id: str) -> str:
        """Récupère les détails complets d'un système"""
        try:
            if session_id not in self.system_database:
                return f"[!] Système non trouvé: {session_id}"
            
            info = self.system_database[session_id]
            system_data = info['system_data']
            
            # Affichage détaillé en JSON formaté
            output = f"Détails système - {session_id}\\n"
            output += "=" * 60 + "\\n"
            
            # Informations formatées lisiblement
            formatted_data = self._format_detailed_info(system_data)
            output += formatted_data
            
            return output
            
        except Exception as e:
            logger.error(f"Erreur dans get_system_details: {e}")
            return f"[!] Erreur lors de la récupération: {e}"
    
    def _format_detailed_info(self, system_data: Dict[str, Any]) -> str:
        """Formate les informations détaillées de manière lisible"""
        try:
            output = ""
            
            # Informations de base
            if 'basic' in system_data:
                basic = system_data['basic']
                output += "INFORMATIONS DE BASE:\\n"
                for key, value in basic.items():
                    output += f"  {key:20s}: {value}\\n"
                output += "\\n"
            
            # Informations matérielles
            if 'hardware' in system_data:
                hw = system_data['hardware']
                output += "MATÉRIEL:\\n"
                
                if 'cpu' in hw:
                    output += "  CPU:\\n"
                    for key, value in hw['cpu'].items():
                        output += f"    {key:18s}: {value}\\n"
                
                if 'memory' in hw:
                    output += "  Mémoire:\\n"
                    for key, value in hw['memory'].items():
                        output += f"    {key:18s}: {value}\\n"
                
                if 'disks' in hw and hw['disks']:
                    output += "  Disques:\\n"
                    for i, disk in enumerate(hw['disks'], 1):
                        output += f"    Disque {i}:\\n"
                        for key, value in disk.items():
                            output += f"      {key:16s}: {value}\\n"
                
                output += "\\n"
            
            # Informations réseau
            if 'network' in system_data:
                net = system_data['network']
                output += "RÉSEAU:\\n"
                
                if 'interfaces' in net:
                    output += "  Interfaces:\\n"
                    for interface, addresses in net['interfaces'].items():
                        output += f"    {interface}:\\n"
                        for addr in addresses:
                            if isinstance(addr, dict):
                                for key, value in addr.items():
                                    output += f"      {key:14s}: {value}\\n"
                
                if 'statistics' in net:
                    output += "  Statistiques:\\n"
                    for key, value in net['statistics'].items():
                        if isinstance(value, int):
                            formatted_value = format_bytes(value) if 'bytes' in key else str(value)
                        else:
                            formatted_value = str(value)
                        output += f"    {key:16s}: {formatted_value}\\n"
                
                output += "\\n"
            
            # Processus top (si disponible)
            if 'processes' in system_data:
                proc = system_data['processes']
                output += f"PROCESSUS (Total: {proc.get('count', 'Inconnu')}):\\n"
                
                if 'top_cpu' in proc and proc['top_cpu']:
                    output += "  Top CPU:\\n"
                    for p in proc['top_cpu'][:5]:  # Top 5
                        output += f"    {p['name']:20s} PID:{p['pid']:6d} CPU:{p['cpu_percent']}\\n"
                
                if 'top_memory' in proc and proc['top_memory']:
                    output += "  Top Mémoire:\\n"
                    for p in proc['top_memory'][:5]:  # Top 5
                        output += f"    {p['name']:20s} PID:{p['pid']:6d} MEM:{p['memory_percent']}\\n"
                
                output += "\\n"
            
            return output
            
        except Exception as e:
            logger.warning(f"Erreur formatage détaillé: {e}")
            return f"Erreur lors du formatage: {e}"
    
    def get_system_stats(self) -> str:
        """Retourne les statistiques globales des systèmes"""
        try:
            output = f"""
╔════════════════════════════════════════╗
║        STATISTIQUES SYSTÈME           ║
╠════════════════════════════════════════╣
║ Systèmes analysés: {self.systems_analyzed:14d} ║
║ Systèmes actifs: {len(self.system_database):16d} ║
║ Plateformes uniques: {len(self.unique_platforms):11d} ║
║ Utilisateurs uniques: {len(self.unique_users):10d} ║
╚════════════════════════════════════════╝

Plateformes détectées:"""
            
            for platform in sorted(self.unique_platforms):
                output += f"\\n  - {platform}"
            
            output += "\\n\\nUtilisateurs détectés:"
            for user in sorted(self.unique_users):
                output += f"\\n  - {user}"
            
            return output
            
        except Exception as e:
            logger.error(f"Erreur dans get_system_stats: {e}")
            return f"[!] Erreur lors de la récupération des statistiques: {e}"
    
    def export_system_data(self, session_id: str = None, format: str = 'json') -> str:
        """
        Exporte les données système
        
        Args:
            session_id: ID de session spécifique (optionnel)
            format: Format d'export ('json', 'txt')
            
        Returns:
            str: Message de résultat
        """
        try:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            
            if session_id:
                if session_id not in self.system_database:
                    return f"[!] Système non trouvé: {session_id}"
                
                data_to_export = {session_id: self.system_database[session_id]}
                filename = f"system_data_{session_id[:8]}_{timestamp}.{format}"
            else:
                data_to_export = self.system_database
                filename = f"system_data_all_{timestamp}.{format}"
            
            export_path = self.data_dir / filename
            
            if format == 'json':
                with open(export_path, 'w', encoding='utf-8') as f:
                    json.dump(data_to_export, f, indent=2, ensure_ascii=False)
            elif format == 'txt':
                with open(export_path, 'w', encoding='utf-8') as f:
                    f.write(f"# System Data Export\\n")
                    f.write(f"# Generated: {datetime.now().isoformat()}\\n\\n")
                    
                    for sid, info in data_to_export.items():
                        f.write(f"Session: {sid}\\n")
                        f.write("=" * 50 + "\\n")
                        f.write(self._format_detailed_info(info['system_data']))
                        f.write("\\n" + "-" * 50 + "\\n\\n")
            else:
                return f"[!] Format non supporté: {format}"
            
            return f"[+] Données exportées: {filename}"
            
        except Exception as e:
            logger.error(f"Erreur dans export_system_data: {e}")
            return f"[!] Erreur lors de l'export: {e}"
    
    def cleanup_old_data(self, days: int = 30) -> str:
        """Nettoie les anciennes données système"""
        try:
            cutoff_time = datetime.now().timestamp() - (days * 24 * 3600)
            cleaned_files = 0
            
            for file_path in self.data_dir.glob("*_sysinfo.json"):
                if file_path.stat().st_mtime < cutoff_time:
                    file_path.unlink()
                    cleaned_files += 1
            
            return f"[+] Nettoyage terminé: {cleaned_files} fichiers supprimés"
            
        except Exception as e:
            logger.error(f"Erreur dans cleanup_old_data: {e}")
            return f"[!] Erreur lors du nettoyage: {e}"