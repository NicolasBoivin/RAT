"""
System Handler - Gestionnaire des informations système côté serveur
Traitement et formatage des informations système des agents
"""

import json
import logging
from datetime import datetime
from typing import Dict, Any, List, Optional

logger = logging.getLogger(__name__)

class SystemHandler:
    """Gestionnaire des informations système du serveur"""
    
    def __init__(self):
        # Cache des informations système par session
        self.system_info_cache = {}
        
        # Statistiques
        self.info_requests = 0
        self.last_update = {}
        
        logger.info("SystemHandler initialisé")
    
    def process_system_info(self, session, system_data: Dict[str, Any]) -> str:
        """
        Traite et formate les informations système reçues
        
        Args:
            session: Session de l'agent
            system_data: Données système reçues
        
        Returns:
            str: Informations formatées pour affichage
        """
        try:
            # Mise en cache des informations
            self.system_info_cache[session.id] = system_data
            self.last_update[session.id] = datetime.now()
            self.info_requests += 1
            
            # Formatage pour affichage
            formatted_info = self._format_system_info(system_data)
            
            logger.info(f"Informations système reçues de {session.id}")
            return formatted_info
            
        except Exception as e:
            logger.error(f"Erreur traitement info système: {e}")
            return f"[!] Erreur lors du traitement des informations système: {e}"
    
    def process_network_config(self, session, network_data: Dict[str, Any]) -> str:
        """
        Traite et formate la configuration réseau
        
        Args:
            session: Session de l'agent
            network_data: Données réseau reçues
        
        Returns:
            str: Configuration réseau formatée
        """
        try:
            if network_data.get('status') == 'success':
                output = network_data.get('output', '')
                return self._format_network_output(output)
            else:
                return f"[!] Erreur récupération config réseau: {network_data.get('output', 'Erreur inconnue')}"
                
        except Exception as e:
            logger.error(f"Erreur traitement config réseau: {e}")
            return f"[!] Erreur lors du traitement: {e}"
    
    def _format_system_info(self, system_data: Dict[str, Any]) -> str:
        """Formate les informations système pour affichage"""
        try:
            if isinstance(system_data, str):
                # Si c'est déjà une chaîne JSON, la parser
                try:
                    system_data = json.loads(system_data)
                except:
                    return system_data
            
            output = []
            output.append("╔════════════════════════════════════════════════════════════╗")
            output.append("║                 INFORMATIONS SYSTÈME                       ║")
            output.append("╠════════════════════════════════════════════════════════════╣")
            
            # Informations de base
            basic_info = system_data.get('basic', {})
            if basic_info:
                output.append("║ SYSTÈME DE BASE:                                          ║")
                output.append(f"║   Hostname: {basic_info.get('hostname', 'N/A'):<43} ║")
                output.append(f"║   Platform: {basic_info.get('platform', 'N/A'):<43} ║")
                output.append(f"║   System: {basic_info.get('system', 'N/A'):<45} ║")
                output.append(f"║   Release: {basic_info.get('release', 'N/A'):<44} ║")
                output.append(f"║   Machine: {basic_info.get('machine', 'N/A'):<44} ║")
                output.append(f"║   Username: {basic_info.get('username', 'N/A'):<43} ║")
                output.append(f"║   IP Address: {basic_info.get('ip_address', 'N/A'):<41} ║")
                output.append("╠════════════════════════════════════════════════════════════╣")
            
            # Informations matérielles
            hardware_info = system_data.get('hardware', {})
            if hardware_info:
                output.append("║ MATÉRIEL:                                                  ║")
                
                # CPU
                cpu_info = hardware_info.get('cpu', {})
                if cpu_info:
                    cores = f"{cpu_info.get('physical_cores', 'N/A')}/{cpu_info.get('total_cores', 'N/A')}"
                    output.append(f"║   CPU Cores: {cores:<44} ║")
                    output.append(f"║   CPU Usage: {cpu_info.get('usage', 'N/A'):<44} ║")
                    freq = cpu_info.get('max_frequency', 'N/A')
                    output.append(f"║   CPU Freq: {freq:<45} ║")
                
                # Mémoire
                memory_info = hardware_info.get('memory', {})
                if memory_info:
                    output.append(f"║   RAM Total: {memory_info.get('total', 'N/A'):<43} ║")
                    output.append(f"║   RAM Used: {memory_info.get('used', 'N/A'):<44} ║")
                    output.append(f"║   RAM Usage: {memory_info.get('percentage', 'N/A'):<43} ║")
                
                output.append("╠════════════════════════════════════════════════════════════╣")
            
            # Informations réseau
            network_info = system_data.get('network', {})
            if network_info:
                output.append("║ RÉSEAU:                                                    ║")
                
                # Statistiques réseau
                stats = network_info.get('statistics', {})
                if stats:
                    bytes_sent = self._format_bytes(stats.get('bytes_sent', 0))
                    bytes_recv = self._format_bytes(stats.get('bytes_recv', 0))
                    output.append(f"║   Bytes Sent: {bytes_sent:<43} ║")
                    output.append(f"║   Bytes Recv: {bytes_recv:<43} ║")
                
                output.append("╠════════════════════════════════════════════════════════════╣")
            
            # Informations de sécurité
            security_info = system_data.get('security', {})
            if security_info:
                output.append("║ SÉCURITÉ:                                                  ║")
                admin_status = "OUI" if security_info.get('is_admin') else "NON"
                output.append(f"║   Admin: {admin_status:<48} ║")
                
                antivirus = security_info.get('antivirus', [])
                if antivirus:
                    av_list = ", ".join(antivirus[:2])  # Maximum 2 AV affichés
                    if len(av_list) > 45:
                        av_list = av_list[:42] + "..."
                    output.append(f"║   Antivirus: {av_list:<44} ║")
                
                firewall = security_info.get('firewall', {})
                if firewall:
                    fw_status = firewall.get('status', 'unknown').upper()
                    output.append(f"║   Firewall: {fw_status:<45} ║")
                
                output.append("╠════════════════════════════════════════════════════════════╣")
            
            # Processus top
            process_info = system_data.get('processes', {})
            if process_info:
                output.append("║ PROCESSUS (TOP CPU):                                      ║")
                
                top_cpu = process_info.get('top_cpu', [])[:3]  # Top 3
                for i, proc in enumerate(top_cpu, 1):
                    name = proc.get('name', 'Unknown')[:15]
                    cpu = proc.get('cpu_percent', 'N/A')
                    output.append(f"║   {i}. {name:<15} - CPU: {cpu:<25} ║")
                
                if not top_cpu:
                    output.append("║   Aucune information de processus disponible              ║")
            
            output.append("╚════════════════════════════════════════════════════════════╝")
            
            return "\\n".join(output)
            
        except Exception as e:
            logger.error(f"Erreur formatage info système: {e}")
            return f"[!] Erreur formatage: {e}\\n\\nDonnées brutes:\\n{system_data}"
    
    def _format_network_output(self, network_output: str) -> str:
        """Formate la sortie de configuration réseau"""
        try:
            if not network_output:
                return "[!] Aucune information réseau disponible"
            
            # Nettoyage de base
            lines = network_output.strip().split('\\n')
            
            # En-tête
            formatted_lines = []
            formatted_lines.append("╔════════════════════════════════════════════════════════════╗")
            formatted_lines.append("║                 CONFIGURATION RÉSEAU                      ║")
            formatted_lines.append("╠════════════════════════════════════════════════════════════╣")
            
            # Traitement des lignes
            for line in lines[:50]:  # Limitation à 50 lignes
                if len(line) > 58:  # Largeur du tableau - 4 caractères pour les bordures
                    line = line[:55] + "..."
                
                # Padding pour centrer dans le tableau
                formatted_lines.append(f"║ {line:<58} ║")
            
            formatted_lines.append("╚════════════════════════════════════════════════════════════╝")
            
            return "\\n".join(formatted_lines)
            
        except Exception as e:
            logger.error(f"Erreur formatage réseau: {e}")
            return f"[!] Erreur formatage réseau: {e}\\n\\n{network_output}"
    
    def _format_bytes(self, byte_count: int) -> str:
        """Formate une taille en bytes de manière lisible"""
        try:
            for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
                if byte_count < 1024.0:
                    return f"{byte_count:.1f} {unit}"
                byte_count /= 1024.0
            return f"{byte_count:.1f} PB"
        except:
            return "N/A"
    
    def get_cached_system_info(self, session_id: str) -> Optional[Dict[str, Any]]:
        """
        Récupère les informations système en cache
        
        Args:
            session_id: ID de la session
        
        Returns:
            Dict ou None: Informations système ou None si pas en cache
        """
        return self.system_info_cache.get(session_id)
    
    def get_system_summary(self, session_id: str) -> str:
        """
        Génère un résumé système pour une session
        
        Args:
            session_id: ID de la session
        
        Returns:
            str: Résumé système formaté
        """
        try:
            system_info = self.system_info_cache.get(session_id)
            if not system_info:
                return f"[!] Aucune information système disponible pour {session_id}"
            
            basic = system_info.get('basic', {})
            security = system_info.get('security', {})
            
            summary_parts = []
            
            # Informations de base
            hostname = basic.get('hostname', 'Unknown')
            platform = basic.get('platform', 'Unknown')
            username = basic.get('username', 'Unknown')
            ip_addr = basic.get('ip_address', 'Unknown')
            
            summary_parts.append(f"Host: {hostname} ({ip_addr})")
            summary_parts.append(f"OS: {platform}")
            summary_parts.append(f"User: {username}")
            
            # Statut admin
            is_admin = security.get('is_admin', False)
            admin_status = "Admin" if is_admin else "User"
            summary_parts.append(f"Privileges: {admin_status}")
            
            # Antivirus
            antivirus = security.get('antivirus', [])
            if antivirus:
                av_name = antivirus[0] if len(antivirus) == 1 else f"{len(antivirus)} AV detected"
                summary_parts.append(f"AV: {av_name}")
            
            return " | ".join(summary_parts)
            
        except Exception as e:
            logger.error(f"Erreur génération résumé: {e}")
            return f"[!] Erreur résumé pour {session_id}"
    
    def compare_system_info(self, session_id_1: str, session_id_2: str) -> str:
        """
        Compare les informations système de deux sessions
        
        Args:
            session_id_1: ID de la première session
            session_id_2: ID de la deuxième session
        
        Returns:
            str: Comparaison formatée
        """
        try:
            info1 = self.system_info_cache.get(session_id_1)
            info2 = self.system_info_cache.get(session_id_2)
            
            if not info1 or not info2:
                return "[!] Informations manquantes pour la comparaison"
            
            comparison = []
            comparison.append("╔════════════════════════════════════════════════════════════╗")
            comparison.append("║                 COMPARAISON SYSTÈME                       ║")
            comparison.append("╠════════════════════════════════════════════════════════════╣")
            
            # Comparaison des champs de base
            basic1 = info1.get('basic', {})
            basic2 = info2.get('basic', {})
            
            fields_to_compare = [
                ('hostname', 'Hostname'),
                ('platform', 'Platform'),
                ('system', 'System'),
                ('username', 'Username'),
                ('ip_address', 'IP Address')
            ]
            
            for field, label in fields_to_compare:
                val1 = basic1.get(field, 'N/A')
                val2 = basic2.get(field, 'N/A')
                
                if val1 == val2:
                    status = "✓ Identique"
                else:
                    status = "✗ Différent"
                
                comparison.append(f"║ {label}:")
                comparison.append(f"║   {session_id_1}: {val1[:35]}")
                comparison.append(f"║   {session_id_2}: {val2[:35]}")
                comparison.append(f"║   Statut: {status}")
                comparison.append("║")
            
            comparison.append("╚════════════════════════════════════════════════════════════╝")
            
            return "\\n".join(comparison)
            
        except Exception as e:
            logger.error(f"Erreur comparaison système: {e}")
            return f"[!] Erreur lors de la comparaison: {e}"
    
    def get_statistics(self) -> Dict[str, Any]:
        """Retourne les statistiques du gestionnaire système"""
        return {
            'info_requests': self.info_requests,
            'cached_sessions': len(self.system_info_cache),
            'last_updates': len(self.last_update)
        }
    
    def clear_cache(self, session_id: str = None) -> int:
        """
        Efface le cache des informations système
        
        Args:
            session_id: ID de session (None = tout le cache)
        
        Returns:
            int: Nombre d'entrées supprimées
        """
        try:
            if session_id:
                # Suppression pour une session spécifique
                deleted = 0
                if session_id in self.system_info_cache:
                    del self.system_info_cache[session_id]
                    deleted += 1
                if session_id in self.last_update:
                    del self.last_update[session_id]
                
                return deleted
            else:
                # Suppression complète
                deleted = len(self.system_info_cache)
                self.system_info_cache.clear()
                self.last_update.clear()
                
                return deleted
                
        except Exception as e:
            logger.error(f"Erreur effacement cache: {e}")
            return 0
    
    def export_system_info(self, filepath: str, session_id: str = None) -> bool:
        """
        Exporte les informations système vers un fichier
        
        Args:
            filepath: Chemin du fichier d'export
            session_id: ID de session (None = toutes les sessions)
        
        Returns:
            bool: True si succès
        """
        try:
            # Données à exporter
            if session_id:
                if session_id not in self.system_info_cache:
                    return False
                export_data = {session_id: self.system_info_cache[session_id]}
            else:
                export_data = self.system_info_cache.copy()
            
            # Ajout des métadonnées
            export_with_meta = {
                'export_timestamp': datetime.now().isoformat(),
                'session_filter': session_id,
                'total_sessions': len(export_data),
                'system_info': export_data
            }
            
            # Sauvegarde
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(export_with_meta, f, indent=2, ensure_ascii=False)
            
            logger.info(f"Informations système exportées: {len(export_data)} sessions vers {filepath}")
            return True
            
        except Exception as e:
            logger.error(f"Erreur export système: {e}")
            return False