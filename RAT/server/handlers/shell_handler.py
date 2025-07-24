"""
Shell Handler - Gestionnaire des commandes shell côté serveur
Traitement et logging des réponses aux commandes shell
"""

import logging
from datetime import datetime
from typing import Dict, Any, List
from pathlib import Path

from shared.helpers import format_bytes, sanitize_data

logger = logging.getLogger(__name__)

class ShellHandler:
    """Gestionnaire des commandes shell pour le serveur"""
    
    def __init__(self):
        # Historique des commandes
        self.command_history = []
        self.max_history_size = 1000
        
        # Statistiques
        self.commands_executed = 0
        self.successful_commands = 0
        self.failed_commands = 0
        self.total_execution_time = 0
        
        # Commandes dangereuses à surveiller
        self.dangerous_commands = [
            'rm -rf', 'del /s', 'format', 'dd if=', 'mkfs',
            'shutdown', 'reboot', 'halt', 'poweroff'
        ]
        
        logger.info("ShellHandler initialisé")
    
    def handle_shell_response(self, session, response_data: Dict[str, Any]) -> str:
        """
        Traite la réponse d'une commande shell
        
        Args:
            session: Session client
            response_data: Données de réponse de la commande
            
        Returns:
            str: Sortie formatée pour affichage
        """
        try:
            # Extraction des données de réponse
            command = response_data.get('command', 'Unknown')
            output = response_data.get('output', '')
            status = response_data.get('status', 'unknown')
            return_code = response_data.get('return_code', -1)
            execution_time = response_data.get('execution_time', 0)
            timestamp = response_data.get('timestamp', datetime.now().isoformat())
            
            # Ajout à l'historique
            self._add_to_history(session.id, command, status, output, execution_time, timestamp)
            
            # Mise à jour des statistiques
            self._update_statistics(status, execution_time)
            
            # Vérification des commandes dangereuses
            if self._is_dangerous_command(command):
                self._log_security_event(session.id, command, output)
            
            # Formatage de la sortie
            if status == 'success':
                if not output.strip():
                    return "[*] Commande exécutée (aucune sortie)"
                return output
            elif status == 'timeout':
                return f"[!] Commande interrompue (timeout)\\n{output}" if output else "[!] Commande interrompue (timeout)"
            else:  # error
                return f"[!] Erreur (code: {return_code})\\n{output}" if output else f"[!] Erreur d'exécution (code: {return_code})"
                
        except Exception as e:
            logger.error(f"Erreur dans handle_shell_response: {e}")
            return f"[!] Erreur lors du traitement de la réponse: {e}"
    
    def _add_to_history(self, session_id: str, command: str, status: str, output: str, execution_time: float, timestamp: str):
        """Ajoute une commande à l'historique"""
        try:
            # Limitation de la taille de la sortie pour l'historique
            truncated_output = output[:500] + "..." if len(output) > 500 else output
            
            history_entry = {
                'session_id': session_id,
                'command': command,
                'status': status,
                'output': truncated_output,
                'execution_time': execution_time,
                'timestamp': timestamp,
                'logged_at': datetime.now().isoformat()
            }
            
            self.command_history.append(history_entry)
            
            # Limitation de la taille de l'historique
            if len(self.command_history) > self.max_history_size:
                self.command_history = self.command_history[-self.max_history_size:]
                
        except Exception as e:
            logger.warning(f"Erreur ajout historique: {e}")
    
    def _update_statistics(self, status: str, execution_time: float):
        """Met à jour les statistiques"""
        self.commands_executed += 1
        self.total_execution_time += execution_time
        
        if status == 'success':
            self.successful_commands += 1
        else:
            self.failed_commands += 1
    
    def _is_dangerous_command(self, command: str) -> bool:
        """Vérifie si une commande est dangereuse"""
        command_lower = command.lower()
        return any(dangerous in command_lower for dangerous in self.dangerous_commands)
    
    def _log_security_event(self, session_id: str, command: str, output: str):
        """Log un événement de sécurité pour commande dangereuse"""
        logger.warning(
            f"SECURITY EVENT - Dangerous command executed by {session_id}: {command}",
            extra={'session_id': session_id, 'command': command}
        )
    
    def get_command_history(self, session_id: str = None, limit: int = 50) -> str:
        """
        Récupère l'historique des commandes
        
        Args:
            session_id: ID de session pour filtrer (optionnel)
            limit: Nombre maximum de commandes à retourner
            
        Returns:
            str: Historique formaté
        """
        try:
            # Filtrage par session si demandé
            if session_id:
                filtered_history = [
                    entry for entry in self.command_history 
                    if entry['session_id'] == session_id
                ]
            else:
                filtered_history = self.command_history
            
            if not filtered_history:
                return "Aucun historique de commandes"
            
            # Limitation et tri (plus récent en premier)
            recent_history = filtered_history[-limit:]
            recent_history.reverse()
            
            # Formatage
            output = f"Historique des commandes ({len(recent_history)} entrées):\\n"
            output += "=" * 80 + "\\n"
            
            for i, entry in enumerate(recent_history, 1):
                status_icon = "✓" if entry['status'] == 'success' else "✗"
                time_str = entry['timestamp'].split('T')[1][:8] if 'T' in entry['timestamp'] else entry['timestamp'][:8]
                
                output += (
                    f"{i:2d}. [{time_str}] {status_icon} {entry['session_id'][:8]} > "
                    f"{entry['command'][:40]}\\n"
                )
                
                if entry['output'] and len(entry['output'].strip()) > 0:
                    # Première ligne de la sortie seulement
                    first_line = entry['output'].split('\\n')[0][:60]
                    output += f"     Output: {first_line}\\n"
                
                output += "\\n"
            
            return output
            
        except Exception as e:
            logger.error(f"Erreur dans get_command_history: {e}")
            return f"[!] Erreur lors de la récupération de l'historique: {e}"
    
    def get_command_stats(self) -> str:
        """Retourne les statistiques des commandes"""
        try:
            if self.commands_executed == 0:
                return "Aucune commande exécutée"
            
            avg_execution_time = self.total_execution_time / self.commands_executed
            success_rate = (self.successful_commands / self.commands_executed) * 100
            
            # Top commandes par session
            session_stats = {}
            for entry in self.command_history:
                session_id = entry['session_id']
                if session_id not in session_stats:
                    session_stats[session_id] = 0
                session_stats[session_id] += 1
            
            # Commandes les plus utilisées
            command_counts = {}
            for entry in self.command_history:
                base_command = entry['command'].split()[0] if entry['command'].split() else 'unknown'
                if base_command not in command_counts:
                    command_counts[base_command] = 0
                command_counts[base_command] += 1
            
            top_commands = sorted(command_counts.items(), key=lambda x: x[1], reverse=True)[:5]
            top_sessions = sorted(session_stats.items(), key=lambda x: x[1], reverse=True)[:5]
            
            output = f"""
╔════════════════════════════════════════╗
║           STATISTIQUES SHELL           ║
╠════════════════════════════════════════╣
║ Commandes exécutées: {self.commands_executed:14d} ║
║ Succès: {self.successful_commands:26d} ║
║ Échecs: {self.failed_commands:26d} ║
║ Taux de succès: {success_rate:17.1f}% ║
║ Temps moyen: {avg_execution_time:19.3f}s ║
║ Temps total: {self.total_execution_time:19.1f}s ║
╚════════════════════════════════════════╝

Top commandes:"""
            
            for i, (cmd, count) in enumerate(top_commands, 1):
                output += f"\\n  {i}. {cmd[:20]:20s} ({count:3d} fois)"
            
            output += "\\n\\nTop sessions:"
            for i, (session, count) in enumerate(top_sessions, 1):
                output += f"\\n  {i}. {session[:16]:16s} ({count:3d} commandes)"
            
            return output
            
        except Exception as e:
            logger.error(f"Erreur dans get_command_stats: {e}")
            return f"[!] Erreur lors de la récupération des statistiques: {e}"
    
    def search_command_history(self, search_term: str, session_id: str = None) -> str:
        """
        Recherche dans l'historique des commandes
        
        Args:
            search_term: Terme à rechercher
            session_id: ID de session pour filtrer (optionnel)
            
        Returns:
            str: Résultats de recherche formatés
        """
        try:
            if not search_term:
                return "[!] Terme de recherche requis"
            
            # Filtrage par session si demandé
            history_to_search = self.command_history
            if session_id:
                history_to_search = [
                    entry for entry in self.command_history 
                    if entry['session_id'] == session_id
                ]
            
            # Recherche
            matches = [
                entry for entry in history_to_search
                if search_term.lower() in entry['command'].lower() or 
                   search_term.lower() in entry['output'].lower()
            ]
            
            if not matches:
                return f"Aucun résultat trouvé pour: {search_term}"
            
            # Formatage des résultats
            output = f"Résultats de recherche pour '{search_term}' ({len(matches)} trouvés):\\n"
            output += "=" * 70 + "\\n"
            
            for i, entry in enumerate(matches[-20:], 1):  # 20 derniers résultats
                status_icon = "✓" if entry['status'] == 'success' else "✗"
                time_str = entry['timestamp'].split('T')[1][:8] if 'T' in entry['timestamp'] else entry['timestamp'][:8]
                
                output += (
                    f"{i:2d}. [{time_str}] {status_icon} {entry['session_id'][:8]} > "
                    f"{entry['command'][:50]}\\n"
                )
            
            return output
            
        except Exception as e:
            logger.error(f"Erreur dans search_command_history: {e}")
            return f"[!] Erreur lors de la recherche: {e}"
    
    def export_command_history(self, session_id: str = None, format: str = 'txt') -> str:
        """
        Exporte l'historique des commandes
        
        Args:
            session_id: ID de session pour filtrer (optionnel)
            format: Format d'export ('txt', 'csv', 'json')
            
        Returns:
            str: Message de résultat
        """
        try:
            # Filtrage par session si demandé
            history_to_export = self.command_history
            if session_id:
                history_to_export = [
                    entry for entry in self.command_history 
                    if entry['session_id'] == session_id
                ]
            
            if not history_to_export:
                return "Aucun historique à exporter"
            
            # Génération du nom de fichier
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            session_suffix = f"_{session_id[:8]}" if session_id else "_all"
            filename = f"command_history{session_suffix}_{timestamp}.{format}"
            export_path = Path("logs") / filename
            
            # Export selon le format
            if format == 'txt':
                self._export_txt(export_path, history_to_export)
            elif format == 'csv':
                self._export_csv(export_path, history_to_export)
            elif format == 'json':
                self._export_json(export_path, history_to_export)
            else:
                return f"[!] Format non supporté: {format}"
            
            return f"[+] Historique exporté: {filename} ({len(history_to_export)} entrées)"
            
        except Exception as e:
            logger.error(f"Erreur dans export_command_history: {e}")
            return f"[!] Erreur lors de l'export: {e}"
    
    def _export_txt(self, file_path: Path, history: List[Dict[str, Any]]):
        """Exporte l'historique en format texte"""
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(f"# Command History Export\\n")
            f.write(f"# Generated on: {datetime.now().isoformat()}\\n")
            f.write(f"# Total entries: {len(history)}\\n")
            f.write("=" * 80 + "\\n\\n")
            
            for entry in history:
                f.write(f"Timestamp: {entry['timestamp']}\\n")
                f.write(f"Session: {entry['session_id']}\\n")
                f.write(f"Command: {entry['command']}\\n")
                f.write(f"Status: {entry['status']}\\n")
                f.write(f"Execution Time: {entry['execution_time']}s\\n")
                f.write(f"Output:\\n{entry['output']}\\n")
                f.write("-" * 40 + "\\n\\n")
    
    def _export_csv(self, file_path: Path, history: List[Dict[str, Any]]):
        """Exporte l'historique en format CSV"""
        import csv
        
        with open(file_path, 'w', encoding='utf-8', newline='') as f:
            writer = csv.writer(f)
            
            # En-têtes
            writer.writerow([
                'Timestamp', 'Session ID', 'Command', 'Status', 
                'Execution Time', 'Output Preview'
            ])
            
            # Données
            for entry in history:
                output_preview = entry['output'][:100].replace('\\n', ' ') if entry['output'] else ''
                writer.writerow([
                    entry['timestamp'],
                    entry['session_id'], 
                    entry['command'],
                    entry['status'],
                    entry['execution_time'],
                    output_preview
                ])
    
    def _export_json(self, file_path: Path, history: List[Dict[str, Any]]):
        """Exporte l'historique en format JSON"""
        import json
        
        export_data = {
            'export_info': {
                'generated_at': datetime.now().isoformat(),
                'total_entries': len(history),
                'format_version': '1.0'
            },
            'command_history': [sanitize_data(entry) for entry in history]
        }
        
        with open(file_path, 'w', encoding='utf-8') as f:
            json.dump(export_data, f, indent=2, ensure_ascii=False)
    
    def clear_history(self, session_id: str = None) -> str:
        """
        Efface l'historique des commandes
        
        Args:
            session_id: ID de session pour filtrer (optionnel)
            
        Returns:
            str: Message de résultat
        """
        try:
            if session_id:
                # Suppression pour une session spécifique
                original_count = len(self.command_history)
                self.command_history = [
                    entry for entry in self.command_history 
                    if entry['session_id'] != session_id
                ]
                removed_count = original_count - len(self.command_history)
                return f"[+] Historique effacé pour {session_id}: {removed_count} entrées supprimées"
            else:
                # Suppression complète
                removed_count = len(self.command_history)
                self.command_history.clear()
                return f"[+] Historique complet effacé: {removed_count} entrées supprimées"
                
        except Exception as e:
            logger.error(f"Erreur dans clear_history: {e}")
            return f"[!] Erreur lors de l'effacement: {e}"
    
    def get_handler_info(self) -> Dict[str, Any]:
        """Retourne les informations du gestionnaire shell"""
        return {
            'commands_executed': self.commands_executed,
            'successful_commands': self.successful_commands,
            'failed_commands': self.failed_commands,
            'total_execution_time': self.total_execution_time,
            'history_entries': len(self.command_history),
            'max_history_size': self.max_history_size,
            'dangerous_commands_monitored': len(self.dangerous_commands)
        }