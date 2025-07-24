"""
Shell Handler - Gestionnaire des commandes shell côté serveur
Gestion et formatage des réponses de commandes shell
"""

import re
import html
import logging
from datetime import datetime
from typing import Dict, Any, List, Optional

logger = logging.getLogger(__name__)

class ShellHandler:
    """Gestionnaire des commandes shell du serveur"""
    
    def __init__(self):
        # Historique des commandes
        self.command_history = []
        self.max_history = 1000
        
        # Statistiques
        self.commands_executed = 0
        self.successful_commands = 0
        self.failed_commands = 0
        
        logger.info("ShellHandler initialisé")
    
    def process_shell_response(self, session, command: str, response_data: Dict[str, Any]) -> str:
        """
        Traite la réponse d'une commande shell
        
        Args:
            session: Session de l'agent
            command: Commande exécutée
            response_data: Données de réponse
        
        Returns:
            str: Réponse formatée pour affichage
        """
        try:
            status = response_data.get('status', 'unknown')
            output = response_data.get('output', '')
            return_code = response_data.get('return_code', -1)
            execution_time = response_data.get('execution_time', 0)
            
            # Enregistrement dans l'historique
            self._add_to_history(session.id, command, response_data)
            
            # Mise à jour des statistiques
            self.commands_executed += 1
            if status == 'success':
                self.successful_commands += 1
            else:
                self.failed_commands += 1
            
            # Formatage de la réponse
            if status == 'timeout':
                formatted_output = self._format_timeout_response(command, output, execution_time)
            elif status == 'error':
                formatted_output = self._format_error_response(command, output, return_code)
            elif status == 'success':
                formatted_output = self._format_success_response(command, output, return_code, execution_time)
            else:
                formatted_output = f"[!] Statut inconnu: {status}\\n{output}"
            
            return formatted_output
            
        except Exception as e:
            logger.error(f"Erreur traitement réponse shell: {e}")
            return f"[!] Erreur lors du traitement de la réponse: {e}"
    
    def _format_success_response(self, command: str, output: str, return_code: int, execution_time: float) -> str:
        """Formate une réponse de succès"""
        if not output or output.strip() == "[Aucune sortie]":
            return f"[*] Commande exécutée avec succès (code: {return_code}, temps: {execution_time:.2f}s)"
        
        # Nettoyage et formatage de la sortie
        cleaned_output = self._clean_output(output)
        
        header = f"[*] Résultat de: {command} (code: {return_code}, temps: {execution_time:.2f}s)"
        separator = "-" * min(len(header), 80)
        
        return f"{header}\\n{separator}\\n{cleaned_output}"
    
    def _format_error_response(self, command: str, output: str, return_code: int) -> str:
        """Formate une réponse d'erreur"""
        cleaned_output = self._clean_output(output)
        
        header = f"[!] Erreur lors de l'exécution de: {command} (code: {return_code})"
        separator = "-" * min(len(header), 80)
        
        return f"{header}\\n{separator}\\n{cleaned_output}"
    
    def _format_timeout_response(self, command: str, output: str, execution_time: float) -> str:
        """Formate une réponse de timeout"""
        header = f"[!] Commande interrompue (timeout après {execution_time:.1f}s): {command}"
        separator = "-" * min(len(header), 80)
        
        if output:
            cleaned_output = self._clean_output(output)
            return f"{header}\\n{separator}\\n{cleaned_output}\\n[!] Commande interrompue par timeout"
        else:
            return f"{header}\\n[!] Aucune sortie avant interruption"
    
    def _clean_output(self, output: str) -> str:
        """
        Nettoie la sortie de commande pour l'affichage
        
        Args:
            output: Sortie brute
        
        Returns:
            str: Sortie nettoyée
        """
        if not output:
            return ""
        
        # Suppression des caractères de contrôle dangereux
        # Garder seulement les caractères printables et quelques caractères de contrôle
        cleaned = ''.join(char for char in output if ord(char) >= 32 or char in '\\n\\r\\t')
        
        # Limitation de la taille d'affichage
        max_display_length = 10000  # 10KB max pour l'affichage
        if len(cleaned) > max_display_length:
            cleaned = cleaned[:max_display_length] + "\\n\\n[...SORTIE TRONQUÉE...]"
        
        # Conversion des caractères HTML pour éviter l'injection
        cleaned = html.escape(cleaned, quote=False)
        
        return cleaned
    
    def _add_to_history(self, session_id: str, command: str, response_data: Dict[str, Any]):
        """Ajoute une commande à l'historique"""
        try:
            history_entry = {
                'timestamp': datetime.now().isoformat(),
                'session_id': session_id,
                'command': command,
                'status': response_data.get('status'),
                'return_code': response_data.get('return_code'),
                'execution_time': response_data.get('execution_time'),
                'output_length': len(response_data.get('output', ''))
            }
            
            self.command_history.append(history_entry)
            
            # Limitation de la taille de l'historique
            if len(self.command_history) > self.max_history:
                self.command_history.pop(0)
                
        except Exception as e:
            logger.error(f"Erreur ajout historique: {e}")
    
    def get_command_history(self, session_id: str = None, limit: int = 50) -> List[Dict[str, Any]]:
        """
        Récupère l'historique des commandes
        
        Args:
            session_id: ID de session (None = toutes)
            limit: Nombre maximum d'entrées
        
        Returns:
            List: Historique des commandes
        """
        try:
            history = self.command_history
            
            # Filtrage par session si demandé
            if session_id:
                history = [entry for entry in history if entry['session_id'] == session_id]
            
            # Tri par timestamp (plus récent en premier)
            history = sorted(history, key=lambda x: x['timestamp'], reverse=True)
            
            # Limitation du nombre d'entrées
            return history[:limit]
            
        except Exception as e:
            logger.error(f"Erreur récupération historique: {e}")
            return []
    
    def get_command_statistics(self, session_id: str = None) -> Dict[str, Any]:
        """
        Récupère les statistiques des commandes
        
        Args:
            session_id: ID de session (None = toutes)
        
        Returns:
            Dict: Statistiques
        """
        try:
            if session_id:
                # Statistiques pour une session spécifique
                session_history = [entry for entry in self.command_history if entry['session_id'] == session_id]
                
                stats = {
                    'session_id': session_id,
                    'total_commands': len(session_history),
                    'successful_commands': len([e for e in session_history if e['status'] == 'success']),
                    'failed_commands': len([e for e in session_history if e['status'] == 'error']),
                    'timeout_commands': len([e for e in session_history if e['status'] == 'timeout'])
                }
                
                # Temps d'exécution moyen
                execution_times = [e['execution_time'] for e in session_history if e.get('execution_time')]
                if execution_times:
                    stats['avg_execution_time'] = sum(execution_times) / len(execution_times)
                else:
                    stats['avg_execution_time'] = 0
                
                # Commandes les plus utilisées
                commands = [e['command'].split()[0] if e['command'] else 'unknown' for e in session_history]
                command_counts = {}
                for cmd in commands:
                    command_counts[cmd] = command_counts.get(cmd, 0) + 1
                
                stats['top_commands'] = sorted(command_counts.items(), key=lambda x: x[1], reverse=True)[:10]
                
            else:
                # Statistiques globales
                stats = {
                    'total_commands': self.commands_executed,
                    'successful_commands': self.successful_commands,
                    'failed_commands': self.failed_commands,
                    'timeout_commands': self.commands_executed - self.successful_commands - self.failed_commands,
                    'history_entries': len(self.command_history)
                }
                
                # Taux de succès
                if self.commands_executed > 0:
                    stats['success_rate'] = (self.successful_commands / self.commands_executed) * 100
                else:
                    stats['success_rate'] = 0
            
            return stats
            
        except Exception as e:
            logger.error(f"Erreur calcul statistiques: {e}")
            return {}
    
    def suggest_commands(self, partial_command: str, session_id: str = None) -> List[str]:
        """
        Suggère des commandes basées sur l'historique
        
        Args:
            partial_command: Début de commande
            session_id: ID de session pour filtrer l'historique
        
        Returns:
            List: Suggestions de commandes
        """
        try:
            if not partial_command:
                return []
            
            # Récupération de l'historique approprié
            if session_id:
                history = [entry for entry in self.command_history if entry['session_id'] == session_id]
            else:
                history = self.command_history
            
            # Extraction des commandes uniques
            commands = list(set([entry['command'] for entry in history if entry.get('command')]))
            
            # Filtrage des suggestions
            suggestions = []
            partial_lower = partial_command.lower()
            
            for command in commands:
                if command.lower().startswith(partial_lower):
                    suggestions.append(command)
            
            # Tri par fréquence d'utilisation
            command_counts = {}
            for entry in history:
                cmd = entry.get('command', '')
                if cmd in suggestions:
                    command_counts[cmd] = command_counts.get(cmd, 0) + 1
            
            suggestions.sort(key=lambda x: command_counts.get(x, 0), reverse=True)
            
            return suggestions[:10]  # Maximum 10 suggestions
            
        except Exception as e:
            logger.error(f"Erreur suggestions commandes: {e}")
            return []
    
    def format_command_help(self) -> str:
        """Retourne l'aide des commandes shell"""
        help_text = """
╔═══════════════════════════════════════════════════════════════╗
║                     AIDE COMMANDES SHELL                     ║
╠═══════════════════════════════════════════════════════════════╣
║ USAGE: shell <commande>                                       ║
║                                                               ║
║ EXEMPLES:                                                     ║
║   shell dir                    - Liste les fichiers (Windows)║
║   shell ls -la                 - Liste les fichiers (Linux)  ║
║   shell whoami                 - Utilisateur courant         ║
║   shell hostname               - Nom de la machine           ║
║   shell netstat -an            - Connexions réseau           ║
║   shell ps aux                 - Processus en cours (Linux)  ║
║   shell tasklist               - Processus en cours (Windows)║
║                                                               ║
║ LIMITATIONS DE SÉCURITÉ:                                      ║
║   - Commandes destructives bloquées                          ║
║   - Timeout automatique (30s)                                ║
║   - Sortie limitée (10KB max)                                ║
║   - Certains privilèges peuvent être requis                  ║
╚═══════════════════════════════════════════════════════════════╝
        """
        return help_text.strip()
    
    def clear_history(self, session_id: str = None) -> int:
        """
        Efface l'historique des commandes
        
        Args:
            session_id: ID de session (None = tout l'historique)
        
        Returns:
            int: Nombre d'entrées supprimées
        """
        try:
            if session_id:
                # Suppression pour une session spécifique
                original_count = len(self.command_history)
                self.command_history = [entry for entry in self.command_history if entry['session_id'] != session_id]
                deleted_count = original_count - len(self.command_history)
            else:
                # Suppression complète
                deleted_count = len(self.command_history)
                self.command_history.clear()
                
                # Reset des statistiques
                self.commands_executed = 0
                self.successful_commands = 0
                self.failed_commands = 0
            
            logger.info(f"Historique effacé: {deleted_count} entrées supprimées")
            return deleted_count
            
        except Exception as e:
            logger.error(f"Erreur effacement historique: {e}")
            return 0
    
    def export_history(self, filepath: str, session_id: str = None) -> bool:
        """
        Exporte l'historique vers un fichier
        
        Args:
            filepath: Chemin du fichier d'export
            session_id: ID de session (None = tout l'historique)
        
        Returns:
            bool: True si succès
        """
        try:
            import json
            
            # Récupération de l'historique à exporter
            if session_id:
                history_to_export = [entry for entry in self.command_history if entry['session_id'] == session_id]
            else:
                history_to_export = self.command_history
            
            # Ajout des métadonnées d'export
            export_data = {
                'export_timestamp': datetime.now().isoformat(),
                'session_filter': session_id,
                'total_entries': len(history_to_export),
                'history': history_to_export
            }
            
            # Sauvegarde
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(export_data, f, indent=2, ensure_ascii=False)
            
            logger.info(f"Historique exporté: {len(history_to_export)} entrées vers {filepath}")
            return True
            
        except Exception as e:
            logger.error(f"Erreur export historique: {e}")
            return False