#!/usr/bin/env python3
"""
RAT Server - Point d'entrée principal
Projet académique cybersécurité
"""

import sys
import argparse
from pathlib import Path

# Ajout du répertoire parent au path
sys.path.append(str(Path(__file__).parent.parent))

from server.core.server import RATServer
from server.utils.logger import setup_logger
from server.utils.config import ServerConfig

def parse_arguments():
    """Parse les arguments de ligne de commande"""
    parser = argparse.ArgumentParser(description="RAT Server - Administration à distance")
    parser.add_argument(
        '--host', 
        default='0.0.0.0', 
        help='Adresse d\'écoute (défaut: 0.0.0.0)'
    )
    parser.add_argument(
        '--port', 
        type=int, 
        default=8888, 
        help='Port d\'écoute (défaut: 8888)'
    )
    parser.add_argument(
        '--ssl', 
        action='store_true', 
        help='Activer le chiffrement SSL/TLS'
    )
    parser.add_argument(
        '--debug', 
        action='store_true', 
        help='Mode debug (logs verbeux)'
    )
    parser.add_argument(
        '--config', 
        help='Fichier de configuration personnalisé'
    )
    return parser.parse_args()

def print_banner():
    """Affiche la bannière du serveur"""
    banner = """
    ██████╗  █████╗ ████████╗    ███████╗███████╗██████╗ ██╗   ██╗███████╗██████╗ 
    ██╔══██╗██╔══██╗╚══██╔══╝    ██╔════╝██╔════╝██╔══██╗██║   ██║██╔════╝██╔══██╗
    ██████╔╝███████║   ██║       ███████╗█████╗  ██████╔╝██║   ██║█████╗  ██████╔╝
    ██╔══██╗██╔══██║   ██║       ╚════██║██╔══╝  ██╔══██╗╚██╗ ██╔╝██╔══╝  ██╔══██╗
    ██║  ██║██║  ██║   ██║       ███████║███████╗██║  ██║ ╚████╔╝ ███████╗██║  ██║
    ╚═╝  ╚═╝╚═╝  ╚═╝   ╚═╝       ╚══════╝╚══════╝╚═╝  ╚═╝  ╚═══╝  ╚══════╝╚═╝  ╚═╝
    
    Remote Administration Tool - Version 1.0
    Projet académique cybersécurité
    ⚠️  Usage éducatif uniquement ⚠️
    """
    print(banner)

def main():
    """Fonction principale"""
    print_banner()
    
    # Parse des arguments
    args = parse_arguments()
    
    # Configuration du logger
    logger = setup_logger(debug=args.debug)
    
    # Chargement de la configuration
    config = ServerConfig(config_file=args.config)
    
    # Mise à jour de la config avec les arguments CLI
    config.HOST = args.host
    config.PORT = args.port
    config.USE_SSL = args.ssl
    config.DEBUG = args.debug
    
    logger.info("Démarrage du serveur RAT")
    logger.info(f"Configuration: {args.host}:{args.port} (SSL: {args.ssl})")
    
    try:
        # Création et démarrage du serveur
        server = RATServer(config)
        server.start()
        
    except KeyboardInterrupt:
        logger.info("Arrêt du serveur demandé par l'utilisateur")
    except Exception as e:
        logger.error(f"Erreur fatale: {e}")
        sys.exit(1)
    finally:
        logger.info("Serveur arrêté")

if __name__ == "__main__":
    main()