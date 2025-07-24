#!/usr/bin/env python3
"""
Generate SSL Certificates - Script de génération de certificats SSL
Génère les certificats auto-signés pour le chiffrement serveur-client
Usage académique uniquement
"""

import os
import sys
import argparse
from pathlib import Path
from datetime import datetime, timedelta
from typing import Tuple, Optional

try:
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    CRYPTOGRAPHY_AVAILABLE = True
except ImportError:
    CRYPTOGRAPHY_AVAILABLE = False

def create_certificate_authority() -> Tuple[rsa.RSAPrivateKey, x509.Certificate]:
    """
    Crée une autorité de certification (CA) auto-signée
    
    Returns:
        Tuple contenant la clé privée CA et le certificat CA
    """
    print("🔐 Génération de l'autorité de certification (CA)...")
    
    # Génération de la clé privée CA
    ca_private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    
    # Informations du certificat CA
    ca_subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "FR"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Ile-de-France"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Paris"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "RAT Project Academic CA"),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Cybersecurity Education"),
        x509.NameAttribute(NameOID.COMMON_NAME, "RAT Project Root CA"),
    ])
    
    # Création du certificat CA
    ca_certificate = x509.CertificateBuilder().subject_name(
        ca_subject
    ).issuer_name(
        ca_subject  # Auto-signé
    ).public_key(
        ca_private_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.utcnow()
    ).not_valid_after(
        datetime.utcnow() + timedelta(days=365)  # Valide 1 an
    ).add_extension(
        x509.SubjectAlternativeName([
            x509.DNSName("localhost"),
            x509.DNSName("rat-project-ca"),
        ]),
        critical=False,
    ).add_extension(
        x509.BasicConstraints(ca=True, path_length=0),
        critical=True,
    ).add_extension(
        x509.KeyUsage(
            key_cert_sign=True,
            crl_sign=True,
            digital_signature=False,
            content_commitment=False,
            key_encipherment=False,
            data_encipherment=False,
            key_agreement=False,
            encipher_only=False,
            decipher_only=False,
        ),
        critical=True,
    ).sign(ca_private_key, hashes.SHA256())
    
    print("✅ Autorité de certification créée")
    return ca_private_key, ca_certificate

def create_server_certificate(ca_private_key: rsa.RSAPrivateKey, 
                            ca_certificate: x509.Certificate,
                            server_name: str = "localhost") -> Tuple[rsa.RSAPrivateKey, x509.Certificate]:
    """
    Crée un certificat serveur signé par la CA
    
    Args:
        ca_private_key: Clé privée de la CA
        ca_certificate: Certificat de la CA
        server_name: Nom du serveur (CN)
    
    Returns:
        Tuple contenant la clé privée serveur et le certificat serveur
    """
    print(f"🖥️ Génération du certificat serveur pour '{server_name}'...")
    
    # Génération de la clé privée serveur
    server_private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    
    # Informations du certificat serveur
    server_subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "FR"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Ile-de-France"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Paris"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "RAT Project Academic Server"),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "C2 Server"),
        x509.NameAttribute(NameOID.COMMON_NAME, server_name),
    ])
    
    # Alternative names pour le serveur
    san_list = [
        x509.DNSName("localhost"),
        x509.DNSName("127.0.0.1"),
        x509.DNSName("rat-server"),
        x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
        x509.IPAddress(ipaddress.IPv4Address("0.0.0.0")),
    ]
    
    # Ajout du nom personnalisé si différent
    if server_name not in ["localhost", "127.0.0.1"]:
        try:
            import ipaddress
            # Test si c'est une IP
            ip = ipaddress.ip_address(server_name)
            san_list.append(x509.IPAddress(ip))
        except ValueError:
            # C'est un nom de domaine
            san_list.append(x509.DNSName(server_name))
    
    # Importation du module ipaddress si pas déjà fait
    import ipaddress
    
    # Création du certificat serveur
    server_certificate = x509.CertificateBuilder().subject_name(
        server_subject
    ).issuer_name(
        ca_certificate.subject
    ).public_key(
        server_private_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.utcnow()
    ).not_valid_after(
        datetime.utcnow() + timedelta(days=365)  # Valide 1 an
    ).add_extension(
        x509.SubjectAlternativeName(san_list),
        critical=False,
    ).add_extension(
        x509.BasicConstraints(ca=False, path_length=None),
        critical=True,
    ).add_extension(
        x509.KeyUsage(
            key_cert_sign=False,
            crl_sign=False,
            digital_signature=True,
            content_commitment=False,
            key_encipherment=True,
            data_encipherment=False,
            key_agreement=False,
            encipher_only=False,
            decipher_only=False,
        ),
        critical=True,
    ).add_extension(
        x509.ExtendedKeyUsage([
            x509.oid.ExtendedKeyUsageOID.SERVER_AUTH,
        ]),
        critical=True,
    ).sign(ca_private_key, hashes.SHA256())
    
    print("✅ Certificat serveur créé")
    return server_private_key, server_certificate

def create_client_certificate(ca_private_key: rsa.RSAPrivateKey, 
                            ca_certificate: x509.Certificate,
                            client_name: str = "rat-client") -> Tuple[rsa.RSAPrivateKey, x509.Certificate]:
    """
    Crée un certificat client signé par la CA
    
    Args:
        ca_private_key: Clé privée de la CA
        ca_certificate: Certificat de la CA
        client_name: Nom du client (CN)
    
    Returns:
        Tuple contenant la clé privée client et le certificat client
    """
    print(f"💻 Génération du certificat client pour '{client_name}'...")
    
    # Génération de la clé privée client
    client_private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    
    # Informations du certificat client
    client_subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "FR"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Ile-de-France"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Paris"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "RAT Project Academic Client"),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Agent"),
        x509.NameAttribute(NameOID.COMMON_NAME, client_name),
    ])
    
    # Création du certificat client
    client_certificate = x509.CertificateBuilder().subject_name(
        client_subject
    ).issuer_name(
        ca_certificate.subject
    ).public_key(
        client_private_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.utcnow()
    ).not_valid_after(
        datetime.utcnow() + timedelta(days=365)  # Valide 1 an
    ).add_extension(
        x509.BasicConstraints(ca=False, path_length=None),
        critical=True,
    ).add_extension(
        x509.KeyUsage(
            key_cert_sign=False,
            crl_sign=False,
            digital_signature=True,
            content_commitment=False,
            key_encipherment=True,
            data_encipherment=False,
            key_agreement=False,
            encipher_only=False,
            decipher_only=False,
        ),
        critical=True,
    ).add_extension(
        x509.ExtendedKeyUsage([
            x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH,
        ]),
        critical=True,
    ).sign(ca_private_key, hashes.SHA256())
    
    print("✅ Certificat client créé")
    return client_private_key, client_certificate

def save_certificate_files(output_dir: Path,
                         ca_private_key: rsa.RSAPrivateKey,
                         ca_certificate: x509.Certificate,
                         server_private_key: rsa.RSAPrivateKey,
                         server_certificate: x509.Certificate,
                         client_private_key: Optional[rsa.RSAPrivateKey] = None,
                         client_certificate: Optional[x509.Certificate] = None):
    """
    Sauvegarde tous les certificats et clés dans des fichiers
    
    Args:
        output_dir: Répertoire de sortie
        ca_private_key: Clé privée CA
        ca_certificate: Certificat CA
        server_private_key: Clé privée serveur
        server_certificate: Certificat serveur
        client_private_key: Clé privée client (optionnel)
        client_certificate: Certificat client (optionnel)
    """
    print(f"💾 Sauvegarde des certificats dans '{output_dir}'...")
    
    # Création du répertoire
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # Sauvegarde CA
    with open(output_dir / "ca-private-key.pem", "wb") as f:
        f.write(ca_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
    
    with open(output_dir / "ca-certificate.pem", "wb") as f:
        f.write(ca_certificate.public_bytes(serialization.Encoding.PEM))
    
    # Sauvegarde serveur
    with open(output_dir / "server-private-key.pem", "wb") as f:
        f.write(server_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
    
    with open(output_dir / "server-certificate.pem", "wb") as f:
        f.write(server_certificate.public_bytes(serialization.Encoding.PEM))
    
    # Sauvegarde client si fourni
    if client_private_key and client_certificate:
        with open(output_dir / "client-private-key.pem", "wb") as f:
            f.write(client_private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))
        
        with open(output_dir / "client-certificate.pem", "wb") as f:
            f.write(client_certificate.public_bytes(serialization.Encoding.PEM))
    
    # Création d'un fichier d'information
    info_content = f"""# Certificats SSL RAT Project
Générés le: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
Validité: 365 jours

## Fichiers générés:
- ca-certificate.pem         : Certificat de l'autorité de certification
- ca-private-key.pem         : Clé privée de la CA (À PROTÉGER)
- server-certificate.pem     : Certificat du serveur
- server-private-key.pem     : Clé privée du serveur (À PROTÉGER)
"""
    
    if client_private_key and client_certificate:
        info_content += """- client-certificate.pem     : Certificat du client
- client-private-key.pem     : Clé privée du client (À PROTÉGER)
"""
    
    info_content += """
## Usage:
1. Serveur: Utiliser server-certificate.pem et server-private-key.pem
2. Client: Utiliser ca-certificate.pem pour vérifier le serveur
3. Authentification mutuelle: Utiliser aussi client-certificate.pem

## Sécurité:
- Ces certificats sont auto-signés (usage éducatif uniquement)
- Les clés privées ne sont PAS chiffrées
- NE PAS utiliser en production
- Garder les clés privées confidentielles
"""
    
    with open(output_dir / "README-certificates.txt", "w", encoding="utf-8") as f:
        f.write(info_content)
    
    print("✅ Certificats sauvegardés")

def print_certificate_info(certificate: x509.Certificate, cert_type: str):
    """Affiche les informations d'un certificat"""
    print(f"\n📋 Informations certificat {cert_type}:")
    print(f"   Sujet: {certificate.subject.rfc4514_string()}")
    print(f"   Émetteur: {certificate.issuer.rfc4514_string()}")
    print(f"   Numéro de série: {certificate.serial_number}")
    print(f"   Valide du {certificate.not_valid_before} au {certificate.not_valid_after}")
    
    # Extensions importantes
    try:
        san = certificate.extensions.get_extension_for_oid(x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        san_values = [str(name) for name in san.value]
        print(f"   Noms alternatifs: {', '.join(san_values)}")
    except x509.ExtensionNotFound:
        pass

def main():
    """Fonction principale"""
    parser = argparse.ArgumentParser(description="Générateur de certificats SSL pour RAT Project")
    parser.add_argument(
        "--output-dir", "-o",
        type=str,
        default="server/data/ssl",
        help="Répertoire de sortie pour les certificats"
    )
    parser.add_argument(
        "--server-name", "-s",
        type=str,
        default="localhost",
        help="Nom du serveur pour le certificat"
    )
    parser.add_argument(
        "--client-name", "-c",
        type=str,
        default="rat-client",
        help="Nom du client pour le certificat"
    )
    parser.add_argument(
        "--no-client",
        action="store_true",
        help="Ne pas générer de certificat client"
    )
    parser.add_argument(
        "--info",
        action="store_true",
        help="Afficher les informations détaillées des certificats"
    )
    
    args = parser.parse_args()
    
    # Vérification de la disponibilité de cryptography
    if not CRYPTOGRAPHY_AVAILABLE:
        print("❌ Erreur: Le module 'cryptography' n'est pas installé")
        print("Installation: pip install cryptography")
        sys.exit(1)
    
    print("🔒 Générateur de certificats SSL RAT Project")
    print("=" * 50)
    
    try:
        # Création de l'autorité de certification
        ca_private_key, ca_certificate = create_certificate_authority()
        
        # Création du certificat serveur
        server_private_key, server_certificate = create_server_certificate(
            ca_private_key, ca_certificate, args.server_name
        )
        
        # Création du certificat client (optionnel)
        client_private_key = None
        client_certificate = None
        if not args.no_client:
            client_private_key, client_certificate = create_client_certificate(
                ca_private_key, ca_certificate, args.client_name
            )
        
        # Sauvegarde des fichiers
        output_path = Path(args.output_dir)
        save_certificate_files(
            output_path,
            ca_private_key, ca_certificate,
            server_private_key, server_certificate,
            client_private_key, client_certificate
        )
        
        # Affichage des informations si demandé
        if args.info:
            print_certificate_info(ca_certificate, "CA")
            print_certificate_info(server_certificate, "Serveur")
            if client_certificate:
                print_certificate_info(client_certificate, "Client")
        
        print("\n🎉 Génération des certificats terminée !")
        print(f"📁 Fichiers sauvegardés dans: {output_path.absolute()}")
        print(f"📖 Consultez {output_path}/README-certificates.txt pour plus d'infos")
        
        # Instructions d'usage
        print("\n🚀 Instructions d'usage:")
        print(f"   Serveur: python server/main.py --ssl --cert-file {output_path}/server-certificate.pem --key-file {output_path}/server-private-key.pem")
        print(f"   Client:  python client/main.py --ssl --ca-file {output_path}/ca-certificate.pem")
        
    except Exception as e:
        print(f"❌ Erreur lors de la génération: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()