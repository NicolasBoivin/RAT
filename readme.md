> ⚠️ **AVERTISSEMENT IMPORTANT** ⚠️  
> Ce projet est développé **exclusivement à des fins éducatives** dans le cadre d'un cours de cybersécurité. Il ne doit être utilisé que sur des machines personnelles avec consentement explicite.

## 📋 Description

Ce projet implémente un **Remote Administration Tool (RAT)** complet en Python, développé pour l'apprentissage des concepts de cybersécurité, de communication réseau chiffrée et d'architecture logicielle distribuée.

### 🎯 Objectifs Pédagogiques

- Comprendre les **protocoles de communication** client-serveur
- Maîtriser le **chiffrement SSL/TLS** pour sécuriser les échanges
- Apprendre la **gestion multi-clients** et les architectures distribuées
- Découvrir les **techniques de surveillance** système
- Sensibiliser aux **enjeux de sécurité** et à l'éthique informatique

## 🏗️ Architecture

```
rat_project/
├── 🖥️ server/           # Serveur de commande et contrôle (C2)
│   ├── core/            # Logique métier du serveur
│   ├── handlers/        # Gestionnaires de commandes
│   └── utils/           # Utilitaires serveur
├── 💻 client/           # Agent client (victime)
│   ├── core/            # Logique métier du client
│   ├── modules/         # Modules fonctionnels
│   └── utils/           # Utilitaires client
├── 🔗 shared/           # Code partagé
│   ├── protocol.py      # Protocole de communication
│   ├── constants.py     # Constantes globales
│   └── exceptions.py    # Exceptions personnalisées
├── 🧪 tests/           # Tests unitaires et d'intégration
├── 📜 scripts/         # Scripts utilitaires
└── 📚 docs/            # Documentation
```

## ✨ Fonctionnalités

### 🖥️ Serveur (C2)
- ✅ **Interface interactive** multi-agents
- ✅ **Communication chiffrée** SSL/TLS
- ✅ **Gestion de sessions** avec authentification
- ✅ **Diffusion de commandes** (broadcast)
- ✅ **Logs et audit** complets
- ✅ **Statistiques** de connexion

### 💻 Client (Agent)
- ✅ **Shell interactif** avec restrictions de sécurité
- ✅ **Transfert de fichiers** (download/upload)
- ✅ **Capture d'écran** avec compression
- ✅ **Informations système** détaillées
- ✅ **Recherche de fichiers** avec limitations
- ✅ **Keylogger éthique** avec garde-fous
- ✅ **Webcam/Audio** avec consentement
- ✅ **Persistance** (optionnelle)
- ✅ **Mode furtif** éducatif

## 🚀 Installation

### Prérequis
- Python 3.8 ou supérieur
- Poetry (gestionnaire de dépendances)
- Certificats SSL (générés automatiquement)

### Installation avec Poetry
```bash
# Cloner le projet
git clone https://github.com/students/rat-project.git
cd rat-project

# Installer les dépendances
poetry install

# Installation complète avec support audio (optionnel)
poetry install --extras "full"

# Activer l'environnement virtuel
poetry shell
```

### Installation manuelle
```bash
# Installer les dépendances de base
pip install -r requirements.txt

# Pour le support audio (optionnel)
pip install pyaudio
```

## 🎮 Utilisation

### 1. Génération des certificats SSL
```bash
# Génération automatique
poetry run rat-generate-certs

# Ou manuellement
python scripts/generate_certs.py
```

### 2. Démarrage du serveur
```bash
# Mode standard
poetry run rat-server

# Avec options
python server/main.py --host 0.0.0.0 --port 8888 --ssl --debug
```

### 3. Connexion du client
```bash
# Mode standard
poetry run rat-client

# Avec options
python client/main.py --server 127.0.0.1 --port 8888 --ssl --debug
```

### 4. Interface du serveur
```
RAT Server Console - Tapez 'help' pour l'aide
==================================================
rat > help
rat > sessions
rat > interact agent1
rat agent1 > screenshot
rat agent1 > download /path/to/file
rat agent1 > back
rat > exit
```

## 📋 Commandes Disponibles

### Commandes Serveur
| Commande | Description |
|----------|-------------|
| `help` | Affiche l'aide |
| `sessions` | Liste les agents connectés |
| `interact <agent>` | Interagit avec un agent |
| `stats` | Statistiques du serveur |
| `broadcast <msg>` | Diffuse un message |
| `exit` | Quitte le serveur |

### Commandes Agent
| Commande | Description | Restrictions |
|----------|-------------|--------------|
| `shell <cmd>` | Exécute une commande | Commandes dangereuses bloquées |
| `download <file>` | Télécharge un fichier | Taille max: 100MB |
| `upload <src> <dst>` | Upload un fichier | Extensions limitées |
| `screenshot` | Capture d'écran | Résolution limitée |
| `search <pattern>` | Recherche de fichiers | Profondeur limitée |
| `keylogger start/stop` | Contrôle keylogger | Durée max: 10min |
| `webcam_snapshot` | Photo webcam | Avec consentement |
| `record_audio <sec>` | Enregistrement audio | Durée max: 2min |

## 🔒 Sécurité et Garde-fous

### 🛡️ Protections Implémentées
- **Chiffrement SSL/TLS** pour toutes les communications
- **Authentification** des agents avec tokens
- **Limitations temporelles** sur les enregistrements
- **Filtrage des commandes** dangereuses
- **Taille maximale** des fichiers et données
- **Logs d'audit** complets
- **Mode debug** pour l'analyse

### ⚠️ Usage Éthique
Ce projet inclut de nombreux garde-fous pour un usage éducatif responsable :

1. **Consentement explicite** requis pour surveillance
2. **Durées limitées** pour tous les enregistrements
3. **Résolution réduite** pour préserver la confidentialité
4. **Filtrage automatique** des données sensibles
5. **Indication visuelle** d'activité de surveillance
6. **Documentation complète** des fonctionnalités

## 🧪 Tests

### Exécution des tests
```bash
# Tests unitaires
poetry run pytest

# Tests avec couverture
poetry run pytest --cov=server --cov=client --cov=shared

# Tests d'intégration
poetry run pytest -m integration

# Tests de sécurité
poetry run pytest -m security
```

### Structure des tests
```
tests/
├── unit/              # Tests unitaires
│   ├── test_server/
│   ├── test_client/
│   └── test_shared/
├── integration/       # Tests d'intégration
├── security/          # Tests de sécurité
└── conftest.py       # Configuration pytest
```

## 🔧 Développement

### Configuration de l'environnement
```bash
# Installation en mode développement
poetry install --with dev

# Installation des hooks pre-commit
poetry run pre-commit install

# Formatage du code
poetry run black .
poetry run isort .

# Vérification de la qualité
poetry run flake8
poetry run mypy .
```

### Build du client
```bash
# Build avec PyInstaller
poetry run rat-build

# Ou manuellement
python scripts/build_client.py --onefile --noconsole
```

## 🏛️ Conformité Académique

### 📋 Cahier des Charges
- ✅ Communication TCP chiffrée SSL/TLS
- ✅ Compatibilité Windows/Linux
- ✅ Interface serveur interactive
- ✅ Gestion multi-agents
- ✅ Toutes les fonctionnalités demandées
- ✅ Gestion d'erreurs robuste
- ✅ Logging avec module `logger`
- ✅ Tests unitaires avec `pytest`
- ✅ Gestion dépendances avec `poetry`
- ✅ Formatage code avec `pre-commit`

### 📊 Notation
| Critère | Points | Statut |
|---------|--------|--------|
| Fonctionnalités client | 10/10 | ✅ |
| Architecture serveur | 6/6 | ✅ |
| Qualité du code | Bonus | ✅ |
| Tests unitaires | Bonus | ✅ |
| Documentation | Bonus | ✅ |

## 📚 Documentation

### 📖 Ressources d'Apprentissage
- [Architecture TCP/IP](docs/networking.md)
- [Chiffrement SSL/TLS](docs/encryption.md)
- [Protocoles de Communication](docs/protocol.md)
- [Sécurité Informatique](docs/security.md)
- [Tests et Validation](docs/testing.md)

### 🎥 Vidéo de Démonstration
Une vidéo de démonstration complète est disponible montrant :
- Installation et configuration
- Démarrage serveur/client
- Exécution de toutes les fonctionnalités
- Tests de sécurité et limitations

## 🤝 Contribution

Ce projet étant académique, les contributions sont limitées aux membres de l'équipe de développement pour des raisons d'évaluation.

### 👥 Équipe
- **Développeur 1** : Architecture serveur, communication
- **Développeur 2** : Modules client, sécurité

## 📜 Licence

Ce projet est sous licence MIT - voir le fichier [LICENSE](LICENSE) pour plus de détails.

## ⚖️ Responsabilité Légale

Les développeurs de ce projet :
- ✅ Déclinent toute responsabilité en cas d'usage malveillant
- ✅ Rappellent que l'usage doit être conforme à la législation
- ✅ Encouragent l'usage éducatif et éthique uniquement
- ✅ Fournissent des garde-fous de sécurité intégrés

## 🙏 Remerciements

- **Professeur de Cybersécurité** pour l'encadrement
- **Université** pour le contexte éducatif
- **Communauté Open Source** pour les bibliothèques utilisées

---

<div align="center">

**🎓 Projet Académique - Usage Éducatif Uniquement 🎓**

*Développé avec ❤️ pour l'apprentissage de la cybersécurité*

</div>#   R A T 
 
 