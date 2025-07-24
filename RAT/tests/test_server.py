"""
Tests unitaires pour le serveur RAT
Tests des fonctionnalités principales avec mocks et fixtures
"""

import pytest
import socket
import threading
import time
from unittest.mock import Mock, patch, MagicMock
import json

# Import des modules à tester
from server.core.server import RATServer
from server.core.session_manager import SessionManager, ClientSession
from server.core.command_handler import CommandHandler
from server.utils.config import ServerConfig
from shared.protocol import Protocol, MessageType
from shared.exceptions import RATException


class TestClientSession:
    """Tests pour la classe ClientSession"""
    
    def test_session_creation(self):
        """Test de création d'une session"""
        mock_socket = Mock()
        address = ("127.0.0.1", 12345)
        
        session = ClientSession(mock_socket, address)
        
        assert session.socket == mock_socket
        assert session.address == address
        assert session.is_active is True
        assert session.is_authenticated is False
        assert session.id.startswith("agent_")
        assert len(session.id) == 14  # "agent_" + 8 caractères
    
    def test_session_authentication(self):
        """Test d'authentification d'une session"""
        mock_socket = Mock()
        session = ClientSession(mock_socket, ("127.0.0.1", 12345))
        
        # Avant authentification
        assert session.is_authenticated is False
        
        # Authentification
        session.mark_as_authenticated()
        
        assert session.is_authenticated is True
        assert session.last_seen > 0
    
    def test_send_message_success(self):
        """Test d'envoi de message réussi"""
        mock_socket = Mock()
        session = ClientSession(mock_socket, ("127.0.0.1", 12345))
        session.mark_as_authenticated()
        
        message = {"type": "test", "data": {"message": "hello"}}
        
        with patch.object(Protocol, 'encode_message', return_value=b'encoded_message'):
            result = session.send_message(message)
        
        assert result is True
        mock_socket.send.assert_called_once_with(b'encoded_message')
    
    def test_send_message_failure(self):
        """Test d'envoi de message échoué"""
        mock_socket = Mock()
        mock_socket.send.side_effect = Exception("Connection failed")
        
        session = ClientSession(mock_socket, ("127.0.0.1", 12345))
        session.mark_as_authenticated()
        
        message = {"type": "test", "data": {}}
        
        with patch.object(Protocol, 'encode_message', return_value=b'encoded_message'):
            result = session.send_message(message)
        
        assert result is False
        assert session.is_active is False
    
    def test_session_info_summary(self):
        """Test du résumé d'informations de session"""
        mock_socket = Mock()
        session = ClientSession(mock_socket, ("192.168.1.100", 8888))
        
        # Ajout d'informations système
        session.system_info = {
            'platform': 'Windows-10',
            'username': 'testuser',
            'hostname': 'testhost'
        }
        
        summary = session.get_info_summary()
        
        assert session.id in summary
        assert "192.168.1.100:8888" in summary
        assert "Windows-10" in summary
        assert "testuser" in summary
        assert "testhost" in summary
        assert "Active" in summary


class TestSessionManager:
    """Tests pour le gestionnaire de sessions"""
    
    def test_session_manager_initialization(self):
        """Test d'initialisation du gestionnaire"""
        manager = SessionManager()
        
        assert len(manager.sessions) == 0
        assert manager.current_session is None
        assert manager.total_sessions_created == 0
    
    def test_create_session(self):
        """Test de création d'une nouvelle session"""
        manager = SessionManager()
        mock_socket = Mock()
        address = ("127.0.0.1", 12345)
        
        session = manager.create_session(mock_socket, address)
        
        assert session.socket == mock_socket
        assert session.address == address
        assert session.id in manager.sessions
        assert manager.total_sessions_created == 1
        assert manager.current_session == session.id  # Auto-sélection
    
    def test_multiple_sessions(self):
        """Test de gestion de plusieurs sessions"""
        manager = SessionManager()
        
        # Création de plusieurs sessions
        session1 = manager.create_session(Mock(), ("127.0.0.1", 1001))
        session2 = manager.create_session(Mock(), ("127.0.0.1", 1002))
        session3 = manager.create_session(Mock(), ("127.0.0.1", 1003))
        
        assert len(manager.sessions) == 3
        assert manager.total_sessions_created == 3
        assert manager.current_session == session1.id  # Premier reste sélectionné
    
    def test_set_current_session(self):
        """Test de définition de la session courante"""
        manager = SessionManager()
        
        session1 = manager.create_session(Mock(), ("127.0.0.1", 1001))
        session2 = manager.create_session(Mock(), ("127.0.0.1", 1002))
        
        # Authentification des sessions
        session1.mark_as_authenticated()
        session2.mark_as_authenticated()
        
        # Changement de session courante
        result = manager.set_current_session(session2.id)
        
        assert result is True
        assert manager.current_session == session2.id
    
    def test_remove_session(self):
        """Test de suppression d'une session"""
        manager = SessionManager()
        
        session1 = manager.create_session(Mock(), ("127.0.0.1", 1001))
        session2 = manager.create_session(Mock(), ("127.0.0.1", 1002))
        
        # Authentification
        session1.mark_as_authenticated()
        session2.mark_as_authenticated()
        
        assert len(manager.sessions) == 2
        
        # Suppression de session1
        manager.remove_session(session1.id)
        
        assert len(manager.sessions) == 1
        assert session1.id not in manager.sessions
        assert session2.id in manager.sessions
        assert manager.current_session == session2.id  # Auto-sélection
    
    def test_get_active_sessions(self):
        """Test de récupération des sessions actives"""
        manager = SessionManager()
        
        session1 = manager.create_session(Mock(), ("127.0.0.1", 1001))
        session2 = manager.create_session(Mock(), ("127.0.0.1", 1002))
        session3 = manager.create_session(Mock(), ("127.0.0.1", 1003))
        
        # Seules les sessions 1 et 3 sont authentifiées
        session1.mark_as_authenticated()
        session3.mark_as_authenticated()
        
        active_sessions = manager.get_active_sessions()
        
        assert len(active_sessions) == 2
        assert session1 in active_sessions
        assert session3 in active_sessions
        assert session2 not in active_sessions
    
    def test_cleanup_inactive_sessions(self):
        """Test de nettoyage des sessions inactives"""
        manager = SessionManager()
        
        session1 = manager.create_session(Mock(), ("127.0.0.1", 1001))
        session2 = manager.create_session(Mock(), ("127.0.0.1", 1002))
        
        session1.mark_as_authenticated()
        session2.mark_as_authenticated()
        
        # Simulation d'ancienneté pour session1
        session1.last_seen = time.time() - 400  # 400 secondes (> 300 timeout)
        
        removed_count = manager.cleanup_inactive_sessions(timeout=300)
        
        assert removed_count == 1
        assert session1.id not in manager.sessions
        assert session2.id in manager.sessions
    
    def test_broadcast_message(self):
        """Test de diffusion de message"""
        manager = SessionManager()
        
        session1 = manager.create_session(Mock(), ("127.0.0.1", 1001))
        session2 = manager.create_session(Mock(), ("127.0.0.1", 1002))
        
        session1.mark_as_authenticated()
        session2.mark_as_authenticated()
        
        message = {"type": "broadcast", "data": {"text": "Hello all"}}
        
        with patch.object(session1, 'send_message', return_value=True) as mock1, \
             patch.object(session2, 'send_message', return_value=True) as mock2:
            
            sent_count = manager.broadcast_message(message)
            
            assert sent_count == 2
            mock1.assert_called_once_with(message)
            mock2.assert_called_once_with(message)


class TestCommandHandler:
    """Tests pour le gestionnaire de commandes"""
    
    @pytest.fixture
    def setup_command_handler(self):
        """Fixture pour créer un gestionnaire de commandes"""
        session_manager = SessionManager()
        config = ServerConfig()
        command_handler = CommandHandler(session_manager, config)
        return command_handler, session_manager
    
    def test_help_command(self, setup_command_handler):
        """Test de la commande help"""
        command_handler, _ = setup_command_handler
        
        result = command_handler.handle_command("help")
        
        assert result is not None
        assert "COMMANDES SERVEUR" in result
        assert "sessions" in result
        assert "interact" in result
    
    def test_sessions_command_empty(self, setup_command_handler):
        """Test de la commande sessions sans sessions"""
        command_handler, session_manager = setup_command_handler
        
        result = command_handler.handle_command("sessions")
        
        assert "Aucune session active" in result
    
    def test_sessions_command_with_sessions(self, setup_command_handler):
        """Test de la commande sessions avec des sessions actives"""
        command_handler, session_manager = setup_command_handler
        
        # Création de sessions
        session1 = session_manager.create_session(Mock(), ("127.0.0.1", 1001))
        session2 = session_manager.create_session(Mock(), ("192.168.1.100", 1002))
        
        session1.mark_as_authenticated()
        session2.mark_as_authenticated()
        
        # Ajout d'informations système
        session1.system_info = {'platform': 'Windows', 'username': 'user1'}
        session2.system_info = {'platform': 'Linux', 'username': 'user2'}
        
        result = command_handler.handle_command("sessions")
        
        assert "Sessions actives (2)" in result
        assert session1.id in result
        assert session2.id in result
        assert "127.0.0.1" in result
        assert "192.168.1.100" in result
    
    def test_interact_command(self, setup_command_handler):
        """Test de la commande interact"""
        command_handler, session_manager = setup_command_handler
        
        # Création d'une session
        session = session_manager.create_session(Mock(), ("127.0.0.1", 1001))
        session.mark_as_authenticated()
        session.system_info = {'platform': 'Windows', 'hostname': 'testhost'}
        
        result = command_handler.handle_command(f"interact {session.id}")
        
        assert f"Interaction avec {session.id}" in result
        assert session_manager.current_session == session.id
        assert "testhost" in result
    
    def test_interact_invalid_session(self, setup_command_handler):
        """Test de la commande interact avec session invalide"""
        command_handler, _ = setup_command_handler
        
        result = command_handler.handle_command("interact invalid_session")
        
        assert "non trouvé ou inactif" in result
    
    def test_stats_command(self, setup_command_handler):
        """Test de la commande stats"""
        command_handler, session_manager = setup_command_handler
        
        # Création de quelques sessions
        session1 = session_manager.create_session(Mock(), ("127.0.0.1", 1001))
        session2 = session_manager.create_session(Mock(), ("127.0.0.1", 1002))
        session1.mark_as_authenticated()
        
        result = command_handler.handle_command("stats")
        
        assert "STATISTIQUES SERVEUR" in result
        assert "Sessions actives: 1" in result
        assert "Sessions totales: 2" in result
        assert "Créées au total:  2" in result
    
    def test_agent_command_no_session(self, setup_command_handler):
        """Test de commande agent sans session sélectionnée"""
        command_handler, session_manager = setup_command_handler
        
        result = command_handler.handle_command("screenshot")
        
        assert "Commande serveur inconnue" in result or "help" in result
    
    def test_agent_command_with_session(self, setup_command_handler):
        """Test de commande agent avec session sélectionnée"""
        command_handler, session_manager = setup_command_handler
        
        # Création et sélection d'une session
        session = session_manager.create_session(Mock(), ("127.0.0.1", 1001))
        session.mark_as_authenticated()
        session_manager.set_current_session(session.id)
        
        with patch.object(session, 'send_message', return_value=True):
            result = command_handler.handle_command("screenshot")
        
        assert "capture d'écran envoyée" in result
    
    def test_unknown_command(self, setup_command_handler):
        """Test de commande inconnue"""
        command_handler, _ = setup_command_handler
        
        result = command_handler.handle_command("unknown_command")
        
        assert "Commande serveur inconnue" in result
        assert "unknown_command" in result


class TestProtocol:
    """Tests pour le protocole de communication"""
    
    def test_create_message(self):
        """Test de création de message"""
        data = {"test": "value", "number": 42}
        message = Protocol.create_message(MessageType.COMMAND, data)
        
        assert message['type'] == MessageType.COMMAND.value
        assert message['data'] == data
        assert 'protocol_version' in message
        assert 'message_id' in message
        assert 'timestamp' in message
        assert message['compressed'] is False
    
    def test_encode_decode_message(self):
        """Test d'encodage et décodage de message"""
        original_data = {"command": "test", "args": ["arg1", "arg2"]}
        original_message = Protocol.create_message(MessageType.COMMAND, original_data)
        
        # Encodage
        encoded = Protocol.encode_message(original_message)
        assert isinstance(encoded, bytes)
        assert encoded.startswith(Protocol.MAGIC_HEADER)
        
        # Décodage
        decoded_message = Protocol.decode_message(encoded)
        assert decoded_message is not None
        assert decoded_message['type'] == MessageType.COMMAND.value
        assert decoded_message['data'] == original_data
        assert decoded_message['message_id'] == original_message['message_id']
    
    def test_encode_decode_large_message(self):
        """Test avec un message volumineux (compression)"""
        # Création d'un message volumineux
        large_data = {"large_text": "A" * 2000}  # > COMPRESSION_THRESHOLD
        message = Protocol.create_message(MessageType.COMMAND, large_data, compress=True)
        
        # Vérification de la compression
        assert message['compressed'] is True
        
        # Encodage/Décodage
        encoded = Protocol.encode_message(message)
        decoded = Protocol.decode_message(encoded)
        
        assert decoded is not None
        assert decoded['compressed'] is False  # Décompressé
        assert decoded['data'] == large_data
    
    def test_create_response(self):
        """Test de création de réponse"""
        original_message = Protocol.create_message(MessageType.COMMAND, {"cmd": "test"})
        response_data = {"result": "success", "output": "Test completed"}
        
        response = Protocol.create_response(original_message, response_data)
        
        assert response['type'] == MessageType.COMMAND_RESPONSE.value
        assert response['data']['status'] == 'success'
        assert response['data']['result'] == 'success'
        assert response['data']['original_message_id'] == original_message['message_id']
    
    def test_create_error_response(self):
        """Test de création de réponse d'erreur"""
        original_message = Protocol.create_message(MessageType.COMMAND, {"cmd": "test"})
        
        error_response = Protocol.create_error_response(
            original_message, 
            "Command failed", 
            "CMD_ERROR"
        )
        
        assert error_response['type'] == MessageType.ERROR.value
        assert error_response['data']['error_message'] == "Command failed"
        assert error_response['data']['error_code'] == "CMD_ERROR"
    
    def test_invalid_message_decode(self):
        """Test de décodage de message invalide"""
        # Message sans en-tête magique
        invalid_data = b"INVALID_HEADER" + b"test data"
        
        result = Protocol.decode_message(invalid_data)
        assert result is None
    
    def test_message_too_large(self):
        """Test de message trop volumineux"""
        large_message = Protocol.create_message(
            MessageType.COMMAND, 
            {"data": "A" * (Protocol.MAX_MESSAGE_SIZE + 1000)}
        )
        
        with pytest.raises(ValueError, match="Message trop volumineux"):
            Protocol.encode_message(large_message)


class TestServerConfig:
    """Tests pour la configuration serveur"""
    
    def test_default_config(self):
        """Test de configuration par défaut"""
        config = ServerConfig()
        
        assert config.HOST == "0.0.0.0"
        assert config.PORT == 8888
        assert config.USE_SSL is False
        assert config.MAX_CONNECTIONS == 100
        assert config.DEBUG is False
    
    def test_config_validation(self):
        """Test de validation de configuration"""
        config = ServerConfig()
        
        # Configuration valide
        is_valid, errors = config.validate_config()
        assert is_valid is True
        assert len(errors) == 0
        
        # Configuration invalide
        config.PORT = -1
        is_valid, errors = config.validate_config()
        assert is_valid is False
        assert len(errors) > 0
        assert "PORT invalide" in str(errors)


@pytest.mark.integration
class TestServerIntegration:
    """Tests d'intégration pour le serveur"""
    
    def test_server_startup_shutdown(self):
        """Test de démarrage et arrêt du serveur"""
        config = ServerConfig()
        config.PORT = 9999  # Port de test
        config.DEBUG = True
        
        server = RATServer(config)
        
        # Test de démarrage dans un thread séparé
        server_thread = threading.Thread(target=server.start)
        server_thread.daemon = True
        
        try:
            server_thread.start()
            time.sleep(0.5)  # Laisser le temps au serveur de démarrer
            
            # Vérification que le port est ouvert
            test_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            result = test_socket.connect_ex(("127.0.0.1", 9999))
            test_socket.close()
            
            # Port devrait être accessible
            assert result == 0
            
        finally:
            # Arrêt du serveur
            server.stop()
            time.sleep(0.1)


# Fixtures globales pour les tests
@pytest.fixture
def mock_socket():
    """Mock socket pour les tests"""
    mock = Mock()
    mock.recv.return_value = b""
    mock.send.return_value = 100
    return mock


@pytest.fixture
def sample_session():
    """Session d'exemple pour les tests"""
    mock_socket = Mock()
    session = ClientSession(mock_socket, ("127.0.0.1", 12345))
    session.mark_as_authenticated()
    session.system_info = {
        'platform': 'Test-Platform',
        'username': 'testuser',
        'hostname': 'testhost'
    }
    return session


# Tests de performances
@pytest.mark.slow
class TestPerformance:
    """Tests de performance"""
    
    def test_many_sessions_creation(self):
        """Test de création de nombreuses sessions"""
        manager = SessionManager()
        
        start_time = time.time()
        
        # Création de 1000 sessions
        for i in range(1000):
            session = manager.create_session(Mock(), ("127.0.0.1", 1000 + i))
            session.mark_as_authenticated()
        
        creation_time = time.time() - start_time
        
        assert len(manager.sessions) == 1000
        assert creation_time < 5.0  # Moins de 5 secondes
        assert manager.total_sessions_created == 1000
    
    def test_message_encoding_performance(self):
        """Test de performance d'encodage de messages"""
        large_data = {"content": "A" * 10000}  # 10KB
        
        start_time = time.time()
        
        # Encodage de 100 messages
        for _ in range(100):
            message = Protocol.create_message(MessageType.COMMAND, large_data)
            encoded = Protocol.encode_message(message)
            decoded = Protocol.decode_message(encoded)
            assert decoded is not None
        
        encoding_time = time.time() - start_time
        
        assert encoding_time < 2.0  # Moins de 2 secondes


if __name__ == "__main__":
    # Exécution des tests en mode standalone
    pytest.main([__file__, "-v", "--tb=short"])