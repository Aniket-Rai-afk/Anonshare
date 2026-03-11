"""
tests/test_tor.py - Unit tests for tor_manager.py

These tests exercise TorManager without requiring an actual Tor daemon.
Socket-level calls are mocked to isolate the unit under test.
"""
import os
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import socket
from unittest.mock import patch, MagicMock
import pytest

from tor_manager import TorManager, TorError


class TestTorReachability:
    def test_reachable_returns_true_when_socket_connects(self):
        tm = TorManager()
        with patch("socket.create_connection") as mock_conn:
            mock_conn.return_value.__enter__ = lambda s: s
            mock_conn.return_value.__exit__ = MagicMock(return_value=False)
            assert tm.is_tor_reachable() is True

    def test_not_reachable_when_socket_raises(self):
        tm = TorManager()
        with patch("socket.create_connection", side_effect=OSError("refused")):
            assert tm.is_tor_reachable() is False

    def test_require_tor_raises_when_not_reachable(self):
        tm = TorManager()
        with patch.object(tm, "is_tor_reachable", return_value=False):
            with pytest.raises(TorError):
                tm.require_tor()

    def test_require_tor_passes_when_reachable(self):
        tm = TorManager()
        with patch.object(tm, "is_tor_reachable", return_value=True):
            tm.require_tor()   # should not raise


class TestTorToggle:
    def test_enable_patches_socket(self):
        tm = TorManager()
        original = socket.socket
        try:
            with patch("socks.setdefaultproxy"), \
                 patch("socks.socksocket", create=True):
                tm.enable_tor()
                assert tm._tor_active is True
        finally:
            socket.socket = original
            tm._tor_active = False

    def test_disable_restores_socket(self):
        tm = TorManager()
        sentinel = object()
        tm._original_socket = sentinel  # type: ignore[assignment]
        tm._tor_active = True
        with patch("socks.setdefaultproxy"):
            tm.disable_tor()
        assert socket.socket is sentinel
        assert tm._tor_active is False

    def test_enable_is_idempotent(self):
        tm = TorManager()
        tm._tor_active = True
        # Should return without calling socks at all
        with patch("socks.setdefaultproxy") as mock_set:
            tm.enable_tor()
            mock_set.assert_not_called()

    def test_context_manager(self):
        tm = TorManager()
        with patch.object(tm, "require_tor"), \
             patch.object(tm, "enable_tor") as mock_en, \
             patch.object(tm, "disable_tor") as mock_dis:
            with tm:
                pass
            mock_en.assert_called_once()
            mock_dis.assert_called_once()


class TestTorVerification:
    def test_verify_returns_true_when_is_tor(self):
        tm = TorManager()
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"IsTor": True, "IP": "1.2.3.4"}
        with patch("requests.get", return_value=mock_resp):
            assert tm.verify_tor_connection() is True

    def test_verify_returns_false_when_not_tor(self):
        tm = TorManager()
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"IsTor": False, "IP": "8.8.8.8"}
        with patch("requests.get", return_value=mock_resp):
            assert tm.verify_tor_connection() is False

    def test_verify_returns_false_on_network_error(self):
        tm = TorManager()
        with patch("requests.get", side_effect=Exception("network error")):
            assert tm.verify_tor_connection() is False
