# tests/test_firewall.py
"""
Tests unitaires pour detector.py, counter.py, blocker.py.
Lancer avec : pytest tests/test_firewall.py -v
"""

import time
import subprocess
from unittest.mock import patch, MagicMock
import pytest


# ===========================================================================
# detector.py
# ===========================================================================

class TestDetector:
    """Tests pour detect_port_scan()"""

    def setup_method(self):
        """Réinitialise l'état global du détecteur avant chaque test."""
        from detector import connections
        connections.clear()

    def test_no_scan_single_port(self):
        """Un seul port → pas de scan."""
        from detector import detect_port_scan
        detected, ports = detect_port_scan("1.2.3.4|TCP", 80)
        assert detected is False
        assert ports is None

    def test_no_scan_below_threshold(self):
        """Deux ports distincts → sous le seuil (PORT_THRESHOLD=3)."""
        from detector import detect_port_scan
        detect_port_scan("1.2.3.4|TCP", 80)
        detected, ports = detect_port_scan("1.2.3.4|TCP", 443)
        assert detected is False

    def test_scan_detected_at_threshold(self):
        """3 ports distincts → scan détecté."""
        from detector import detect_port_scan
        detect_port_scan("1.2.3.4|TCP", 80)
        detect_port_scan("1.2.3.4|TCP", 443)
        detected, ports = detect_port_scan("1.2.3.4|TCP", 8080)
        assert detected is True
        assert ports == {80, 443, 8080}

    def test_scan_detected_above_threshold(self):
        """5 ports distincts → scan détecté, tous les ports retournés."""
        from detector import detect_port_scan
        for port in [21, 22, 23, 25, 80]:
            detect_port_scan("10.0.0.1|TCP", port)
        detected, ports = detect_port_scan("10.0.0.1|TCP", 443)
        assert detected is True
        assert {21, 22, 23, 25, 80, 443}.issubset(ports)

    def test_duplicate_ports_not_counted(self):
        """Le même port répété ne doit pas déclencher de scan."""
        from detector import detect_port_scan
        for _ in range(10):
            detect_port_scan("5.5.5.5|TCP", 80)
        detected, _ = detect_port_scan("5.5.5.5|TCP", 80)
        assert detected is False

    def test_different_flows_isolated(self):
        """Deux IPs différentes ne partagent pas leur compteur."""
        from detector import detect_port_scan
        detect_port_scan("1.1.1.1|TCP", 80)
        detect_port_scan("1.1.1.1|TCP", 443)
        # IP différente — ne doit pas hériter des ports de 1.1.1.1
        detected, _ = detect_port_scan("2.2.2.2|TCP", 8080)
        assert detected is False

    def test_tcp_and_udp_isolated(self):
        """TCP et UDP sont des flux séparés pour la même IP."""
        from detector import detect_port_scan
        detect_port_scan("1.2.3.4|TCP", 80)
        detect_port_scan("1.2.3.4|TCP", 443)
        # UDP ne doit pas compter avec TCP
        detected, _ = detect_port_scan("1.2.3.4|UDP", 53)
        assert detected is False

    def test_window_expiry(self):
        """Les ports hors de la fenêtre temporelle sont purgés."""
        from detector import detect_port_scan, connections, TIME_WINDOW

        key = "9.9.9.9|TCP"
        now = time.time()

        # Injecter manuellement deux entrées expirées
        connections[key] = [
            (now - TIME_WINDOW - 5, 80),
            (now - TIME_WINDOW - 5, 443),
        ]

        # Un nouveau port arrive — les anciens doivent être purgés
        detected, _ = detect_port_scan(key, 8080)
        assert detected is False  # seulement 1 port valide après purge

    def test_returns_unique_ports_set(self):
        """Les ports retournés lors d'un scan sont bien un set (sans doublons)."""
        from detector import detect_port_scan
        detect_port_scan("3.3.3.3|TCP", 80)
        detect_port_scan("3.3.3.3|TCP", 80)   # doublon
        detect_port_scan("3.3.3.3|TCP", 443)
        detected, ports = detect_port_scan("3.3.3.3|TCP", 8080)
        assert detected is True
        assert len(ports) == len(set(ports))   # pas de doublons


# ===========================================================================
# counter.py
# ===========================================================================

class TestCounter:
    """Tests pour should_block() et record_scan()"""

    def setup_method(self):
        from counter import events
        events.clear()

    def test_not_blocked_first_scan(self):
        """Premier scan → pas encore bloqué (seuil = 2)."""
        from counter import should_block
        result = should_block("1.2.3.4|TCP")
        assert result is False

    def test_blocked_at_threshold(self):
        """Deux scans dans la fenêtre → blocage déclenché."""
        from counter import should_block, THRESHOLD
        key = "1.2.3.4|TCP"
        results = [should_block(key) for _ in range(THRESHOLD)]
        assert results[-1] is True

    def test_not_blocked_below_threshold(self):
        """THRESHOLD-1 appels → pas encore bloqué."""
        from counter import should_block, THRESHOLD
        key = "7.7.7.7|TCP"
        for _ in range(THRESHOLD - 1):
            result = should_block(key)
        assert result is False

    def test_window_expiry_resets_count(self):
        """Après expiration de la fenêtre, le compteur repart à zéro."""
        from counter import should_block, events, WINDOW_SECONDS

        key = "8.8.8.8|TCP"
        now = time.time()

        # Simuler des événements expirés
        from collections import deque
        events[key] = deque([now - WINDOW_SECONDS - 10, now - WINDOW_SECONDS - 5])

        # Le premier appel après expiration doit retourner False
        result = should_block(key)
        assert result is False

    def test_different_keys_independent(self):
        """Deux IPs différentes ont des compteurs indépendants."""
        from counter import should_block, THRESHOLD
        key_a = "10.0.0.1|TCP"
        key_b = "10.0.0.2|TCP"
        for _ in range(THRESHOLD):
            should_block(key_a)
        # key_b n'a aucun événement → pas bloqué
        assert should_block(key_b) is False

    def test_record_scan_count(self):
        """record_scan() incrémente bien le compteur."""
        from counter import record_scan, events
        key = "5.5.5.5|UDP"
        assert record_scan(key) == 1
        assert record_scan(key) == 2
        assert record_scan(key) == 3


# ===========================================================================
# blocker.py
# ===========================================================================

class TestBlocker:
    """Tests pour block_ip(), unblock_ip(), is_private_ip()."""

    def setup_method(self):
        from blocker import blocked_cache
        blocked_cache.clear()

    # --- is_private_ip ---

    def test_loopback_is_private(self):
        from blocker import is_private_ip
        assert is_private_ip("127.0.0.1") is True

    def test_rfc1918_is_private(self):
        from blocker import is_private_ip
        assert is_private_ip("192.168.1.1")  is True
        assert is_private_ip("10.0.0.1")     is True
        assert is_private_ip("172.16.0.1")   is True

    def test_public_ip_not_private(self):
        from blocker import is_private_ip
        assert is_private_ip("8.8.8.8")       is False
        assert is_private_ip("203.0.113.5")   is False
        assert is_private_ip("1.1.1.1")       is False

    def test_invalid_ip_treated_as_private(self):
        """Une IP invalide ne doit jamais être bloquée."""
        from blocker import is_private_ip
        assert is_private_ip("not_an_ip")  is True
        assert is_private_ip("")           is True
        assert is_private_ip("999.x.y.z") is True

    # --- block_ip ---

    def test_block_private_ip_refused(self):
        """Une IP privée ne doit jamais être bloquée — sécurité critique."""
        from blocker import block_ip
        assert block_ip("192.168.1.1") is False
        assert block_ip("127.0.0.1")   is False
        assert block_ip("10.0.0.1")    is False

    def test_block_ip_calls_netsh(self):
        """block_ip() appelle bien netsh pour une IP publique."""
        from blocker import block_ip

        mock_result = MagicMock()
        mock_result.returncode = 0

        with patch("blocker.rule_exists", return_value=False), \
             patch("blocker.subprocess.run", return_value=mock_result) as mock_run:
            result = block_ip("8.8.8.8")

        assert result is True
        assert mock_run.call_count == 2   # une fois IN, une fois OUT

        # Vérifie que les commandes contiennent bien "block" et l'IP
        calls = [str(c) for c in mock_run.call_args_list]
        assert any("block" in c for c in calls)
        assert any("8.8.8.8" in c for c in calls)

    def test_block_ip_cached_avoids_netsh(self):
        """Si l'IP est déjà dans blocked_cache, netsh n'est pas rappelé."""
        from blocker import block_ip, blocked_cache

        blocked_cache.add("8.8.8.8")

        with patch("blocker.subprocess.run") as mock_run:
            result = block_ip("8.8.8.8")

        assert result is True
        mock_run.assert_not_called()

    def test_block_ip_already_in_windows(self):
        """Si la règle existe déjà dans Windows, on ne la recrée pas."""
        from blocker import block_ip

        with patch("blocker.rule_exists", return_value=True), \
             patch("blocker.subprocess.run") as mock_run:
            result = block_ip("1.1.1.1")

        assert result is True
        mock_run.assert_not_called()

    def test_block_ip_netsh_failure_returns_false(self):
        """Si netsh échoue (returncode != 0), block_ip retourne False."""
        from blocker import block_ip

        mock_fail = MagicMock()
        mock_fail.returncode = 1
        mock_fail.stderr = "Access denied"

        with patch("blocker.rule_exists", return_value=False), \
             patch("blocker.subprocess.run", return_value=mock_fail):
            result = block_ip("2.2.2.2")

        assert result is False

    def test_block_ip_adds_to_cache(self):
        """Après un blocage réussi, l'IP est dans blocked_cache."""
        from blocker import block_ip, blocked_cache

        mock_ok = MagicMock()
        mock_ok.returncode = 0

        with patch("blocker.rule_exists", return_value=False), \
             patch("blocker.subprocess.run", return_value=mock_ok):
            block_ip("5.5.5.5")

        assert "5.5.5.5" in blocked_cache

    # --- unblock_ip ---

    def test_unblock_private_ip_refused(self):
        """Une IP privée ne peut pas être débloquée non plus."""
        from blocker import unblock_ip
        assert unblock_ip("192.168.0.1") is False

    def test_unblock_ip_calls_netsh_delete(self):
        """unblock_ip() appelle bien netsh delete rule."""
        from blocker import unblock_ip

        mock_ok = MagicMock()
        mock_ok.returncode = 0

        with patch("blocker.rule_exists", return_value=True), \
             patch("blocker.subprocess.run", return_value=mock_ok) as mock_run:
            result = unblock_ip("8.8.8.8")

        assert result is True
        calls = [str(c) for c in mock_run.call_args_list]
        assert any("delete" in c for c in calls)

    def test_unblock_ip_removes_from_cache(self):
        """Après unblock, l'IP est retirée de blocked_cache."""
        from blocker import unblock_ip, blocked_cache

        blocked_cache.add("8.8.8.8")

        mock_ok = MagicMock()
        mock_ok.returncode = 0

        with patch("blocker.rule_exists", return_value=True), \
             patch("blocker.subprocess.run", return_value=mock_ok):
            unblock_ip("8.8.8.8")

        assert "8.8.8.8" not in blocked_cache

    def test_unblock_ip_rule_not_found_still_ok(self):
        """Si la règle n'existe pas dans Windows, unblock retourne True sans erreur."""
        from blocker import unblock_ip

        with patch("blocker.rule_exists", return_value=False), \
             patch("blocker.subprocess.run") as mock_run:
            result = unblock_ip("3.3.3.3")

        assert result is True
        mock_run.assert_not_called()

    def test_unblock_ip_netsh_failure_returns_false(self):
        """Si netsh delete échoue, unblock_ip retourne False."""
        from blocker import unblock_ip

        mock_fail = MagicMock()
        mock_fail.returncode = 1
        mock_fail.stderr = "Error"

        with patch("blocker.rule_exists", return_value=True), \
             patch("blocker.subprocess.run", return_value=mock_fail):
            result = unblock_ip("4.4.4.4")

        assert result is False

    # --- load_blocked_cache_from_windows ---

    def test_load_blocked_cache(self):
        """load_blocked_cache_from_windows() remplit bien blocked_cache."""
        from blocker import load_blocked_cache_from_windows, blocked_cache

        load_blocked_cache_from_windows(["1.1.1.1", "2.2.2.2", "3.3.3.3"])
        assert "1.1.1.1" in blocked_cache
        assert "2.2.2.2" in blocked_cache
        assert "3.3.3.3" in blocked_cache

    def test_load_blocked_cache_empty_list(self):
        """Liste vide → cache reste vide, pas d'erreur."""
        from blocker import load_blocked_cache_from_windows, blocked_cache
        load_blocked_cache_from_windows([])
        assert len(blocked_cache) == 0