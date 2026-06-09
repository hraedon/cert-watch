from unittest.mock import MagicMock, patch

from cert_watch.scan import _probe_hsts


def _make_hsts_mock(has_hsts=True):
    mock_conn = MagicMock()
    mock_response = MagicMock()
    mock_response.getheader.return_value = (
        "max-age=31536000" if has_hsts else None
    )
    mock_conn.getresponse.return_value = mock_response
    return mock_conn


class TestProbeHts:
    def test_returns_none_for_non_443_port(self):
        assert _probe_hsts("example.com", 8443) is None

    def test_returns_true_when_hsts_header_present(self):
        mock_conn = _make_hsts_mock(has_hsts=True)
        with patch("http.client.HTTPSConnection", return_value=mock_conn):
            result = _probe_hsts("example.com", 443)
        assert result is True
        mock_conn.request.assert_called_once_with(
            "HEAD", "/", headers={"Host": "example.com"}
        )

    def test_returns_false_when_no_hsts_header(self):
        mock_conn = _make_hsts_mock(has_hsts=False)
        with patch("http.client.HTTPSConnection", return_value=mock_conn):
            result = _probe_hsts("example.com", 443)
        assert result is False
        mock_conn.close.assert_called_once()

    def test_returns_none_on_connection_error(self):
        with patch(
            "http.client.HTTPSConnection",
            side_effect=OSError("connection refused"),
        ):
            result = _probe_hsts("unreachable.test", 443)
        assert result is None

    def test_returns_none_on_ssl_error(self):
        with patch(
            "http.client.HTTPSConnection",
            side_effect=OSError("SSL handshake failed"),
        ):
            result = _probe_hsts("bad-ssl.test", 443)
        assert result is None

    def test_pinned_ip_connects_to_pinned_ip(self):
        mock_conn = _make_hsts_mock(has_hsts=True)
        mock_ssl_sock = MagicMock()
        mock_raw_sock = MagicMock()

        def fake_wrap_socket(sock, server_hostname=None, **kw):
            assert server_hostname == "example.com"
            assert sock is mock_raw_sock
            return mock_ssl_sock

        mock_ctx = MagicMock()
        mock_ctx.wrap_socket = fake_wrap_socket

        with (
            patch("cert_watch.scan_conn.socket.create_connection") as mock_connect,
            patch("cert_watch.scan_conn.ssl.create_default_context", return_value=mock_ctx),
            patch("http.client.HTTPSConnection", return_value=mock_conn),
        ):
            mock_connect.return_value = mock_raw_sock
            result = _probe_hsts("example.com", 443, pinned_ip="10.0.0.1")

        assert result is True
        mock_connect.assert_called_once_with(
            ("10.0.0.1", 443), timeout=5.0
        )

    def test_pinned_ip_ssl_failure_returns_none(self):
        mock_raw_sock = MagicMock()
        mock_ctx = MagicMock()
        mock_ctx.wrap_socket.side_effect = OSError("TLS handshake failed")

        with (
            patch("cert_watch.scan_conn.socket.create_connection", return_value=mock_raw_sock),
            patch("cert_watch.scan_conn.ssl.create_default_context", return_value=mock_ctx),
        ):
            result = _probe_hsts("example.com", 443, pinned_ip="10.0.0.1")

        assert result is None
        mock_raw_sock.close.assert_called_once()

    def test_pinned_ip_connection_refused_returns_none(self):
        with patch(
            "cert_watch.scan_conn.socket.create_connection",
            side_effect=ConnectionRefusedError("refused"),
        ):
            result = _probe_hsts(
                "example.com", 443, pinned_ip="10.0.0.1"
            )
        assert result is None

    def test_conn_closed_on_success(self):
        mock_conn = _make_hsts_mock(has_hsts=True)
        with patch("http.client.HTTPSConnection", return_value=mock_conn):
            _probe_hsts("example.com", 443)
        mock_conn.close.assert_called_once()

    def test_conn_closed_on_response_error(self):
        mock_conn = MagicMock()
        mock_conn.getresponse.side_effect = RuntimeError("read timeout")

        with patch("http.client.HTTPSConnection", return_value=mock_conn):
            result = _probe_hsts("example.com", 443)
        assert result is None
