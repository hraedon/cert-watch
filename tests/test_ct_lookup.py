from unittest.mock import MagicMock, patch

from cert_watch.ct_lookup import CTEntry, query_ct_log


def test_query_ct_log_success():
    fake_json = [
        {
            "issuer_ca_id": 1,
            "issuer_name": "Test CA",
            "common_name": "example.com",
            "name_value": "example.com\nwww.example.com",
            "not_before": "2025-01-01T00:00:00+00:00",
            "not_after": "2027-01-01T00:00:00+00:00",
            "serial_number": "abc123",
        },
    ]
    with patch("cert_watch.ct_lookup.ssrf_safe_urlopen") as mock_open:
        mock_resp = MagicMock()
        mock_resp.read.return_value = __import__("json").dumps(fake_json).encode()
        mock_resp.__enter__ = MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_open.return_value = mock_resp
        result = query_ct_log("example.com")
    assert isinstance(result, list)
    assert len(result) == 1
    assert isinstance(result[0], CTEntry)
    assert result[0].common_name == "example.com"


def test_query_ct_log_expired_filtered():
    fake_json = [
        {
            "issuer_ca_id": 1,
            "issuer_name": "Test CA",
            "common_name": "old.example.com",
            "name_value": "old.example.com",
            "not_before": "2020-01-01T00:00:00+00:00",
            "not_after": "2021-01-01T00:00:00+00:00",
            "serial_number": "xyz",
        },
    ]
    with patch("cert_watch.ct_lookup.ssrf_safe_urlopen") as mock_open:
        mock_resp = MagicMock()
        mock_resp.read.return_value = __import__("json").dumps(fake_json).encode()
        mock_resp.__enter__ = MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_open.return_value = mock_resp
        result = query_ct_log("old.example.com")
    assert isinstance(result, list)
    assert len(result) == 0


def test_query_ct_log_network_error():
    with patch(
        "cert_watch.ct_lookup.ssrf_safe_urlopen",
        side_effect=OSError("timeout"),
    ):
        result = query_ct_log("down.example.com")
    assert isinstance(result, str)
    assert "CT lookup failed" in result


def test_query_ct_log_invalid_json():
    with patch("cert_watch.ct_lookup.ssrf_safe_urlopen") as mock_open:
        mock_resp = MagicMock()
        mock_resp.read.return_value = b"not json"
        mock_resp.__enter__ = MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_open.return_value = mock_resp
        result = query_ct_log("bad.example.com")
    assert isinstance(result, str)
    assert "invalid JSON" in result
