from unittest.mock import MagicMock, patch

from cert_watch.caa_check import CAAResult, check_caa


def test_check_caa_no_records():
    """When dnspython is not installed, should return an error."""
    result = check_caa("example.com")
    assert isinstance(result, CAAResult)
    assert result.domain == "example.com"
    assert result.error != ""
    assert "dnspython" in result.error


def test_check_caa_with_mocked_dns():
    """Mock dnspython to return actual CAA records."""
    mock_answer = MagicMock()
    mock_answer.__iter__ = MagicMock(return_value=iter([
        "0 issue \"letsencrypt.org\"",
        "0 issuewild \";\"",
    ]))

    mock_resolver = MagicMock()
    mock_resolver.resolve.return_value = mock_answer

    mock_rdata = MagicMock()
    mock_rdata.CAA = 257

    with patch.dict("sys.modules", {"dns.resolver": mock_resolver, "dns.rdatatype": mock_rdata}):
        # Temporarily make the function think dnspython is available
        import cert_watch.caa_check as caa_mod
        original_query = caa_mod._query_caa_records
        try:
            def _fake_query(domain):
                return ["0 issue \"letsencrypt.org\"", "0 issuewild \";\""]
            caa_mod._query_caa_records = _fake_query
            result = check_caa("example.com")
            assert result.domain == "example.com"
            assert result.issue_allowed is True
            assert result.issuewild_allowed is False
            assert 'issue "letsencrypt.org"' in result.records
        finally:
            caa_mod._query_caa_records = original_query


def test_check_caa_no_caa_records():
    """No CAA records means unrestricted issuance."""
    import cert_watch.caa_check as caa_mod
    original_query = caa_mod._query_caa_records
    try:
        def _fake_query(domain):
            return []
        caa_mod._query_caa_records = _fake_query
        result = check_caa("example.com")
        assert result.error == ""
        assert result.issue_allowed is True
        assert result.issuewild_allowed is True
        assert result.records == []
    finally:
        caa_mod._query_caa_records = original_query


def test_check_caa_blocked_issue():
    """Empty issue tag (';') blocks issuance."""
    import cert_watch.caa_check as caa_mod
    original_query = caa_mod._query_caa_records
    try:
        def _fake_query(domain):
            return ["0 issue \";\""]
        caa_mod._query_caa_records = _fake_query
        result = check_caa("example.com")
        assert result.issue_allowed is False
        assert result.issuewild_allowed is True  # no issuewild explicitly set
    finally:
        caa_mod._query_caa_records = original_query
