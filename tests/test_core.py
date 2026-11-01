import pytest
from fastapi import HTTPException
from app.routes import calculate_score, validate_indicator, validate_json_list

@pytest.mark.parametrize(
    "severity,confidence,expected",
    [
        ("low", 100, 20),
        ("medium", 100, 50),
        ("high", 100, 75),
        ("critical", 100, 100),
        ("critical", 50, 50),
        ("high", 0, 0),
    ],
)
def test_calculate_score(severity, confidence, expected):
    assert calculate_score(severity, confidence) == expected

@pytest.mark.parametrize(
    "value,kind",
    [
        ("192.0.2.10", "ip"),
        ("example.com", "domain"),
        ("https://example.com/path", "url"),
        ("d41d8cd98f00b204e9800998ecf8427e", "hash"),
        ("analyst@example.com", "email"),
        ("CVE-2024-12345", "cve"),
    ],
)
def test_valid_indicators(value, kind):
    assert validate_indicator(value, kind) == value

@pytest.mark.parametrize(
    "value,kind",
    [
        ("999.1.1.1", "ip"),
        ("not a domain", "domain"),
        ("ftp://example.com", "url"),
        ("xyz", "hash"),
        ("not-an-email", "email"),
        ("CVE-24-1", "cve"),
    ],
)
def test_invalid_indicators(value, kind):
    with pytest.raises(HTTPException):
        validate_indicator(value, kind)

def test_json_array_validation():
    assert validate_json_list('["malware"]', "tags") == '["malware"]'
    with pytest.raises(HTTPException):
        validate_json_list('{"not":"array"}', "tags")
