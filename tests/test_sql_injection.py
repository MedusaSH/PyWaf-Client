import pytest
from app.security.detectors.sql_injection import SQLInjectionDetector


def test_sql_injection_union_select():
    detector = SQLInjectionDetector()
    payload = "1' UNION SELECT * FROM users--"
    detected, reason = detector.detect(payload)
    assert detected is True
    assert reason is not None


def test_sql_injection_boolean_based():
    detector = SQLInjectionDetector()
    payload = "admin' OR '1'='1"
    detected, reason = detector.detect(payload)
    assert detected is True


def test_sql_injection_time_based():
    detector = SQLInjectionDetector()
    payload = "1'; WAITFOR DELAY '00:00:05'--"
    detected, reason = detector.detect(payload)
    assert detected is True


def test_sql_injection_legitimate():
    detector = SQLInjectionDetector()
    payload = "SELECT product_name FROM products WHERE category = 'electronics'"
    detected, reason = detector.detect(payload)
    assert detected is False


def test_sql_injection_drop_table():
    detector = SQLInjectionDetector()
    payload = "'; DROP TABLE users--"
    detected, reason = detector.detect(payload)
    assert detected is True

