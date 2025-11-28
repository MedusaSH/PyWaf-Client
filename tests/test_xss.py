import pytest
from app.security.detectors.xss import XSSDetector


def test_xss_script_tag():
    detector = XSSDetector()
    payload = "<script>alert('XSS')</script>"
    detected, reason = detector.detect(payload)
    assert detected is True


def test_xss_javascript_protocol():
    detector = XSSDetector()
    payload = "javascript:alert('XSS')"
    detected, reason = detector.detect(payload)
    assert detected is True


def test_xss_onerror():
    detector = XSSDetector()
    payload = "<img src=x onerror=alert('XSS')>"
    detected, reason = detector.detect(payload)
    assert detected is True


def test_xss_iframe():
    detector = XSSDetector()
    payload = "<iframe src='javascript:alert(\"XSS\")'></iframe>"
    detected, reason = detector.detect(payload)
    assert detected is True


def test_xss_legitimate():
    detector = XSSDetector()
    payload = "<div>Hello World</div>"
    detected, reason = detector.detect(payload)
    assert detected is False

