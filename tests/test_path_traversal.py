import pytest
from app.security.detectors.path_traversal import PathTraversalDetector


def test_path_traversal_basic():
    detector = PathTraversalDetector()
    payload = "../../../etc/passwd"
    detected, reason = detector.detect(payload)
    assert detected is True


def test_path_traversal_encoded():
    detector = PathTraversalDetector()
    payload = "..%2f..%2f..%2fetc%2fpasswd"
    detected, reason = detector.detect(payload)
    assert detected is True


def test_path_traversal_windows():
    detector = PathTraversalDetector()
    payload = "..\\..\\..\\windows\\system32"
    detected, reason = detector.detect(payload)
    assert detected is True


def test_path_traversal_absolute():
    detector = PathTraversalDetector()
    payload = "/etc/passwd"
    detected, reason = detector.detect(payload)
    assert detected is True


def test_path_traversal_legitimate():
    detector = PathTraversalDetector()
    payload = "/api/users/123"
    detected, reason = detector.detect(payload)
    assert detected is False

