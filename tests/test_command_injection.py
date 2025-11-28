import pytest
from app.security.detectors.command_injection import CommandInjectionDetector


def test_command_injection_semicolon():
    detector = CommandInjectionDetector()
    payload = "test; ls -la"
    detected, reason = detector.detect(payload)
    assert detected is True


def test_command_injection_pipe():
    detector = CommandInjectionDetector()
    payload = "test | cat /etc/passwd"
    detected, reason = detector.detect(payload)
    assert detected is True


def test_command_injection_backtick():
    detector = CommandInjectionDetector()
    payload = "test `whoami`"
    detected, reason = detector.detect(payload)
    assert detected is True


def test_command_injection_ampersand():
    detector = CommandInjectionDetector()
    payload = "test && rm -rf /"
    detected, reason = detector.detect(payload)
    assert detected is True


def test_command_injection_legitimate():
    detector = CommandInjectionDetector()
    payload = "user@example.com"
    detected, reason = detector.detect(payload)
    assert detected is False

