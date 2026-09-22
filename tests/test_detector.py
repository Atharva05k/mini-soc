import pandas as pd
import pytest 

from detector import (
    create_alert,
    detect_brute_force,
    detect_password_spray,
    detect_possible_compromise,
)

def make_logs(rows) :
    logs = pd.DataFrame(
        rows,
        columns=[
            "timestamp",
            "event_type",
            "username",
            "source_ip",
            "status",
        ],
    )

    logs["timestamp"] = pd.to_datetime(logs["timestamp"])

    return logs

def test_brute_force_should_trigger():

    logs = make_logs([
        ["2026-09-17 09:00:00", "login", "admin", "192.168.1.10", "failed"],
        ["2026-09-17 09:01:00", "login", "admin", "192.168.1.10", "failed"],
        ["2026-09-17 09:02:00", "login", "admin", "192.168.1.10", "failed"],
        ["2026-09-17 09:03:00", "login", "admin", "192.168.1.10", "failed"],
        ["2026-09-17 09:04:00", "login", "admin", "192.168.1.10", "failed"],
    ])

    result = detect_brute_force(logs)

    assert len(result) ==1

def test_brute_force_should_not_trigger_outside_window():

    logs = make_logs([
        ["2026-09-17 09:00:00", "login", "admin", "192.168.1.10", "failed"],
        ["2026-09-17 09:20:00", "login", "admin", "192.168.1.10", "failed"],
        ["2026-09-17 09:40:00", "login", "admin", "192.168.1.10", "failed"],
        ["2026-09-17 10:00:00", "login", "admin", "192.168.1.10", "failed"],
        ["2026-09-17 10:20:00", "login", "admin", "192.168.1.10", "failed"],
    ])

    result = detect_brute_force(logs)

    assert result.empty

def test_password_spray_should_trigger():

    logs = make_logs([
        ["2026-09-17 11:00:00", "login", "rahul", "192.168.1.30", "failed"],
        ["2026-09-17 11:05:00", "login", "priya", "192.168.1.30", "failed"],
        ["2026-09-17 11:10:00", "login", "neha", "192.168.1.30", "failed"],
    ])

    result = detect_password_spray(logs)

    assert len(result) == 1

def test_password_spray_should_not_trigger_same_user():

    logs = make_logs([
        ["2026-09-17 11:00:00", "login", "rahul", "192.168.1.30", "failed"],
        ["2026-09-17 11:02:00", "login", "rahul", "192.168.1.30", "failed"],
        ["2026-09-17 11:04:00", "login", "rahul", "192.168.1.30", "failed"],
    ])

    result = detect_password_spray(logs)

    assert result.empty

def test_compromise_should_trigger():

    logs = make_logs([
        ["2026-09-17 09:00:00", "login", "admin", "192.168.1.10", "failed"],
        ["2026-09-17 09:01:00", "login", "admin", "192.168.1.10", "failed"],
        ["2026-09-17 09:02:00", "login", "admin", "192.168.1.10", "failed"],
        ["2026-09-17 09:03:00", "login", "admin", "192.168.1.10", "failed"],
        ["2026-09-17 09:04:00", "login", "admin", "192.168.1.10", "failed"],
        ["2026-09-17 09:05:00", "login", "admin", "192.168.1.10", "success"],
    ])

    result = detect_possible_compromise(logs)

    assert len(result)  == 1

def test_compromise_shuld_not_trigger_with_four_failures():

    logs = make_logs([
        ["2026-09-17 09:00:00", "login", "admin", "192.168.1.10", "failed"],
        ["2026-09-17 09:01:00", "login", "admin", "192.168.1.10", "failed"],
        ["2026-09-17 09:02:00", "login", "admin", "192.168.1.10", "failed"],
        ["2026-09-17 09:03:00", "login", "admin", "192.168.1.10", "failed"],
        ["2026-09-17 09:04:00", "login", "admin", "192.168.1.10", "success"]
    ])

    result = detect_possible_compromise(logs)

    assert result.empty

def test_invalid_alert_severity_should_fail():
    with pytest.raises(ValueError):
        create_alert(
            "TEST-001",
            "Test Alert",
            "INVALID",
            "192.168.1.1",
            "testuser",
            "Test alert",
        )