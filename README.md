# MiniSOC — Security Event Detection & Incident Triage System

MiniSOC is a lightweight Security Operations Center (SOC) project built in Python.

It ingests authentication logs, detects suspicious activity using rule-based detection logic, and stores both raw security events and generated alerts in PostgreSQL hosted on Supabase.

The project is designed to demonstrate core SOC concepts such as event ingestion, detection engineering, time-window correlation, alert generation, database persistence, and automated testing.

---

## Features

- CSV-based security log ingestion
- PostgreSQL event storage using Supabase
- Structured security alert generation
- Duplicate event prevention
- Duplicate alert prevention
- Time-window based detection logic
- Automated detection testing with pytest
- Environment-variable based secret management

---

## Detection Rules

### AUTH-001 — Brute Force

Detects repeated failed login attempts against the same account from the same source IP within a defined time window.

**Default logic:**

- Same source IP
- Same username
- 5 or more failed login attempts
- Within 10 minutes
- Severity: HIGH

---

### AUTH-002 — Possible Account Compromise

Detects multiple failed authentication attempts followed by a successful login.

**Default logic:**

- Same source IP
- Same username
- 5 or more failed attempts
- Followed by successful authentication
- Within 10 minutes
- Severity: CRITICAL

---

### AUTH-003 — Password Spray

Detects failed authentication attempts against multiple different accounts from the same source IP.

**Default logic:**

- Same source IP
- 3 or more unique usernames
- Failed authentication attempts
- Within 10 minutes
- Severity: HIGH

---

## Architecture

```text
security_logs.csv
        |
        v
   Pandas Parser
        |
        +----------------------+
        |                      |
        v                      v
 Raw Event Storage       Detection Engine
        |                 |     |     |
        |              AUTH-001 | AUTH-003
        |                       |
        |                    AUTH-002
        |                       |
        |                       v
        |                Structured Alerts
        |                       |
        +-----------+-----------+
                    |
                    v
                  db.py
                    |
                    v
                 psycopg
                    |
                    v
           Supabase PostgreSQL
              |           |
            events       alerts
