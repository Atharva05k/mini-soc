# MiniSOC Security Event Detection System

MiniSOC is a lightweight cybersecurity monitoring project built in Python.

It ingests security event logs, detects suspicious authentication activity, and stores both raw events and generated alerts in a PostgreSQL database hosted on Supabase.

## Current Features

- Security log ingestion from CSV
- Brute-force login detection
- Password-spray detection
- Possible account compromise detection
- Time-window based brute-force detection
- Structured security alerts
- Raw event storage in PostgreSQL
- Alert storage in PostgreSQL
- Duplicate event prevention
- Duplicate alert prevention
- Supabase-hosted PostgreSQL database
- Environment-variable based credential management

## Detection Rules

### AUTH-001 — Brute Force

Detects multiple failed login attempts against the same account from the same source IP within a defined time window.

Severity: `HIGH`

### AUTH-002 — Possible Account Compromise

Detects repeated failed login attempts followed by a successful login for the same user and source IP.

Severity: `CRITICAL`

### AUTH-003 — Password Spray

Detects a single source IP attempting failed logins against multiple different user accounts.

Severity: `HIGH`

## Architecture

```text
security_logs.csv
        |
        v
      Pandas
        |
        v
 Detection Engine
   |     |      |
   |     |      |
AUTH-001 AUTH-002 AUTH-003
        |
        v
 Structured Alerts
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
 events      alerts
