import os

import psycopg
from dotenv import load_dotenv

load_dotenv()

database_url = os.getenv("DATABASE_URL")

if not database_url:
    raise ValueError("DATABASE_URL was not found in .env")

def save_alerts(alerts):
    saved_count = 0

    with psycopg.connect(database_url) as conn:

        with conn.cursor() as cursor:

            for alert in alerts:

             cursor.execute(
                """
                INSERT INTO public.alerts (
                    rule_id,
                    alert_type,
                    severity,
                    source_ip,
                    username
                    description
                )
                VALUES (%s, %s, %s, %s, %s, %s)
                ON CONFLICT (
                    rule_id,
                    source_ip,
                    username,
                    descrioption
                )
                DO NOTHING;
                """,
                (
                    alert["rule_id"],
                    alert["alert_type"],
                    alert["severity"],
                    alert["source_ip"],
                    alert["username"],
                    alert["description"]
                )
        )

        saved_count += cursor.rowcount

    return saved_count   