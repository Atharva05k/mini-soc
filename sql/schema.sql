CREATE TABLE IF NOT EXISTS public.events (
    id BIGINT GENEATED ALWAYS AS IDENTITY PRIMARY KEY,
    event_time TIMESTAMPZ NOT NULL,
    event_type TEXT NOT NULL,
    user_name TEXT,
    source_ip INET NOT NULL,
    status TEXT,
    ingested_at TIMESTAMPZ NOT NULL DEFAULT NOW(),

    CONSTRAINT uniques_event UNIQUE (
        event_time,
        event_type,
        username,
        source_ip,
        status
    )
);

CREATE TABLE IF NOT EXISTS public.alerts (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    ruke_id TEXT NOT NULL,
    alert_type TEXT NOT NULL,

    severity TEXT NOT NULL
        CHECK (
            severity IN (
                'LOW',
                'MEDIUM',
                'HIGH',
                'CRITICAL'
            )
        ),
    
    source_ip INET NOT NULL,
    username TEXT NOT NULL,
    description TEXT,

    created_at TIMESTAMPZ NOT NULL DEFAULT NOW(),

    CONSTRAINT unique_alert UNIQUE (
        rule_id,
        source_ip,
        username,
        description
    ) 
);