from sqlalchemy import inspect, text
from app.database import engine, Base
from app import models

def migrate():
    inspector = inspect(engine)
    tables = inspector.get_table_names()
    if "indicators" not in tables:
        Base.metadata.create_all(bind=engine)
        return

    existing = {c["name"] for c in inspector.get_columns("indicators")}
    additions = {
        "threat_score": "INTEGER NOT NULL DEFAULT 50",
        "source": "VARCHAR(100) NOT NULL DEFAULT 'manual'",
        "confidence": "INTEGER NOT NULL DEFAULT 50",
        "tlp": "VARCHAR(20) NOT NULL DEFAULT 'clear'",
        "status": "VARCHAR(30) NOT NULL DEFAULT 'active'",
        "first_seen": "DATETIME",
        "last_seen": "DATETIME",
        "expires_at": "DATETIME",
        "tags": "TEXT NOT NULL DEFAULT '[]'",
        "attack_techniques": "TEXT NOT NULL DEFAULT '[]'",
        "analyst_notes": "TEXT",
        "updated_at": "DATETIME"
    }
    with engine.begin() as connection:
        for name, definition in additions.items():
            if name not in existing:
                connection.execute(text(f"ALTER TABLE indicators ADD COLUMN {name} {definition}"))
    Base.metadata.create_all(bind=engine)

if __name__ == "__main__":
    migrate()
