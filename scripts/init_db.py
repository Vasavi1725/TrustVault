"""Initialize the configured database. Run from the project root after setting .env."""
from app.main import Base, engine

Base.metadata.create_all(bind=engine)
with engine.begin() as conn:
    if engine.dialect.name == "sqlite":
        conn.exec_driver_sql("CREATE TRIGGER IF NOT EXISTS audit_no_update BEFORE UPDATE ON audit_events BEGIN SELECT RAISE(ABORT, 'audit events are append-only'); END")
        conn.exec_driver_sql("CREATE TRIGGER IF NOT EXISTS audit_no_delete BEFORE DELETE ON audit_events BEGIN SELECT RAISE(ABORT, 'audit events are append-only'); END")
    elif engine.dialect.name == "postgresql":
        conn.exec_driver_sql("CREATE OR REPLACE FUNCTION trustvault_reject_audit_mutation() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'audit events are append-only'; END; $$")
        conn.exec_driver_sql("DROP TRIGGER IF EXISTS audit_no_update_delete ON audit_events")
        conn.exec_driver_sql("CREATE TRIGGER audit_no_update_delete BEFORE UPDATE OR DELETE ON audit_events FOR EACH ROW EXECUTE FUNCTION trustvault_reject_audit_mutation()")
print("TrustVault database tables and audit immutability triggers are ready.")
