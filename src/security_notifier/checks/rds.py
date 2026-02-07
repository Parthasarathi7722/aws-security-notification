"""RDS security check."""
import logging

logger = logging.getLogger(__name__)


def run(config, clients):
    """Get RDS security issues.

    Returns list of {"severity": str, "description": str}.
    """
    events = []
    try:
        rds = clients.get("rds")
        response = rds.describe_db_instances(MaxRecords=50)
        for db in response.get("DBInstances", []):
            db_id = db.get("DBInstanceIdentifier")

            if db.get("PubliclyAccessible"):
                events.append({
                    "severity": "CRITICAL",
                    "description": f"CRITICAL: Database {db_id} is publicly accessible",
                })

            if not db.get("StorageEncrypted"):
                events.append({
                    "severity": "CRITICAL",
                    "description": f"CRITICAL: Database {db_id} storage is not encrypted",
                })

            if db.get("BackupRetentionPeriod", 0) == 0:
                events.append({
                    "severity": "HIGH",
                    "description": f"Database {db_id} has no automated backups enabled",
                })

            if not db.get("DeletionProtection", False):
                events.append({
                    "severity": "HIGH",
                    "description": f"Database {db_id} has deletion protection disabled",
                })
    except Exception as e:
        logger.error(f"RDS check error: {e}")
    return events
