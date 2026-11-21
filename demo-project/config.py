# Controlled mock credentials for testing - NOT REAL SECRETS
# VULNERABLE: Hardcoded mock live secret in configuration file (CWE-798)
STRIPE_LIVE_KEY = "REDACTED_PLACEHOLDER"
DATABASE_URL = "postgres://admin_user:fakePassword123@db.prod.internal:5432/ecommerce_db"
