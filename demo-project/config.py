# Controlled mock credentials for testing - NOT REAL SECRETS
# All secrets loaded from environment variables (CWE-798 remediation)
import os
STRIPE_LIVE_KEY = os.environ.get("STRIPE_LIVE_KEY", "REDACTED_PLACEHOLDER")
DATABASE_URL = os.environ.get("DATABASE_URL", "postgres://admin_user:@db.prod.internal:5432/ecommerce_db")
