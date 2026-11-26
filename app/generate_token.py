"""Generate a local development JWT from explicit environment configuration."""
import argparse
from app.auth import ALLOWED_ROLES, create_development_token

parser = argparse.ArgumentParser()
parser.add_argument("--subject", required=True)
parser.add_argument("--role", action="append", required=True, choices=sorted(ALLOWED_ROLES))
parser.add_argument("--expires-minutes", type=int, default=60)
parser.add_argument("--tenant-id", help="required by future V4 tenant-aware routes")
args = parser.parse_args()
if args.expires_minutes <= 0:
    parser.error("--expires-minutes must be positive")
print(create_development_token(args.subject, args.role, args.expires_minutes, tenant_id=args.tenant_id))
