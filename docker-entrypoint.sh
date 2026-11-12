#!/bin/bash
# Starts Keycloak only when every setting the realm file and the server need is present. Without this check a
# missing variable would leave a literal "${NAME}" in the imported realm (for example as a password or a client
# secret) instead of failing.
set -euo pipefail

# Every SMTP_ setting is required and must not be empty, the login and its password too: the local mail catcher
# ignores them (SMTP_AUTH=false), so a placeholder value costs nothing there, while an empty login against a real
# relay would only fail at the first verification mail, after the server had started and looked healthy. For the same
# reason the checks below refuse a switch, a port or a sender that Keycloak would accept at start and fail on at send.
# GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET are the OAuth client of the login with Google, created in the Google Cloud
# Console at deploy time; locally they are placeholders, with which the Google button fails and every other login works.
required=(
  KC_DB_URL
  KC_DB_USERNAME
  KC_DB_PASSWORD
  KC_HOSTNAME
  KC_BOOTSTRAP_ADMIN_USERNAME
  KC_BOOTSTRAP_ADMIN_PASSWORD
  CHANCE_WEB_URL
  TENANTS_CLIENT_SECRET
  PAYMENTS_CLIENT_SECRET
  MARKET_MAKER_CLIENT_SECRET
  MARKETS_CLIENT_SECRET
  TENANTS_MARKETS_CLIENT_SECRET
  PLATFORM_ADMIN_USERNAME
  PLATFORM_ADMIN_PASSWORD
  PLATFORM_ADMIN_EMAIL
  SMTP_HOST
  SMTP_PORT
  SMTP_FROM
  SMTP_SSL
  SMTP_STARTTLS
  SMTP_AUTH
  SMTP_USER
  SMTP_PASSWORD
  GOOGLE_CLIENT_ID
  GOOGLE_CLIENT_SECRET
)

missing=()
for name in "${required[@]}"; do
  if [[ -z "${!name:-}" ]]; then missing+=("$name"); fi
done
if (( ${#missing[@]} > 0 )); then
  echo "identity: missing settings: ${missing[*]}" >&2
  exit 64
fi

# Keycloak takes only the exact string "true" as on, so a typo such as "yes" would silently switch TLS or the login off.
for name in SMTP_SSL SMTP_STARTTLS SMTP_AUTH; do
  if [[ "${!name}" != "true" && "${!name}" != "false" ]]; then
    echo "identity: $name must be true or false" >&2
    exit 64
  fi
done
if [[ ! "$SMTP_PORT" =~ ^[0-9]{1,5}$ ]] || (( 10#$SMTP_PORT < 1 || 10#$SMTP_PORT > 65535 )); then
  echo "identity: SMTP_PORT must be a port number (1-65535)" >&2
  exit 64
fi
# Keycloak checks the sender only when it sends, so a name or a half address here would start a healthy-looking server
# whose every sign-up fails with "Invalid sender address". The display name is the realm's fromDisplayName, not this.
address='^[^@[:space:]]+@[^@[:space:]]+\.[^@[:space:]]+$'
if [[ ! "$SMTP_FROM" =~ $address ]]; then
  echo "identity: SMTP_FROM must be an e-mail address such as no-reply@example.com" >&2
  exit 64
fi
# The realm imports the platform admin's address as already verified, so Keycloak never mails it to check it: a name
# or a half address here would only show when the admin needs a mail.
if [[ ! "$PLATFORM_ADMIN_EMAIL" =~ $address ]]; then
  echo "identity: PLATFORM_ADMIN_EMAIL must be an e-mail address such as platform-admin@example.com" >&2
  exit 64
fi
# Never send the relay's password in plain text: a login needs TLS (SMTP_SSL, usually port 465) or STARTTLS (587).
if [[ "$SMTP_AUTH" == "true" && "$SMTP_SSL" != "true" && "$SMTP_STARTTLS" != "true" ]]; then
  echo "identity: SMTP_AUTH=true needs SMTP_SSL=true or SMTP_STARTTLS=true" >&2
  exit 64
fi
if [[ "$SMTP_SSL" == "true" && "$SMTP_STARTTLS" == "true" ]]; then
  echo "identity: set SMTP_SSL (TLS from the first byte) or SMTP_STARTTLS (upgrade after connecting), not both" >&2
  exit 64
fi

# The realm is imported only on the first start; an existing realm is never overwritten.
exec /opt/keycloak/bin/kc.sh "$@"
