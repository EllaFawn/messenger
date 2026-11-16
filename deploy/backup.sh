#!/usr/bin/env bash
# Dumps the production database and encrypts it to a public key.
#
# The matching private key must NOT be on this server: a backup made here can
# then only be read by whoever holds that key somewhere else.
#
#   BACKUP_RECIPIENT=age1... ./deploy/backup.sh
#
# Needs: docker, and age (https://age-encryption.org; `apt install age`).
# See docs/deploy.md for creating the key, scheduling this, and restoring.
set -euo pipefail

: "${BACKUP_RECIPIENT:?Set BACKUP_RECIPIENT to your age public key (starts with age1)}"
BACKUP_DIR="${BACKUP_DIR:-./backups}"
KEEP_DAYS="${KEEP_DAYS:-14}"
COMPOSE_PROJECT="${COMPOSE_PROJECT:-messager}"
ENV_FILE="${ENV_FILE:-.env.prod}"

case "$BACKUP_RECIPIENT" in
  age1*) ;;
  *) echo "BACKUP_RECIPIENT does not look like an age public key" >&2; exit 1 ;;
esac

cd "$(dirname "$0")/.."
umask 077
mkdir -p "$BACKUP_DIR"

name="messager-$(date -u +%Y%m%dT%H%M%SZ).dump.age"
tmp="$BACKUP_DIR/.$name.partial"
trap 'rm -f "$tmp"' EXIT

# Custom-format dump, straight into encryption: no unencrypted copy touches the disk.
docker compose -p "$COMPOSE_PROJECT" -f docker-compose.prod.yml --env-file "$ENV_FILE" \
  exec -T postgres pg_dump -U messager -Fc messager \
  | age -r "$BACKUP_RECIPIENT" -o "$tmp"

if [ ! -s "$tmp" ]; then
  echo "backup is empty; keeping nothing" >&2
  exit 1
fi
mv "$tmp" "$BACKUP_DIR/$name"
chmod 600 "$BACKUP_DIR/$name"

# Drop old backups only after a new one has been written successfully.
find "$BACKUP_DIR" -name 'messager-*.dump.age' -type f -mtime "+$KEEP_DAYS" -delete

echo "wrote $BACKUP_DIR/$name"
