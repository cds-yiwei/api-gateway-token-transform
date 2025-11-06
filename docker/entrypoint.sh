#!/bin/sh
# Entrypoint copies keys from a mounted /keys directory into the OpenResty conf/keys
# directory. Keys are expected to be generated separately (see docker/keys/generate-keys.sh).

CONF_DIR="/usr/local/openresty/nginx/conf"
KEY_DIR="$CONF_DIR/keys"
SRC_KEYS_DIR="/keys"
PRIVATE_KEY="$KEY_DIR/private.pem"
PUBLIC_KEY="$KEY_DIR/public.pem"

echo "Ensuring key directory exists: $KEY_DIR"
mkdir -p "$KEY_DIR"
chown openresty:openresty "$KEY_DIR" || true

if [ -f "$PRIVATE_KEY" ] && [ -f "$PUBLIC_KEY" ]; then
  echo "Keys already present in $KEY_DIR, skipping copy"
else
  echo "Looking for keys in $SRC_KEYS_DIR"
  if [ -f "$SRC_KEYS_DIR/private.pem" ] && [ -f "$SRC_KEYS_DIR/public.pem" ]; then
    echo "Copying keys from $SRC_KEYS_DIR to $KEY_DIR"
    cp "$SRC_KEYS_DIR/private.pem" "$PRIVATE_KEY"
    cp "$SRC_KEYS_DIR/public.pem" "$PUBLIC_KEY"
    chmod 600 "$PRIVATE_KEY"
    chown openresty:openresty "$PRIVATE_KEY" "$PUBLIC_KEY" || true
  else
    echo "ERROR: keys not found in $SRC_KEYS_DIR and none present in $KEY_DIR"
    echo "Please provide private.pem and public.pem under a mounted /keys volume or place them into $KEY_DIR"
    exit 1
  fi
fi

# Exec the passed command (OpenResty) so signals are forwarded correctly
exec "$@"
