#!/bin/sh
# Generate demo RSA keypair into /keys folder (private.pem, public.pem), create a self-signed cert (cert.pem)
# and export private key + cert to PKCS#12 (private.p12).
# Usage: ./generate-keys.sh [-c CN] [-d DAYS]
# Example: ./generate-keys.sh -c my-service.local -d 365

set -e

usage() {
  cat <<EOF
Usage: $0 [options]

Options:
  -c, --cn    Common Name for self-signed certificate (default: localhost)
  -d, --days  Number of days certificate is valid (default: 365)
  -h, --help  Show this help
EOF
}

# parse args
CN="localhost"
DAYS="365"
while [ $# -gt 0 ]; do
  case "$1" in
    -c|--cn)
      CN="$2"
      shift 2
      ;;
    -d|--days)
      DAYS="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown option: $1"
      usage
      exit 1
      ;;
  esac
done

if command -v realpath >/dev/null 2>&1; then
  SCRIPT_FILE=$(realpath "${BASH_SOURCE:-$0}")
  SCRIPT_DIR=$(dirname "$SCRIPT_FILE")
else
  SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE:-$0}")" >/dev/null 2>&1 && pwd)"
fi
OUT_DIR="$SCRIPT_DIR/../keys"
mkdir -p "$OUT_DIR"
PRIVATE_KEY="$OUT_DIR/private.pem"
PUBLIC_KEY="$OUT_DIR/public.pem"
CERT="$OUT_DIR/cert.pem"
P12="$OUT_DIR/private.p12"

if [ -f "$PRIVATE_KEY" ] || [ -f "$PUBLIC_KEY" ] || [ -f "$CERT" ] || [ -f "$P12" ]; then
  echo "Warning: one or more output files already exist in $OUT_DIR"
  echo "Refusing to overwrite. Remove existing files if you want to regenerate."
  exit 1
fi

echo "Generating 2048-bit RSA private key: $PRIVATE_KEY"
openssl genrsa -out "$PRIVATE_KEY" 2048

echo "Generating public key: $PUBLIC_KEY"
openssl rsa -in "$PRIVATE_KEY" -pubout -out "$PUBLIC_KEY"

echo "Creating self-signed certificate (CN=$CN, days=$DAYS): $CERT"
# use -subj to avoid interactive prompt
openssl req -new -x509 -key "$PRIVATE_KEY" -out "$CERT" -days "$DAYS" -subj "/CN=$CN"

# Prompt for optional PKCS#12 password
echo
printf "Enter password to protect the PKCS#12 file (IBM Verify requires password protected P12 key): "
stty -echo
read P12_PASS
stty echo
echo

if [ -z "$P12_PASS" ]; then
  # empty password, set to default
  PASS_ARG="pass:changeme"
else
  # careful to avoid leaking password in logs; pass via arg
  PASS_ARG="pass:$P12_PASS"
fi

echo "Exporting PKCS#12: $P12"
openssl pkcs12 -export -out "$P12" -inkey "$PRIVATE_KEY" -in "$CERT" -name "$CN" -passout "$PASS_ARG"

chmod 600 "$PRIVATE_KEY" || true
chmod 600 "$P12" || true

echo "Done. Files created in $OUT_DIR:"
echo "  - private key: $PRIVATE_KEY"
echo "  - public key:  $PUBLIC_KEY"
echo "  - cert:        $CERT"
echo "  - p12:         $P12"

cat <<EOF
Keys generated in $OUT_DIR
You can now start the container mounting this directory as /keys:
  docker run --rm -p 8080:8080 -v $OUT_DIR:/keys api-gateway-demo:local
EOF