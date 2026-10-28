#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
ID=''; INTERMEDIARY=''; PORT=2028; INVENTORY=''; HOST=''
while (($#)); do
  case "$1" in
    --id) ID="${2:?}";shift 2;;
    --intermediario) INTERMEDIARY="${2:?}";shift 2;;
    --port) PORT="${2:?}";shift 2;;
    --inventario) INVENTORY="${2:?}";shift 2;;
    --host) HOST="${2:?}";shift 2;;
    *) echo "Argumento invalido: $1" >&2;exit 1;;
  esac
done
[[ "$ID" =~ ^SI-[A-Za-z0-9_-]+$ && -n "$INTERMEDIARY" ]] || { echo 'Uso: ./start-bodega.sh --id SI-04 --intermediario 10.1.35.5:2027 [--port 2028] [--inventario tienda.dat]' >&2; exit 1; }
IP="${INTERMEDIARY%:*}"; BROKER_PORT="${INTERMEDIARY##*:}"
[[ "$IP" != "$INTERMEDIARY" ]] || { echo 'Formato intermediario IP:PUERTO' >&2; exit 1; }
if [[ ! -f "certs/$ID.crt" || ! -f "certs/$ID.key" ]]; then
  ./TLSManager.out enroll --id "$ID" --host "$IP"
fi
export SIQP_CA_FILE="$PWD/certs/siqp-trust.crt"
export SIQP_CLIENT_CERT="$PWD/certs/$ID.crt"
export SIQP_CLIENT_KEY="$PWD/certs/$ID.key"
args=(--id "$ID" --intermediario "$INTERMEDIARY" --port "$PORT" --inventario "${INVENTORY:-$ID.dat}" --cert "$SIQP_CLIENT_CERT" --key "$SIQP_CLIENT_KEY")
[[ -z "$HOST" ]] || args+=(--host "$HOST")
exec ./ThreadMirrorServer.out "${args[@]}"
