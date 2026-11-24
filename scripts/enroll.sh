#!/usr/bin/env bash
# Enroll one device's Tailscale node key with a derp-admit verifier.
#
# The enroll token is read from the environment variable ENROLL_TOKEN or, when
# that is unset or empty, from standard input (a prompt without echo when
# standard input is a terminal). It is never accepted as an argument and never
# printed. It is taken out of the environment before any other program runs,
# and read from standard input before any other program runs, so no child
# process (tailscale, jq, python3, curl, ...) gets it in its environment, its
# arguments or its standard input; jq/python3 and curl receive it only inside
# the JSON they read from a pipe.
#
# Runs with bash 3.2 (macOS) and on Linux. Needs curl, and jq or python3.
set -euo pipefail

# First thing: move the token into an unexported shell variable.
TOKEN=${ENROLL_TOKEN:-}
unset ENROLL_TOKEN

PROG=${0##*/}

# Exit codes.
EX_OK=0
EX_USAGE=2         # bad arguments, missing --url, no token, missing --label
EX_LOCAL=3         # missing tool, cannot read the local node key
EX_NETWORK=4       # verifier not reachable (connection, DNS, TLS, timeout)
EX_BAD_REQUEST=10  # 400/413: malformed request or node key
EX_BAD_TOKEN=11    # 401: unknown enroll token
EX_FORBIDDEN=12    # 403: token revoked/expired, user disabled or gone, device limit, device revoked
EX_CONFLICT=13     # 409: node key belongs to another user
EX_RATE=14         # 429: rate limited
EX_SERVER=15       # any other status (404 wrong URL, 5xx server error, ...)
EX_NOT_VERIFIER=16 # HTTP 200 whose body is not the verifier's {"ok":true}

usage() {
  cat <<EOF
Usage: $PROG --url <verifier base URL> [--label <text>] [--node-key <key>] [--cacert <file>]

Registers a Tailscale node key with a derp-admit verifier (POST /register).

  On the device itself: omit --node-key; the key is read from the local
  Tailscale client (tailscale status --json, Self.PublicKey). --label
  defaults to the host name.

  For another device (operator): pass --node-key nodekey:<64 hex> and
  --label (required; --label '' sends no label).

Options:
  --url URL        verifier base URL, e.g. https://verifier.example.com
                   (default: \$VERIFIER_URL)
  --label TEXT     device label shown to admins
  --node-key KEY   node key to enroll instead of this device's own
  --cacert FILE    CA bundle to verify the verifier's TLS certificate (curl --cacert)
  -h, --help       show this help

Environment:
  ENROLL_TOKEN     enroll token; if unset or empty, read from standard input
  VERIFIER_URL     default for --url
  TAILSCALE_BIN    tailscale CLI to use (default: tailscale on PATH; on macOS
                   also /Applications/Tailscale.app/Contents/MacOS/Tailscale)

Exit codes:
  0 enrolled (or already enrolled for this user)
  2 usage error        3 local problem (tools, node key)   4 verifier unreachable
  10 bad request (400) 11 unknown token (401)              12 refused (403)
  13 node key belongs to another user (409)                14 rate limited (429)
  15 other HTTP status
  16 HTTP 200 but the answer is not a derp-admit verifier's (wrong --url?)
EOF
}

die() { # die CODE MESSAGE
  printf '%s: %s\n' "$PROG" "$2" >&2
  exit "$1"
}

# Value of an option that takes an argument: "--opt value" or "--opt=value".
need_arg() { # need_arg OPT NARGS
  [ "$2" -ge 2 ] || die "$EX_USAGE" "$1 needs a value (see --help)"
}

URL=${VERIFIER_URL:-}
LABEL="" LABEL_SET=0 NODE_KEY="" CACERT=""

while [ $# -gt 0 ]; do
  case $1 in
    -h|--help) usage; exit "$EX_OK" ;;
    --url) need_arg "$1" $#; URL=$2; shift 2 ;;
    --url=*) URL=${1#*=}; shift ;;
    --label) need_arg "$1" $#; LABEL=$2; LABEL_SET=1; shift 2 ;;
    --label=*) LABEL=${1#*=}; LABEL_SET=1; shift ;;
    --node-key) need_arg "$1" $#; NODE_KEY=$2; shift 2 ;;
    --node-key=*) NODE_KEY=${1#*=}; shift ;;
    --cacert) need_arg "$1" $#; CACERT=$2; shift 2 ;;
    --cacert=*) CACERT=${1#*=}; shift ;;
    --token|--token=*) die "$EX_USAGE" "the enroll token is not accepted as an argument; set ENROLL_TOKEN or pass it on standard input" ;;
    *) die "$EX_USAGE" "unknown argument: $1 (see --help)" ;;
  esac
done

# ------------------------------------------------- checks (builtins only) ---

[ -n "$URL" ] || die "$EX_USAGE" "no verifier URL: pass --url or set VERIFIER_URL"
case $URL in
  http://*|https://*) ;;
  *) die "$EX_USAGE" "--url must start with http:// or https:// (got: $URL)" ;;
esac
while [ "${URL%/}" != "$URL" ]; do URL=${URL%/}; done
if [ -n "$NODE_KEY" ] && [ "$LABEL_SET" = 0 ]; then
  die "$EX_USAGE" "--label is required with --node-key (use --label '' for none)"
fi
# Same shape the verifier accepts: "nodekey:" and 64 hex digits (builtin test).
NODE_KEY_RE='^nodekey:[0-9a-fA-F]{64}$'
check_node_key() {
  [[ $NODE_KEY =~ $NODE_KEY_RE ]] ||
    die "$EX_BAD_REQUEST" "malformed node key (expected nodekey: followed by 64 hex digits): $NODE_KEY"
}
if [ -n "$NODE_KEY" ]; then check_node_key; fi
if [ -n "$CACERT" ] && [ ! -r "$CACERT" ]; then
  die "$EX_USAGE" "--cacert file not readable: $CACERT"
fi

# Tools (command -v is a builtin), checked before asking for the token.
command -v curl >/dev/null 2>&1 || die "$EX_LOCAL" "curl not found"

JSON_TOOL=""
if command -v jq >/dev/null 2>&1; then
  JSON_TOOL=jq
elif command -v python3 >/dev/null 2>&1; then
  JSON_TOOL=python3
else
  die "$EX_LOCAL" "neither jq nor python3 found; install one of them (needed to build JSON safely)"
fi

# ------------------------------------------------------------------- token ---

# Read before any other program starts, so none of them can read it from
# standard input. "read" is a builtin.
if [ -z "$TOKEN" ]; then
  if [ -t 0 ]; then
    IFS= read -r -s -p "Enroll token: " TOKEN || true
    printf '\n' >&2
  else
    IFS= read -r TOKEN || true
  fi
fi
# Trim surrounding whitespace (the verifier trims too).
TOKEN=${TOKEN#"${TOKEN%%[![:space:]]*}"}
TOKEN=${TOKEN%"${TOKEN##*[![:space:]]}"}
[ -n "$TOKEN" ] || die "$EX_USAGE" "no enroll token: set ENROLL_TOKEN or pass it on standard input"

# No child process may inherit standard input from here on.
exec </dev/null

case $URL in
  http://127.0.0.1*|http://localhost*|http://\[::1\]*) ;;
  http://*) printf '%s: warning: %s is plain HTTP; the enroll token crosses the network unencrypted\n' "$PROG" "$URL" >&2 ;;
esac

# ---------------------------------------------------------------- node key ---

find_tailscale() {
  if [ -n "${TAILSCALE_BIN:-}" ]; then
    [ -x "$TAILSCALE_BIN" ] || command -v "$TAILSCALE_BIN" >/dev/null 2>&1 ||
      die "$EX_LOCAL" "TAILSCALE_BIN is not executable: $TAILSCALE_BIN"
    printf '%s\n' "$TAILSCALE_BIN"
    return
  fi
  if command -v tailscale >/dev/null 2>&1; then
    command -v tailscale
    return
  fi
  local mac=/Applications/Tailscale.app/Contents/MacOS/Tailscale
  if [ "$(uname -s)" = Darwin ] && [ -x "$mac" ]; then
    printf '%s\n' "$mac"
    return
  fi
  die "$EX_LOCAL" "tailscale CLI not found: install Tailscale, set TAILSCALE_BIN, or pass --node-key"
}

# Self.PublicKey from "tailscale status --json" on standard input.
self_public_key() {
  if [ "$JSON_TOOL" = jq ]; then
    jq -r '.Self.PublicKey // empty'
  else
    python3 -I -c 'import json, sys
self = json.load(sys.stdin).get("Self") or {}
print(self.get("PublicKey") or "")'
  fi
}

if [ -z "$NODE_KEY" ]; then
  TS=$(find_tailscale)
  if ! STATUS=$("$TS" status --json 2>/dev/null); then
    die "$EX_LOCAL" "'$TS status --json' failed; is tailscaled running?"
  fi
  if ! NODE_KEY=$(printf '%s' "$STATUS" | self_public_key 2>/dev/null); then
    die "$EX_LOCAL" "cannot parse the output of '$TS status --json'"
  fi
  case $NODE_KEY in
    ""|nodekey:0000000000000000000000000000000000000000000000000000000000000000)
      die "$EX_LOCAL" "this device has no node key yet; log in to your control server first (tailscale up)" ;;
  esac
  if [ "$LABEL_SET" = 0 ]; then
    LABEL=$(hostname 2>/dev/null || uname -n)
    LABEL=${LABEL%%.*}
  fi
  printf 'Node key of this device: %s\n' "$NODE_KEY" >&2
fi

check_node_key

# -------------------------------------------------------------------- body ---

# The token goes to the JSON tool on standard input (printf is a builtin).
build_body() {
  if [ "$JSON_TOOL" = jq ]; then
    printf '%s' "$TOKEN" | jq -cRs --arg nodeKey "$NODE_KEY" --arg label "$LABEL" \
      '{token: ., nodeKey: $nodeKey, label: $label}'
  else
    printf '%s' "$TOKEN" | python3 -I -c 'import json, sys
print(json.dumps({"token": sys.stdin.read(), "nodeKey": sys.argv[1], "label": sys.argv[2]}))' \
      "$NODE_KEY" "$LABEL"
  fi
}
BODY=$(build_body) || die "$EX_LOCAL" "could not build the request body with $JSON_TOOL"
TOKEN=""

# True when the response body on standard input is a JSON object with "ok": true.
is_ok_body() {
  if [ "$JSON_TOOL" = jq ]; then
    jq -e 'type == "object" and .ok == true' >/dev/null 2>&1
  else
    python3 -I -c 'import json, sys
try:
    d = json.load(sys.stdin)
except ValueError:
    sys.exit(1)
sys.exit(0 if isinstance(d, dict) and d.get("ok") is True else 1)' 2>/dev/null
  fi
}

# ------------------------------------------------------------------ request ---

CURL_OPTS=()
if [ -n "$CACERT" ]; then CURL_OPTS+=(--cacert "$CACERT"); fi

if ! RESP=$(printf '%s' "$BODY" | curl -sS --connect-timeout 10 --max-time 30 \
  ${CURL_OPTS[@]+"${CURL_OPTS[@]}"} \
  -H 'content-type: application/json' --data-binary @- \
  -w '\n%{http_code}' "$URL/register"); then
  BODY=""
  die "$EX_NETWORK" "could not reach the verifier at $URL/register (see the curl error above)"
fi
BODY=""

STATUS=${RESP##*$'\n'}
RESP_BODY=${RESP%$'\n'*}
case $STATUS in
  200)
    if ! printf '%s' "$RESP_BODY" | is_ok_body; then
      die "$EX_NOT_VERIFIER" "$URL/register answered HTTP 200 without the verifier's {\"ok\":true}: $URL does not look like a derp-admit verifier (check --url)"
    fi
    printf 'Enrolled %s%s with %s.\n' "$NODE_KEY" "${LABEL:+ (label \"$LABEL\")}" "$URL"
    exit "$EX_OK" ;;
  400|413)
    die "$EX_BAD_REQUEST" "the verifier rejected the request as malformed (HTTP $STATUS): check the node key" ;;
  401)
    die "$EX_BAD_TOKEN" "the enroll token is not known to this verifier (HTTP 401): check for typos or ask for a new token" ;;
  403)
    die "$EX_FORBIDDEN" "enrollment refused (HTTP 403): the token is revoked or expired, the user is disabled, the token's device limit is reached, or this device was revoked by an admin" ;;
  409)
    die "$EX_CONFLICT" "this node key is already enrolled for another user (HTTP 409): ask an admin" ;;
  429)
    die "$EX_RATE" "too many enrollment attempts from this address (HTTP 429): wait a few seconds and retry" ;;
  000|"")
    die "$EX_NETWORK" "no HTTP response from $URL/register" ;;
  *)
    die "$EX_SERVER" "unexpected answer from $URL/register (HTTP $STATUS); check --url, or the verifier's logs for a server error" ;;
esac
