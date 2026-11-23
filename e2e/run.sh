#!/usr/bin/env bash
# End-to-end test of derp-admit with real Tailscale clients.
#
#   e2e/run.sh            build, start, provision, assert A..G, tear down
#   e2e/run.sh --keep     same, but leave the stack and the machines running
#   e2e/run.sh --build    force rebuilding the local images first
#   e2e/run.sh --prebuilt never build or pull: use images already loaded on
#                         this host (same as E2E_PREBUILT=1; see README)
#   e2e/run.sh --down     only tear down (same as e2e/down.sh)
#
# Servers (postgres, verifier, derper, headscale, tools) run in Docker Compose
# project "derp-admit-e2e". The three Tailscale clients run in OrbStack Linux
# machines derp-e2e-a, derp-e2e-b, derp-e2e-c (kernel TUN, real tailscaled).
# See e2e/README.md.
set -euo pipefail
trap 'echo "run.sh: command failed at line $LINENO: $BASH_COMMAND" >&2' ERR

HERE=$(cd "$(dirname "$0")" && pwd)
PROJECT=derp-admit-e2e
COMPOSE_FILE="$HERE/docker-compose.yml"

MACHINE_DISTRO=ubuntu:noble   # Ubuntu 24.04 LTS
TS_VERSION=1.104.7            # tailscale package from pkgs.tailscale.com (stable)
MA=derp-e2e-a MB=derp-e2e-b MC=derp-e2e-c
MACHINES=("$MA" "$MB" "$MC")

DERP_HOST=derp.e2e.test       # DERP map HostName == cert SAN == /etc/hosts name
HS_HOST=headscale.e2e.test
DERP_PORT=39443               # loopback-published ports (docker-compose.yml)
HS_PORT=39080
REGION=900                    # region id in headscale/derp.yaml
REGION_CODE=e2e-derp
RELAY=e2e                     # derper --verify-client-url=.../verify/e2e
ROLE=e2e-access

KEEP=0 BUILD=0 DOWN_ONLY=0 PREBUILT=${E2E_PREBUILT:-0}
for arg in "$@"; do
  case $arg in
    --keep) KEEP=1 ;;
    --build) BUILD=1 ;;
    --prebuilt) PREBUILT=1 ;;
    --down) DOWN_ONLY=1 ;;
    -h|--help) sed -n '2,16p' "$0"; exit 0 ;;
    *) echo "unknown argument: $arg" >&2; exit 2 ;;
  esac
done

# ---------------------------------------------------------------- output ---

T0=$(date +%s)
declare -a SUMMARY=()
FAILED=0

say() { printf '%s\n' "$*"; }
section() { printf '\n==== %s\n' "$*"; }
info() { printf -- '-- %s\n' "$*"; }
# evidence LABEL TEXT: print TEXT (possibly multi-line) indented under LABEL.
evidence() {
  printf '   [%s]\n' "$1"
  if [ -n "${2:-}" ]; then
    printf '%s\n' "$2" | sed 's/^/     | /'
  else
    printf '     | (nothing)\n'
  fi
}
result() { # result ID STATUS TEXT
  printf '%s %s: %s\n' "$2" "$1" "$3"
  SUMMARY+=("$2 $1: $3")
  if [ "$2" = FAIL ]; then FAILED=1; fi
}
die() { printf 'FATAL: %s\n' "$*" >&2; exit 1; }

# ---------------------------------------------------------------- tools ----

dc() { docker compose -p "$PROJECT" -f "$COMPOSE_FILE" "$@"; }
tool() { dc exec -T tools e2etool "$@"; }
api() { tool api "$@"; }
tmpl() { dc exec -T tools e2etool tmpl "$1"; }        # JSON on stdin
hs() { dc exec -T headscale headscale "$@"; }
now() { dc exec -T tools date -u +%s; }                 # clock of the Docker VM
iso() { dc exec -T tools date -u -d "@$1" +%Y-%m-%dT%H:%M:%SZ; }

# Run a command as root inside an OrbStack machine. Working directory "/" so
# no macOS path is ever involved; scripts are passed as argv, data via stdin.
m() { local name=$1; shift; orb run -m "$name" -u root -w / "$@"; }
mbash() { local name=$1 script=$2; shift 2; m "$name" bash -c "$script" e2e "$@"; }

retry() { # retry TRIES DELAY cmd...
  local n=$1 d=$2 i; shift 2
  for ((i = 1; i <= n; i++)); do
    if "$@"; then return 0; fi
    [ "$i" -lt "$n" ] && sleep "$d"
  done
  return 1
}

# wait_until TIMEOUT cmd...: poll every second.
wait_until() {
  local t=$1 i; shift
  for ((i = 0; i < t; i++)); do
    if "$@" >/dev/null 2>&1; then return 0; fi
    sleep 1
  done
  return 1
}

machine_state() { orb list 2>/dev/null | awk -v n="$1" '$1 == n { print $2 }'; }

# ------------------------------------------------------- machine scripts ---

# Install the pinned tailscale package from pkgs.tailscale.com (once).
# shellcheck disable=SC2016 # expanded inside the machine
PROVISION_SCRIPT='
set -euo pipefail
ver=$1
export DEBIAN_FRONTEND=noninteractive
retry() { for i in 1 2 3 4 5; do "$@" && return 0; sleep 5; done; return 1; }
have=$(dpkg-query -W -f="\${Version}" tailscale 2>/dev/null || true)
if [ "$have" != "$ver" ]; then
  retry apt-get -q -o Acquire::Retries=5 update
  retry apt-get -q -o Acquire::Retries=5 install -y --no-install-recommends \
    curl ca-certificates jq nftables iputils-ping iproute2 gnupg
  retry curl -fsSL --retry 5 -o /usr/share/keyrings/tailscale-archive-keyring.gpg \
    https://pkgs.tailscale.com/stable/ubuntu/noble.noarmor.gpg
  echo "deb [signed-by=/usr/share/keyrings/tailscale-archive-keyring.gpg] https://pkgs.tailscale.com/stable/ubuntu noble main" \
    > /etc/apt/sources.list.d/tailscale.list
  retry apt-get -q -o Acquire::Retries=5 update
  retry apt-get -q -o Acquire::Retries=5 install -y --allow-downgrades "tailscale=$ver"
  apt-mark hold tailscale >/dev/null
fi
# No log upload to Tailscale Inc.; fixed WireGuard port.
cat > /etc/default/tailscaled <<EOF
PORT="41641"
FLAGS="--no-logs-no-support"
TS_NO_LOGS_NO_SUPPORT=true
EOF
systemctl enable tailscaled >/dev/null 2>&1 || true
echo "tailscale $(dpkg-query -W -f="\${Version}" tailscale) installed"
'

# Reset the machine for a run: wipe tailscaled state, point the two rig host
# names at host.orb.internal (where OrbStack exposes the Docker host's
# loopback-published ports to machines), trust the CA read from stdin, and
# drop all traffic to and from the other machines (args: V4PEERS V6PEERS,
# comma separated, possibly empty).
# shellcheck disable=SC2016 # expanded inside the machine
RESET_SCRIPT='
set -euo pipefail
v4=$1 v6=$2
svc=$(getent ahostsv4 host.orb.internal | awk "NR == 1 { print \$1 }")
[ -n "$svc" ] || { echo "cannot resolve host.orb.internal" >&2; exit 1; }
systemctl stop tailscaled
rm -rf /var/lib/tailscale
sed -i "/# derp-admit-e2e\$/d" /etc/hosts
printf "%s derp.e2e.test # derp-admit-e2e\n%s headscale.e2e.test # derp-admit-e2e\n" "$svc" "$svc" >> /etc/hosts
cat > /usr/local/share/ca-certificates/derp-admit-e2e.crt
update-ca-certificates --fresh >/dev/null 2>&1
nft delete table inet derp_e2e 2>/dev/null || true
{
  echo "table inet derp_e2e {"
  echo "  chain pre { type filter hook prerouting priority raw; policy accept;"
  [ -n "$v4" ] && echo "    ip saddr { $v4 } drop"
  [ -n "$v6" ] && echo "    ip6 saddr { $v6 } drop"
  echo "  }"
  echo "  chain out { type filter hook output priority raw; policy accept;"
  [ -n "$v4" ] && echo "    ip daddr { $v4 } drop"
  [ -n "$v6" ] && echo "    ip6 daddr { $v6 } drop"
  echo "  }"
  echo "}"
} | nft -f -
systemctl start tailscaled
for i in $(seq 1 30); do [ -S /run/tailscale/tailscaled.sock ] && break; sleep 1; done
echo "reset done; derp.e2e.test and headscale.e2e.test -> $svc (host.orb.internal)"
'

# Undo everything RESET_SCRIPT did (run before the machines are stopped).
CLEAN_SCRIPT='
systemctl stop tailscaled 2>/dev/null || true
rm -rf /var/lib/tailscale
sed -i "/# derp-admit-e2e\$/d" /etc/hosts
rm -f /usr/local/share/ca-certificates/derp-admit-e2e.crt
update-ca-certificates --fresh >/dev/null 2>&1 || true
nft delete table inet derp_e2e 2>/dev/null || true
echo "machine cleaned"
'

# ------------------------------------------------------------- teardown ----

teardown() {
  section "teardown"
  dc down -v --remove-orphans 2>&1 | sed 's/^/   /' || true
  if command -v orb >/dev/null 2>&1; then
    local n
    for n in "${MACHINES[@]}"; do
      if [ "$(machine_state "$n")" = running ]; then
        mbash "$n" "$CLEAN_SCRIPT" 2>&1 | sed "s/^/   $n: /" || true
        orb stop "$n" >/dev/null 2>&1 || true   # always by exact name
      fi
    done
    orb list 2>/dev/null | awk '$1 ~ /^derp-e2e-[abc]$/' | sed 's/^/   /'
  fi
}

if [ "$DOWN_ONLY" = 1 ]; then
  teardown
  exit 0
fi

command -v docker >/dev/null || die "docker not found"
command -v orb >/dev/null || die "orb (OrbStack) not found: the clients run in OrbStack machines"

on_exit() {
  local rc=$?
  if [ "$KEEP" = 1 ]; then
    section "--keep: stack and machines left running; remove with e2e/down.sh"
  else
    teardown
  fi
  section "summary ($(($(date +%s) - T0))s)"
  local l
  for l in ${SUMMARY[@]+"${SUMMARY[@]}"}; do say "$l"; done
  if [ "$rc" -ne 0 ] || [ "$FAILED" -ne 0 ]; then
    say "RESULT: FAIL"
    exit 1
  fi
  say "RESULT: PASS"
}
trap on_exit EXIT

# --------------------------------------------------------------- images ----

section "images"
images_missing() {
  local i
  for i in derp-admit-e2e-verifier:local derp-admit-e2e-derper:v1.84.3 derp-admit-e2e-tools:local; do
    docker image inspect "$i" >/dev/null 2>&1 || return 0
  done
  return 1
}
if [ "$PREBUILT" = 1 ]; then
  info "prebuilt mode: no build, no pull"
  for img in $(dc config --images | sort -u); do
    docker image inspect "$img" >/dev/null 2>&1 || die "prebuilt mode: image $img is not loaded"
  done
elif [ "$BUILD" = 1 ] || images_missing; then
  info "building verifier, derper and tools images"
  retry 3 10 dc build || die "image build failed"
fi
for img in $(dc config --images | sort -u); do
  [ "$PREBUILT" = 1 ] && break
  case $img in derp-admit-e2e-*) continue ;; esac
  if ! docker image inspect "$img" >/dev/null 2>&1; then
    info "pulling $img"
    retry 5 10 docker pull -q "$img" || die "cannot pull $img"
  fi
done
dc config --images | sort -u | while read -r img; do
  printf '   %s %s\n' "$img" "$(docker image inspect -f '{{.Id}}' "$img" | cut -c1-19)"
done

# ---------------------------------------------------------------- stack ----

section "stack"
dc down -v --remove-orphans >/dev/null 2>&1 || true
dc up -d --wait --no-build --pull never 2>&1 | sed 's/^/   /'
evidence "published ports (loopback only)" "$(docker ps --filter "label=com.docker.compose.project=$PROJECT" --format '{{.Names}} {{.Ports}}' | grep -- '->' || true)"

# ------------------------------------------------------------- machines ----

section "machines"
ensure_machine() {
  local n=$1 st i
  st=$(machine_state "$n")
  if [ "$st" = creating ]; then
    info "$n: waiting for an earlier creation to finish"
    for ((i = 0; i < 600; i++)); do st=$(machine_state "$n"); [ "$st" != creating ] && break; sleep 1; done
  fi
  if [ -z "$st" ]; then
    for i in 1 2 3 4 5; do
      info "$n: orb create $MACHINE_DISTRO $n (try $i)"
      if orb create "$MACHINE_DISTRO" "$n"; then break; fi
      if [ -n "$(machine_state "$n")" ]; then orb delete -f "$n" >/dev/null 2>&1 || true; fi
      sleep 10
    done
    st=$(machine_state "$n")
  fi
  case $st in
    running) ;;
    stopped) orb start "$n" >/dev/null ;;
    *) die "$n: unexpected machine state '$st'" ;;
  esac
  retry 5 10 mbash "$n" "$PROVISION_SCRIPT" "$TS_VERSION" 2>&1 | tail -1 | sed "s/^/   $n: /"
}
for n in "${MACHINES[@]}"; do ensure_machine "$n"; done

mip4() { m "$1" ip -4 -o addr show dev eth0 | awk '{ sub("/.*", "", $4); print $4; exit }'; }
mip6() { m "$1" ip -6 -o addr show dev eth0 scope global | awk '{ sub("/.*", "", $4); print $4 }' | paste -sd, -; }
# Indexed like MACHINES (bash 3.2 on macOS has no associative arrays).
IP4S=() IP6S=()
for i in 0 1 2; do
  IP4S[i]=$(mip4 "${MACHINES[i]}")
  IP6S[i]=$(mip6 "${MACHINES[i]}")
  info "${MACHINES[i]}: eth0 ${IP4S[i]} ${IP6S[i]:-(no global IPv6)}"
done
ip4of() { local i; for i in 0 1 2; do if [ "${MACHINES[i]}" = "$1" ]; then echo "${IP4S[i]}"; fi; done; }
ip6of() { local i; for i in 0 1 2; do if [ "${MACHINES[i]}" = "$1" ]; then echo "${IP6S[i]}"; fi; done; }

CA_PEM=$(dc exec -T tools cat /pki/ca.crt)
for n in "${MACHINES[@]}"; do
  v4="" v6=""
  for p in "${MACHINES[@]}"; do
    [ "$p" = "$n" ] && continue
    v4="${v4:+$v4, }$(ip4of "$p")"
    p6=$(ip6of "$p")
    if [ -n "$p6" ]; then v6="${v6:+$v6, }${p6//,/, }"; fi
  done
  printf '%s\n' "$CA_PEM" | mbash "$n" "$RESET_SCRIPT" "$v4" "$v6" | sed "s/^/   $n: /"
done

# ------------------------------------------------------------ provision ----

section "provision headscale and verifier"
hs users create e2e >/dev/null
HS_UID=$(hs users list -o json | tmpl '{{range .}}{{if eq (str .name) "e2e"}}{{.id}}{{end}}{{end}}')
[ -n "$HS_UID" ] || die "headscale user not found"
AUTHKEY=$(hs preauthkeys create --user "$HS_UID" --reusable --expiration 2h -o json | tmpl '{{.key}}')
[ -n "$AUTHKEY" ] || die "no headscale pre-auth key"
info "headscale user e2e (id $HS_UID) and a reusable pre-auth key created"

api POST /admin/relays "{\"name\":\"$RELAY\",\"description\":\"e2e derper\"}" >/dev/null
api POST /admin/roles "{\"name\":\"$ROLE\",\"relays\":[\"$RELAY\"]}" >/dev/null
ALICE=$(api POST /admin/users "{\"username\":\"alice\",\"roles\":[\"standard\",\"$ROLE\"]}" | tmpl '{{.user.id}}')
CAROL=$(api POST /admin/users "{\"username\":\"carol\",\"roles\":[\"standard\",\"$ROLE\"]}" | tmpl '{{.user.id}}')
TOK_ALICE=$(api POST /admin/tokens "{\"userId\":\"$ALICE\",\"maxDevices\":5}" | tmpl '{{.token}}')
TOK_CAROL=$(api POST /admin/tokens "{\"userId\":\"$CAROL\",\"maxDevices\":5}" | tmpl '{{.token}}')
evidence "verifier roles" "$(api GET /admin/roles | tmpl '{{range .roles}}{{.name}} -> {{json .relays}}
{{end}}')"
evidence "verifier users" "$(api GET /admin/users | tmpl '{{range .users}}{{.username}} -> {{json .roles}}
{{end}}')"

# ------------------------------------------------------------- helpers -----

nodekey() { m "$1" tailscale status --json | tmpl '{{.Self.PublicKey}}'; }
tsip() { m "$1" tailscale ip -4; }
shortkey() { tool shortkey "$1"; }
register() { # register MACHINE TOKEN
  api POST /register "{\"token\":\"$2\",\"nodeKey\":\"$(nodekey "$1")\",\"label\":\"$1\"}"
}
journal_since() { m "$1" journalctl -u tailscaled --no-pager -o short-iso --since "@$2"; }
derp_connected_since() { journal_since "$1" "$2" | grep -E "magicsock: derp-$REGION connected"; }
derp_recv_err_since() { journal_since "$1" "$2" | grep -E "derp.Recv\\(derp-$REGION\\)"; }
derper_since() { dc logs --no-log-prefix --since "$1" derper 2>&1; }
derper_registered_since() { derper_since "$1" | grep -F "$(shortkey "$2")" | grep -F "register single client"; }
derper_rejected_since() { derper_since "$1" | grep -F "client $2 rejected"; }
audit() { # audit NODEKEY [SINCE_EPOCH]: newest verify audit rows for the key
  local q="nodeKey=$1&limit=${AUDIT_LIMIT:-3}"
  if [ -n "${2:-}" ]; then q="$q&since=$(iso "$2")"; fi
  api GET "/admin/audit/verify?$q" |
    tmpl '{{range .entries}}{{.ts}} relay={{str .relay}} allowed={{.allowed}} reason="{{str .reason}}" nodeKey={{.nodeKey}}
{{end}}'
}
audit_newest_is() { # audit_newest_is NODEKEY SINCE ALLOWED [REASON]
  local row
  row=$(AUDIT_LIMIT=1 audit "$1" "$2")
  [ -n "$row" ] || return 1
  grep -q "allowed=$3 " <<<"$row" || return 1
  if [ -n "${4:-}" ]; then grep -qF "reason=\"$4\"" <<<"$row" || return 1; fi
  grep -qF "relay=$RELAY " <<<"$row"
}
health() { m "$1" tailscale status --json | tmpl '{{range .Health}}{{.}}
{{end}}'; }
ts_ping() { m "$1" tailscale ping --until-direct=false -c 3 --timeout 3s "$2" 2>&1; }
relayed_ok() { grep -q "via DERP($REGION_CODE)" <<<"$1" && ! grep -Eq 'via [0-9a-f\[]' <<<"$1"; }
peer_path() { # peer_path FROM PEER_TSIP: CurAddr and Relay of the peer in FROM's status
  m "$1" tailscale status --json | tmpl "{{range .Peer}}{{if eq (index .TailscaleIPs 0) \"$2\"}}peer={{.HostName}} CurAddr=\"{{.CurAddr}}\" Relay={{.Relay}} Online={{.Online}}{{end}}{{end}}"
}
device_id() { api GET "/admin/devices?userId=$1" | tmpl "{{range .devices}}{{if eq .nodeKey \"$2\"}}{{.id}}{{end}}{{end}}"; }
up() { m "$1" tailscale up --login-server="http://$HS_HOST:$HS_PORT" --authkey="$AUTHKEY" \
  --hostname="$1" --accept-dns=false --accept-routes=false --timeout=90s; }

# ------------------------------------------------- preconditions (P1-P3) ---

section "P: rig preconditions"
for n in "${MACHINES[@]}"; do
  evidence "$n: uname -a / tailscale version" "$(m "$n" uname -a)
$(m "$n" tailscale version | head -1)"
done
probe=$(m "$MA" curl -sS -o /dev/null -w 'HTTP %{http_code}, ssl_verify_result=%{ssl_verify_result}, %{remote_ip}:%{remote_port}' "https://$DERP_HOST:$DERP_PORT/derp/probe" 2>&1 || true)
evidence "$MA: curl https://$DERP_HOST:$DERP_PORT/derp/probe (system trust store, throwaway CA)" "$probe"
if grep -q "HTTP 200, ssl_verify_result=0" <<<"$probe"; then
  result P1 PASS "machine reaches derper over verified TLS for $DERP_HOST"
else
  result P1 FAIL "TLS probe to derper failed"
fi

blocked=1 out=""
for pair in "$MA $MC" "$MC $MA" "$MA $MB" "$MB $MA" "$MB $MC" "$MC $MB"; do
  read -r f t <<<"$pair"
  t4=$(ip4of "$t") t6=$(ip6of "$t")
  if o=$(m "$f" ping -c 1 -W 2 "$t4" 2>&1); then blocked=0; fi
  out+="$f -> $t $t4: $(tail -2 <<<"$o" | head -1)"$'\n'
  for a6 in ${t6//,/ }; do
    if o=$(m "$f" ping -6 -c 1 -W 2 "$a6" 2>&1); then blocked=0; fi
    out+="$f -> $t $a6: $(tail -2 <<<"$o" | head -1)"$'\n'
  done
done
ctl=$(m "$MA" ping -c 1 -W 2 "$(ip4of "$MA")" 2>&1 | tail -2 | head -1 || true)
evidence "plain ping between machine addresses (must fail; last line: own address as control)" "${out}$MA -> itself: $ctl"
if [ "$blocked" = 1 ]; then
  result P2 PASS "no direct IP path between any two machines (IPv4 and IPv6 dropped by nft table inet derp_e2e)"
else
  result P2 FAIL "a direct path between machines still works"
fi

# ------------------------------------------------------- A: positive -------

section "A: positive control"
MARK_UP=$(now)
up "$MA"
KEY_A=$(nodekey "$MA")
register "$MA" "$TOK_ALICE" >/dev/null
up "$MC"
KEY_C=$(nodekey "$MC")
register "$MC" "$TOK_CAROL" >/dev/null
TSIP_A=$(tsip "$MA") TSIP_C=$(tsip "$MC")
info "$MA $KEY_A $TSIP_A (user alice); $MC $KEY_C $TSIP_C (user carol)"
# shellcheck disable=SC2016 # Go template, not shell
evidence "$MA: tailscale debug derp-map (regions, nodes)" "$(m "$MA" tailscale debug derp-map | tmpl '{{range $id, $r := .Regions}}region {{$id}} code={{$r.RegionCode}}{{range $r.Nodes}} node={{.Name}} HostName={{.HostName}} DERPPort={{.DERPPort}} STUNPort={{.STUNPort}} CertName="{{str .CertName}}" InsecureForTests={{str .InsecureForTests}}{{end}}
{{end}}')"
evidence "headscale nodes list" "$(hs nodes list 2>&1)"

if wait_until 60 derp_connected_since "$MA" "$MARK_UP" && wait_until 30 audit_newest_is "$KEY_A" "$MARK_UP" true; then ok=1; else ok=0; fi
c_log=$(derp_connected_since "$MA" "$MARK_UP" | tail -2 || true)
d_log=$(derper_registered_since "$MARK_UP" "$KEY_A" | tail -2 || true)
a_row=$(AUDIT_LIMIT=1 audit "$KEY_A" "$MARK_UP")
state=$(m "$MA" tailscale status --json | tmpl '{{with .Self}}Self.HostName={{.HostName}} Self.Relay={{.Relay}} Online={{.Online}}{{end}}')
evidence "$MA tailscaled journal" "$c_log"
evidence "$MA tailscale status --json" "$state
health: $(health "$MA" | tr '\n' ' ')"
evidence "derper log ($(shortkey "$KEY_A") = $MA)" "$d_log"
evidence "verify audit, newest row for $MA" "$a_row"
if [ "$ok" = 1 ] && [ -n "$c_log" ] && [ -n "$d_log" ] && grep -q "Self.Relay=$REGION_CODE" <<<"$state"; then
  result A PASS "$MA holds a DERP connection to our derper, admitted by the verifier"
else
  result A FAIL "$MA not shown connected (journal/derper/audit/status above)"
fi

# --------------------------------------------------- B: relayed traffic ----

section "B: relayed traffic between $MA and $MC (no direct path)"
wait_until 60 derp_connected_since "$MC" "$MARK_UP" || true
p=$(ts_ping "$MA" "$TSIP_C" || true)
icmp=$(m "$MA" ping -c 2 -W 3 "$TSIP_C" 2>&1 | tail -3 || true)
path=$(peer_path "$MA" "$TSIP_C")
evidence "$MA: tailscale ping --until-direct=false -c 3 $TSIP_C" "$p"
evidence "$MA: ping -c 2 $TSIP_C (ICMP through tailscale0)" "$icmp"
evidence "$MA: status of peer $MC" "$path"
if relayed_ok "$p" && grep -q 'CurAddr=""' <<<"$path"; then
  result B PASS "$MA <-> $MC traffic flows only via DERP($REGION_CODE)"
else
  result B FAIL "ping not relayed via our derper"
fi

# ------------------------------------------------------- C: deny -----------

section "C: unregistered client $MB is refused"
MARK_B=$(now)
up "$MB"
KEY_B=$(nodekey "$MB")
TSIP_B=$(tsip "$MB")
info "$MB $KEY_B $TSIP_B (not registered)"
wait_until 60 derper_rejected_since "$MARK_B" "$KEY_B" || true
# The "Relay server unavailable" health warning needs 10s to become visible.
wait_until 30 sh -c "orb run -m $MB -u root -w / tailscale status --json | grep -q 'could not connect to the'" || true
rej=$(derper_rejected_since "$MARK_B" "$KEY_B" | tail -2 || true)
row=$(AUDIT_LIMIT=1 audit "$KEY_B" "$MARK_B")
conn=$(derp_connected_since "$MB" "$MARK_B" || true)
errs=$(derp_recv_err_since "$MB" "$MARK_B" | tail -2 || true)
hb=$(health "$MB")
p=$(ts_ping "$MA" "$TSIP_B" || true)
evidence "derper log" "$rej"
evidence "verify audit, newest row for $MB" "$row"
evidence "$MB journal: 'derp-$REGION connected' lines" "$conn"
evidence "$MB journal: DERP receive errors" "$errs"
evidence "$MB tailscale status --json .Health" "$hb"
evidence "$MA: tailscale ping $TSIP_B" "$p"
if [ -n "$rej" ] && grep -q 'allowed=false reason="not registered"' <<<"$row" && [ -z "$conn" ] &&
  { grep -q "could not connect" <<<"$hb" || [ -n "$errs" ]; } && ! grep -q "pong from" <<<"$p"; then
  result C PASS "derper refused $MB because the verifier answered 'not registered'"
else
  result C FAIL "deny of $MB not shown"
fi

# ------------------------------------------------------- D: flip -----------

section "D: register $MB, it is admitted"
MARK_D=$(now)
evidence "POST /register for $MB" "$(register "$MB" "$TOK_ALICE")"
# b keeps retrying its home DERP (magicsock backoff <= 5s); the next attempt is admitted.
wait_until 60 derp_connected_since "$MB" "$MARK_D" || true
wait_until 30 audit_newest_is "$KEY_B" "$MARK_D" true || true
conn=$(derp_connected_since "$MB" "$MARK_D" | tail -1 || true)
reg=$(derper_registered_since "$MARK_D" "$KEY_B" | tail -1 || true)
row=$(AUDIT_LIMIT=1 audit "$KEY_B" "$MARK_D")
p=$(ts_ping "$MA" "$TSIP_B" || true)
evidence "$MB journal" "$conn"
evidence "derper log ($(shortkey "$KEY_B") = $MB)" "$reg"
evidence "verify audit, newest row for $MB" "$row"
evidence "$MA: tailscale ping $TSIP_B" "$p"
if [ -n "$conn" ] && [ -n "$reg" ] && grep -q 'allowed=true' <<<"$row" && relayed_ok "$p"; then
  result D PASS "$MB admitted after registration, traffic via DERP"
else
  result D FAIL "$MB not admitted after registration"
fi

# --------------------------------------------------- E: revocation ---------

section "E: revoke $MA (derper verifies at connect time only)"
DEV_A=$(device_id "$ALICE" "$KEY_A")
MARK_E=$(now)
evidence "POST /admin/devices/<id of $MA>/revoke" "$(api POST "/admin/devices/$DEV_A/revoke" "{}")"
sleep 8
p=$(ts_ping "$MA" "$TSIP_C" || true)
rows=$(audit "$KEY_A" "$MARK_E")
dl=$(derper_since "$MARK_E" | grep -F -e "$KEY_A" -e "$(shortkey "$KEY_A")" | grep -v "read frame" | tail -3 || true)
errs=$(derp_recv_err_since "$MA" "$MARK_E" || true)
evidence "$MA: tailscale ping $TSIP_C, 8s after the revoke" "$p"
evidence "verify audit rows for $MA since the revoke" "$rows"
evidence "derper log about $MA since the revoke (frame reads omitted)" "$dl"
evidence "$MA journal: DERP receive errors since the revoke" "$errs"
if relayed_ok "$p" && [ -z "$rows" ] && [ -z "$errs" ]; then e1=1; else e1=0; fi

MARK_E2=$(now)
evidence "$MA: tailscale debug break-derp-conns" "$(m "$MA" tailscale debug break-derp-conns 2>&1; journal_since "$MA" "$MARK_E2" | grep -E 'closing connection to derp|break' | tail -2)"
wait_until 30 derper_rejected_since "$MARK_E2" "$KEY_A" || true
wait_until 30 audit_newest_is "$KEY_A" "$MARK_E2" false revoked || true
sleep 3
rej=$(derper_rejected_since "$MARK_E2" "$KEY_A" | tail -1 || true)
row=$(AUDIT_LIMIT=1 audit "$KEY_A" "$MARK_E2")
conn=$(derp_connected_since "$MA" "$MARK_E2" || true)
p=$(ts_ping "$MA" "$TSIP_C" || true)
evidence "derper log" "$rej"
evidence "verify audit, newest row for $MA" "$row"
evidence "$MA journal: 'derp-$REGION connected' since the reconnect" "$conn"
evidence "$MA: tailscale ping $TSIP_C" "$p"
if [ "$e1" = 1 ] && [ -n "$rej" ] && grep -q 'allowed=false reason="revoked"' <<<"$row" && [ -z "$conn" ] &&
  ! grep -q "pong from" <<<"$p"; then
  result E PASS "revoked $MA kept its open DERP connection until it reconnected, then was refused with 'revoked'"
else
  result E FAIL "revocation behaviour not shown (connected-after-revoke=$e1)"
fi

info "re-enable $MA for the remaining assertions"
MARK_EN=$(now)
api POST "/admin/devices/$DEV_A/enable" "{}" >/dev/null
wait_until 60 derp_connected_since "$MA" "$MARK_EN" || info "$MA did not come back"
info "$(derp_connected_since "$MA" "$MARK_EN" | tail -1 || true)"

# ------------------------------------------------ F: per-relay policy ------

section "F: per-relay policy on relay '$RELAY'"
evidence "derper arguments" "$(docker inspect -f '{{join .Args " "}}' "$(dc ps -q derper)")"
evidence "roles" "$(api GET /admin/roles | tmpl '{{range .roles}}{{.name}} -> {{json .relays}}
{{end}}')"
evidence "PUT /admin/users/<carol>/roles {\"roles\":[\"standard\"]}" "$(api PUT "/admin/users/$CAROL/roles" '{"roles":["standard"]}')"
MARK_F=$(now)
m "$MC" tailscale debug break-derp-conns >/dev/null
wait_until 30 audit_newest_is "$KEY_C" "$MARK_F" false "policy denied" || true
sleep 3
rej=$(derper_rejected_since "$MARK_F" "$KEY_C" | tail -1 || true)
row=$(AUDIT_LIMIT=1 audit "$KEY_C" "$MARK_F")
conn=$(derp_connected_since "$MC" "$MARK_F" || true)
evidence "derper log" "$rej"
evidence "verify audit, newest row for $MC (user carol, roles [standard])" "$row"
evidence "$MC journal: 'derp-$REGION connected' since the reconnect" "$conn"
if [ -n "$rej" ] && grep -q 'allowed=false reason="policy denied"' <<<"$row" && [ -z "$conn" ]; then f1=1; else f1=0; fi

MARK_F2=$(now)
evidence "PUT /admin/users/<carol>/roles {\"roles\":[\"standard\",\"$ROLE\"]}" "$(api PUT "/admin/users/$CAROL/roles" "{\"roles\":[\"standard\",\"$ROLE\"]}")"
wait_until 60 derp_connected_since "$MC" "$MARK_F2" || true
wait_until 30 audit_newest_is "$KEY_C" "$MARK_F2" true || true
conn=$(derp_connected_since "$MC" "$MARK_F2" | tail -1 || true)
reg=$(derper_registered_since "$MARK_F2" "$KEY_C" | tail -1 || true)
row=$(AUDIT_LIMIT=1 audit "$KEY_C" "$MARK_F2")
p=$(ts_ping "$MA" "$TSIP_C" || true)
evidence "$MC journal" "$conn"
evidence "derper log ($(shortkey "$KEY_C") = $MC)" "$reg"
evidence "verify audit, newest row for $MC" "$row"
evidence "$MA: tailscale ping $TSIP_C" "$p"
if [ "$f1" = 1 ] && [ -n "$conn" ] && [ -n "$reg" ] && grep -q 'allowed=true' <<<"$row" && relayed_ok "$p"; then
  result F PASS "'standard' alone is 'policy denied' on relay $RELAY; binding $ROLE admits"
else
  result F FAIL "per-relay policy not shown (deny-part=$f1)"
fi

# ---------------------------------------------- G: verifier down -----------

section "G: verifier down, fail-open off"
dc stop verifier 2>&1 | sed 's/^/   /'
MARK_G=$(now)
m "$MC" tailscale debug break-derp-conns >/dev/null
wait_until 30 derper_rejected_since "$MARK_G" "$KEY_C" || true
sleep 12
rej=$(derper_rejected_since "$MARK_G" "$KEY_C" | tail -1 || true)
conn=$(derp_connected_since "$MC" "$MARK_G" || true)
hc=$(health "$MC")
p=$(ts_ping "$MA" "$TSIP_C" || true)
evidence "derper log" "$rej"
evidence "$MC journal: 'derp-$REGION connected' while the verifier is down" "$conn"
evidence "$MC tailscale status --json .Health" "$hc"
evidence "$MA: tailscale ping $TSIP_C" "$p"
if [ -n "$rej" ] && [ -z "$conn" ] && ! grep -q "pong from" <<<"$p"; then g1=1; else g1=0; fi

dc start verifier 2>&1 | sed 's/^/   /'
wait_until 60 sh -c "docker inspect -f '{{.State.Health.Status}}' \$(docker compose -p $PROJECT -f '$COMPOSE_FILE' ps -q verifier) | grep -qx healthy" || true
MARK_G2=$(now)
wait_until 60 derp_connected_since "$MC" "$MARK_G2" || true
wait_until 30 audit_newest_is "$KEY_C" "$MARK_G2" true || true
conn=$(derp_connected_since "$MC" "$MARK_G2" | tail -1 || true)
row=$(AUDIT_LIMIT=1 audit "$KEY_C" "$MARK_G2")
p=$(ts_ping "$MA" "$TSIP_C" || true)
evidence "$MC journal after the verifier is back" "$conn"
evidence "verify audit, newest row for $MC" "$row"
evidence "$MA: tailscale ping $TSIP_C" "$p"
if [ "$g1" = 1 ] && [ -n "$conn" ] && grep -q 'allowed=true' <<<"$row" && relayed_ok "$p"; then
  result G PASS "verifier down: derper refused $MC; verifier back: admitted"
else
  result G FAIL "verifier-down behaviour not shown (down-part=$g1)"
fi
