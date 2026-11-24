# Onboarding: from zero to a device relaying through your DERP

This guide brings up the production stack in `deploy/`, creates the first
admin key, user and enroll token, enrolls a device with `scripts/enroll.sh`,
and tells your Tailscale control server to use the new relay. The admin API
itself is described in [`README.md`](../README.md); this guide does not repeat
it.

Every command below is run from the root of this repository unless it says
otherwise.

## 1. What you need

- A Linux host with Docker Engine and Docker Compose v2 (`docker compose version`).
- A DNS name for the relay, for example `derp.example.com`, with an `A` (and
  optionally `AAAA`) record pointing at the host.
- Inbound, from the internet:
  - `443/tcp`: DERP over TLS (clients connect here).
  - `80/tcp`: needed by Let's Encrypt (`letsencrypt` cert mode, the default)
    for its HTTP challenge; derper also redirects to HTTPS and answers
    `/generate_204` there.
  - `3478/udp`: STUN, which clients use to find their public address and to
    measure latency to the relay.
- `openssl` (to generate secrets), `curl` and `jq` on the host.

The verifier itself is never exposed: the stack publishes it on `127.0.0.1`
only.

## 2. Bring up the production stack

### Configure

```bash
cp deploy/.env.example deploy/.env
chmod 600 deploy/.env
openssl rand -hex 32   # run three times: POSTGRES_PASSWORD, TOKEN_PEPPER, ADMIN_API_KEY
```

Edit `deploy/.env` (it is ignored by git):

- Fill in the three secrets, which are empty in the example (compose refuses
  to start until they are set): put the generated values in
  `POSTGRES_PASSWORD`, `TOKEN_PEPPER` and `ADMIN_API_KEY`. Use hex:
  `DATABASE_URL` is assembled from the password as a plain string, so
  characters such as `@`, `/` or `:` would break it.
- Set `DERP_HOSTNAME` to the relay's DNS name.
- Choose the certificate mode:
  - `DERP_CERTMODE=letsencrypt` (default): derper obtains and renews a
    certificate itself. `DERP_HOSTNAME` must resolve to this host and ports
    443 and 80 must be reachable from the internet. Certificates are cached in
    the `derper-data` volume.
  - `DERP_CERTMODE=manual`: you provide the certificate. Put two files in a
    host directory and set `DERP_MANUAL_CERT_DIR` to its **absolute** path:
    `<DERP_HOSTNAME>.crt` (certificate with its chain) and
    `<DERP_HOSTNAME>.key` (private key). derper strips every character
    other than letters, digits, `-` and `.` from the host name to build the
    file names (`cmd/derper/cert.go`), checks that the certificate is valid for
    `DERP_HOSTNAME`, and only answers TLS connections whose SNI is exactly
    `DERP_HOSTNAME`. The files must be readable by the container user
    (`uid=100(derper) gid=101(derper)` in the image built from
    `builder/derp_admit/derper.Dockerfile`; mode `0644` on the files works).
    The directory is mounted read-only. derper reads the files only at start,
    so restart it after you renew them (`docker compose ... restart derper`).
    If derper exits with `x509: invalid ECDSA parameters`, the key file is in a
    form Go cannot read (seen with an EC key made by macOS's LibreSSL
    `openssl`); convert it or use an RSA key.
- If you plan to use a named relay instead of the built-in `default`, set
  `DERP_RELAY` now and create that relay in step 3 before any client connects.

Everything else has a working default; `deploy/.env.example` explains each
variable. The stack uses two networks: `front` (derper and the verifier, with
a fixed subnet and derper at a fixed address) and `backend` (the verifier and
PostgreSQL only, `internal: true`, subnet chosen by Docker). If
`10.203.117.0/24` is already used on your host, change `DERP_ADMIT_SUBNET`,
`DERP_ADMIT_GATEWAY` and `DERPER_IPV4` together.

### Build or pull, then start

There is no published derper image, so derper is always built (from
`builder/derp_admit/derper.Dockerfile`, Tailscale v1.84.3). The verifier image
can be built from this checkout or pulled from `VERIFIER_IMAGE` if it has
been published there.

```bash
dc() { docker compose -f deploy/docker-compose.yml --env-file deploy/.env "$@"; }
dc build                 # builds the verifier and derper images
# or, if VERIFIER_IMAGE is published: dc pull verifier && dc build derper
dc up -d --wait
dc ps                    # all three services "healthy"
```

If a required variable is missing, compose stops before starting anything,
for example:

```text
error while interpolating services.verifier.environment.TOKEN_PEPPER: required variable TOKEN_PEPPER is missing a value: set TOKEN_PEPPER (openssl rand -hex 32) in the env file
```

### Check health

```bash
curl -s http://127.0.0.1:8080/healthz      # {"ok":true}
curl -s http://127.0.0.1:8080/readyz       # {"ok":true}
dc logs derper | grep 'serving on'          # derper: serving on :443 with TLS
curl -s -o /dev/null -w '%{http_code}\n' https://derp.example.com/derp/probe   # 200
```

(`8080` is `VERIFIER_HOST_PORT`.) In `manual` mode with a certificate that
your machine does not trust, add `--cacert <file>`; use the real host name
(or `--resolve derp.example.com:443:127.0.0.1` on the host itself), because
derper refuses a TLS connection whose SNI is not `DERP_HOSTNAME`.

The derper health check only shows that derper is serving on port 80; it does
not check TLS.

### Reaching the admin API

The verifier is published on `127.0.0.1:${VERIFIER_HOST_PORT}` of the host
and nowhere else. Run admin commands on the host, or from your workstation
through an SSH tunnel to the host, for example
`ssh -L 8080:127.0.0.1:8080 <host>`, then use `http://127.0.0.1:8080`
locally. The full route reference is in [`README.md`](../README.md#admin-api).

## 3. First admin steps

These are the commands used against a live stack built from `deploy/`. Each
request needs `Authorization: Bearer <key>`. Note that a key passed with `-H`
is visible in the process list to other users of the host while `curl` runs.

```bash
BASE=http://127.0.0.1:8080
BOOTSTRAP_KEY=$(grep '^ADMIN_API_KEY=' deploy/.env | cut -d= -f2-)
```

### Create a named admin key and stop using bootstrap

`ADMIN_API_KEY` becomes an admin key named `bootstrap`. Create a named key,
store it somewhere safe (it is shown only once), then revoke `bootstrap`:

```bash
ADMIN_KEY=$(curl -sS -X POST "$BASE/admin/keys" \
  -H "Authorization: Bearer $BOOTSTRAP_KEY" \
  -H 'content-type: application/json' \
  -d '{"name":"ops-admin","tier":"admin"}' | jq -r .key)
# Response: {"ok":true,"key":"dak_...","meta":{"id":"...","name":"ops-admin","tier":"admin",...}}

BOOT_ID=$(curl -sS "$BASE/admin/keys" -H "Authorization: Bearer $ADMIN_KEY" |
  jq -r '.keys[] | select(.name=="bootstrap") | .id')

curl -sS -X POST "$BASE/admin/keys/$BOOT_ID/revoke" -H "Authorization: Bearer $ADMIN_KEY"
# {"ok":true}

curl -sS -o /dev/null -w '%{http_code}\n' "$BASE/admin/users" -H "Authorization: Bearer $BOOTSTRAP_KEY"
# 401
```

Keep `ADMIN_API_KEY` set and secret: it keeps `/admin` mounted, and it becomes
an admin key again if the verifier restarts at a time when no other admin key
is active (see README, "Bootstrap key, reserved names, and lockout guard").

Give other people and scripts their own keys with the lowest tier they need
(`viewer`, `operator` or `admin`), optionally with `"expiresAt":"2027-01-01T00:00:00Z"`.

### Optional: a named relay and a role granted on it

The built-in relay `default` and role `standard` (granted on `default`) are
enough for one relay. To use your own relay name (and `DERP_RELAY` in
`deploy/.env`):

```bash
curl -sS -X POST "$BASE/admin/relays" \
  -H "Authorization: Bearer $ADMIN_KEY" \
  -H 'content-type: application/json' \
  -d '{"name":"edge-1","description":"first relay"}'
# {"ok":true,"relay":{"name":"edge-1","description":"first relay",...}}

curl -sS -X POST "$BASE/admin/roles" \
  -H "Authorization: Bearer $ADMIN_KEY" \
  -H 'content-type: application/json' \
  -d '{"name":"edge-users","description":"may use edge-1","relays":["edge-1"]}'
# {"ok":true,"role":{"name":"edge-users","relays":["edge-1"],...}}
```

If you changed `DERP_RELAY` after the first start, recreate derper so it uses
the new verify URL: `dc up -d derper`.

### Create a user

```bash
USER_ID=$(curl -sS -X POST "$BASE/admin/users" \
  -H "Authorization: Bearer $ADMIN_KEY" \
  -H 'content-type: application/json' \
  -d '{"username":"alice","email":"alice@example.com"}' |
  jq -r .user.id)
# Response: {"ok":true,"user":{"id":"...","username":"alice","roles":["standard"],...}}
```

Without `roles` the user gets `["standard"]`; with `"roles":[]` the user gets
none and every device of theirs is denied. If you created the `edge-users`
role above, bind it too (only existing roles can be bound):

```bash
curl -sS -X PUT "$BASE/admin/users/$USER_ID/roles" \
  -H "Authorization: Bearer $ADMIN_KEY" \
  -H 'content-type: application/json' \
  -d '{"roles":["standard","edge-users"]}'
# {"ok":true,"roles":["edge-users","standard"],"userId":"..."}
```

(You can also pass `"roles":["standard","edge-users"]` when creating the user.)

### Mint an enroll token

```bash
curl -sS -X POST "$BASE/admin/tokens" \
  -H "Authorization: Bearer $ADMIN_KEY" \
  -H 'content-type: application/json' \
  -d "{\"userId\":\"$USER_ID\",\"maxDevices\":3,\"note\":\"alice devices\",\"expiresAt\":\"2030-01-01T00:00:00Z\"}" |
  jq -r .token
# Response: {"ok":true,"token":"...","meta":{"id":"...","maxDevices":3,"expiresAt":"...",...}}
```

The plaintext token is shown once. `maxDevices` caps the user's active
devices (default `1`, `0` = no limit); `expiresAt` is optional. Hand the token
to the user over a private channel.

## 4. Enroll a device

`scripts/enroll.sh` sends the device's node key and the enroll token to
`POST /register`. It needs `curl`, and `jq` or `python3`; it runs with the
bash 3.2 that ships with macOS and on Linux. The token is read from the
environment variable `ENROLL_TOKEN` or, if that is unset, from standard input
(with a hidden prompt on a terminal). It is never accepted as an argument and
never placed on a command line. The script removes `ENROLL_TOKEN` from its
environment and reads standard input before it starts any other program, so
no program it runs sees the token in its environment or arguments, and
`tailscale` cannot read it from standard input; only `jq`/`python3` (which
build the JSON) and `curl` receive it, through a pipe. Prefer standard input on a shared machine anyway: the
environment the script was started with is readable by the same user and by
root while it runs.

### On the device itself

The device must be logged in to your control server (`tailscale up`) so that
it has a node key. The script reads it from `tailscale status --json`
(`Self.PublicKey`), using `tailscale` on `PATH`, `TAILSCALE_BIN`, or on macOS
`/Applications/Tailscale.app/Contents/MacOS/Tailscale`. The label defaults to
the host name.

```bash
scripts/enroll.sh --url https://verifier.example.com
# Enroll token: (typed, not echoed)
# Node key of this device: nodekey:...
# Enrolled nodekey:... (label "laptop") with https://verifier.example.com.
```

### For another device (operator)

Ask the user for their node key (`tailscale status --json | jq -r .Self.PublicKey`
on their device) and pass it with `--node-key`. `--label` is required in this
mode (`--label ''` sends none).

```bash
read -rs ENROLL_TOKEN && export ENROLL_TOKEN     # paste the token, then Enter
scripts/enroll.sh --url http://127.0.0.1:8080 \
  --node-key nodekey:<64 hex digits> --label 'alice phone'
unset ENROLL_TOKEN
```

### Reaching /register

Enrollment needs the verifier's `/register` to be reachable from wherever the
script runs, and the production compose publishes the verifier on the host's
loopback only. Two ways to handle it:

1. **The operator runs the script on the host** with `--node-key` and
   `--url http://127.0.0.1:8080`, as above. Nothing else is exposed.
2. **A TLS reverse proxy in front of the verifier that forwards only
   `/register`** (exact path, `POST`), so users can enroll from their own
   devices with `--url https://verifier.example.com`. Never forward `/verify`,
   `/admin` or `/metrics`. Use `--cacert <file>` if the proxy's certificate is
   not in the system trust store. Note that the verifier trusts no forwarding
   headers (`X-Forwarded-For` and similar are ignored), so the per-IP register
   rate limit (`REGISTER_RATE_LIMIT_RPS`, `REGISTER_RATE_LIMIT_BURST`) sees the
   proxy's address and all users behind it share one bucket.

### What the script reports

| Exit | Meaning |
| --- | --- |
| `0` | Enrolled (also when this key is already enrolled for the same user; a non-empty label is updated) |
| `2` | Usage: no `--url`, no token, missing `--label` with `--node-key`, unknown argument |
| `3` | Local problem: no `jq`/`python3`, no `tailscale` CLI, device not logged in |
| `4` | The verifier could not be reached (connection, DNS, TLS or timeout; curl's error is shown) |
| `10` | `400`/`413`: malformed request or node key (malformed keys are caught before sending) |
| `11` | `401`: the token is not known to this verifier |
| `12` | `403`: token revoked or expired, user disabled or deleted, the token's device limit reached, or this node key was revoked by an admin |
| `13` | `409`: this node key is already enrolled for another user |
| `14` | `429`: rate limited; wait a few seconds |
| `15` | Any other status, for example `404` from a wrong `--url` or `500` |
| `16` | `200`, but the body is not the verifier's `{"ok":true}`: the URL does not look like a derp-admit verifier (for example a proxy's catch-all page) |

## 5. Tell the control server about your DERP

Clients only use a relay that is in the DERP map they receive from the control
server. `DERPPort` and `STUNPort` must be the host ports (`DERP_HTTPS_PORT`,
`DERP_STUN_PORT`; default `443` and `3478`), and `HostName` must be
`DERP_HOSTNAME`.

### a. Headscale

Point Headscale at a DERP map file, as the real-client test in `e2e/` does
(`e2e/headscale/config.yaml` and `e2e/headscale/derp.yaml`). This path was
tested end to end with real Tailscale clients (Headscale 0.29.7, Tailscale
client 1.104.7; see `e2e/README.md`).

In Headscale's `config.yaml`:

```yaml
derp:
  server:
    enabled: false          # no embedded DERP server
  urls: []                  # no Tailscale public DERP map
  paths:
    - /etc/headscale/derp.yaml
  auto_update_enabled: false
```

`/etc/headscale/derp.yaml` (Headscale decodes it into `tailcfg.DERPMap`; keys
are the lower-cased field names):

```yaml
regions:
  900:
    regionid: 900
    regioncode: my-derp
    regionname: My DERP relay
    nodes:
      - name: 900a
        regionid: 900
        hostname: derp.example.com
        derpport: 443
        stunport: 3478
```

With `urls: []` your relay is the only one clients get. Keep Tailscale's public
map in `urls` if you want it as a fallback; clients may then also use
Tailscale's relays, which do not ask your verifier.

### b. Tailscale's hosted control plane (not tested)

**This path has not been tested by this project.** Per Tailscale's
documentation (<https://tailscale.com/kb/1118/custom-derp-servers>), add a
`derpMap` section to the tailnet policy file. Region IDs `900` to `999` are
reserved for custom regions. The node fields below are the names of the
`tailcfg.DERPRegion` and `tailcfg.DERPNode` fields (`DERPPort` and `STUNPort`
can be left out when they are `443` and `3478`):

```json
"derpMap": {
  "OmitDefaultRegions": true,
  "Regions": {
    "900": {
      "RegionID": 900,
      "RegionCode": "my-derp",
      "RegionName": "My DERP relay",
      "Nodes": [
        {
          "Name": "900a",
          "RegionID": 900,
          "HostName": "derp.example.com",
          "DERPPort": 443,
          "STUNPort": 3478
        }
      ]
    }
  }
}
```

`OmitDefaultRegions: true` removes Tailscale's own DERP regions from the map,
so relayed traffic can only go through your relays. Without it, clients keep
Tailscale's regions too and may pick one of them as home, in which case your
verifier is never asked about that client.

## 6. Check it works

On a client (after it has been enrolled):

```bash
tailscale netcheck
# Your region should be listed under the DERP latencies; it is the "Nearest DERP"
# when it is the only region or the closest one.
tailscale status --json | jq -r .Self.Relay     # home relay: my-derp
tailscale ping --until-direct=false <peer tailscale IP>
# pong from peer (100.x.y.z) via DERP(my-derp) in 23ms
```

`via DERP(<region code>)` shows that the traffic went through the relay. Two
devices that can reach each other directly (`via <ip>:<port>`) do not need the
relay at all; admission control only gates the relay.

On the host, the verify audit shows each decision:

```bash
curl -sS "$BASE/admin/audit/verify?limit=5" -H "Authorization: Bearer $ADMIN_KEY" |
  jq -c '.entries[] | {ts, relay, allowed, reason, nodeKey}'
# {"ts":"...","relay":"default","allowed":true,"reason":"","nodeKey":"nodekey:..."}
```

### What a denied device looks like

- derper log (`dc logs derper`):

  ```text
  derp: 203.0.113.7:51234: client nodekey:... rejected: admission controller: nodekey:.../203.0.113.7 not allowed
  ```

- verify audit: `"allowed":false` with one of these reasons (README,
  "Verify flow"): `not registered` (node key not enrolled), `revoked`
  (device revoked), `user disabled`, `policy denied` (no role of the owner is
  granted on this relay), `unknown relay` (`DERP_RELAY` names a relay that was
  not created), `invalid request`, `internal error` (database or policy sync
  problem). `rate limited` is not audited.
- On the client: no `magicsock: derp-<region id> connected` line in the
  `tailscaled` log, and `tailscale status` shows a health warning that it
  could not connect to the relay; peers cannot be reached through it.

With `DERP_DEBUG_LOGS=true`, derper also logs `register single client` for
every admitted connection.

## 7. Things that will surprise you

- **A decision is taken only when a client connects to derper.** Revoking a
  device, disabling a user, removing a role or grant, or deleting a relay
  stops new connections at once, but a client that is already connected keeps
  relaying until its connection to the relay is re-established (client
  restart, network change, relay restart). See the README section "When a
  change takes effect on a connected client"; the real-client test in `e2e/`
  (assertion E) shows exactly this. To cut existing connections now, restart
  derper: `dc restart derper`.
- **A device's node key can change, and the new key must be enrolled
  again.** In the Tailscale client source (tailscale v1.84.3; other client
  versions may differ), a new node key is generated when the client logs in
  with no stored key, when its old key has expired, and on an interactive
  login such as `tailscale up --force-reauth` (`control/controlclient/direct.go`,
  `doLogin`). `tailscale logout` deletes the login profile that holds the key
  (`ipn/ipnlocal/local.go`, `Logout`), so the next login gets a new key; so
  does a fresh install or wiped client state. The
  old key's device row stays; delete it with `DELETE /admin/devices/:id` if
  you no longer want it, and count it against `maxDevices` until you do.
- **derper fails closed when the verifier is down.** The stack sets
  `--verify-client-url-fail-open=false`, so while the verifier is stopped or
  unreachable every new connection is refused (derper logs `rejected: Post
  "http://verifier:8080/verify/...": ...`). Connections that are already open
  keep working. Keep the verifier and PostgreSQL healthy; the verifier
  also denies everything with `internal error` while its policy sync is stale.
- **`/verify` must be restricted, to the derper address and not the
  subnet.** `/verify` needs no credentials: anyone who can call it can learn
  whether a node key is enrolled, fill the verify audit, and use up the single
  global verify rate limit, which with fail-open off makes derper refuse
  everyone. The compose file sets `VERIFY_ALLOWED_CIDRS` to derper's fixed
  address (`DERPER_IPV4`, a `/32`), not to the whole `front` subnet, because
  requests that arrive through the loopback-published port appear to the
  verifier as coming from the `front` gateway (`DERP_ADMIT_GATEWAY`), which is
  inside the subnet; from the host, `/verify` answers `403`. So call `/verify`
  only from derper; to test it by hand, run the request inside the derper
  container:

  ```bash
  dc exec derper wget -qO- --header 'content-type: application/json' \
    --post-data '{"NodePublic":"nodekey:<64 hex digits>"}' http://verifier:8080/verify/default
  # {"Allow":true}  or  {"Allow":false,"DenyReason":"not registered"}
  ```

  `METRICS_ALLOWED_CIDRS` does the same for `GET /metrics` and defaults to
  `127.0.0.1/32` and the `front` gateway, so only processes on the host can
  scrape it (derper gets `403`); add your Prometheus address there.
- **Network separation depends on your Docker host.** derper is only on
  `front`, so the name `postgres` does not resolve inside it. Blocking routed
  traffic from `front` to the `internal` `backend` network is up to the
  Docker host's firewall rules. On one Docker Desktop-style test host
  (OrbStack, Docker Engine 29.8.2) such traffic was not blocked: derper could
  open a TCP connection to PostgreSQL's backend address. What protected the
  data there was that derper holds no database password and PostgreSQL
  requires one (`scram-sha-256`) for every non-local connection. Check your
  host: this must fail.

  ```bash
  PG_IP=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$(dc ps -q postgres)")
  dc exec derper nc -z -w 3 "$PG_IP" 5432 && echo "REACHABLE: not isolated" || echo "blocked"
  ```

  Also, on Docker Engine versions before 28, hosts on the same LAN can route
  directly to container addresses, so publishing on `127.0.0.1` only is not a
  complete barrier there; check this property for your Docker version.

## 8. Day two

### Rotating admin keys

Create the new key, switch your callers to it, then revoke the old one:

```bash
NEW_KEY=$(curl -sS -X POST "$BASE/admin/keys" -H "Authorization: Bearer $ADMIN_KEY" \
  -H 'content-type: application/json' -d '{"name":"ops-admin-2","tier":"admin"}' | jq -r .key)
OLD_ID=$(curl -sS "$BASE/admin/keys" -H "Authorization: Bearer $NEW_KEY" |
  jq -r '.keys[] | select(.name=="ops-admin") | .id')
curl -sS -X POST "$BASE/admin/keys/$OLD_ID/revoke" -H "Authorization: Bearer $NEW_KEY"
```

The last active `admin`-tier key cannot be revoked (`409`). To rotate
`ADMIN_API_KEY` itself, change it in `deploy/.env` and recreate the verifier
(`dc up -d verifier`); while `bootstrap` is revoked it stays a dormant
credential (README, "Bootstrap key, reserved names, and lockout guard").
Do not change `TOKEN_PEPPER`: every enroll token and named admin key would
stop working.

### Backing up PostgreSQL

```bash
dc exec -T postgres sh -c 'pg_dump -U "$POSTGRES_USER" -d "$POSTGRES_DB" --format=custom' \
  > "verifier-$(date +%Y%m%d).dump"
```

Restore into an empty database with `pg_restore`. Keep `deploy/.env` (above
all `TOKEN_PEPPER`) with the backup: the stored hashes are useless without it.
The derper private key and Let's Encrypt cache are in the `derper-data`
volume; losing them only means a new derper key and a new certificate.

### Upgrading the verifier

Read the release notes and the README section "Upgrading from the previous
version" first, and take a backup.

```bash
git pull                       # if you build from this checkout
dc build verifier              # or: dc pull verifier (published image)
dc up -d --wait verifier
dc logs --tail 50 verifier
curl -s http://127.0.0.1:8080/readyz
```

While the verifier restarts, derper refuses new connections (fail closed);
existing ones keep working. To upgrade derper, change `TAILSCALE_VERSION` in
`builder/derp_admit/derper.Dockerfile` (and the image tag in `DERPER_IMAGE`),
then `dc build derper && dc up -d derper`; restarting derper makes every
client reconnect, and each reconnect is checked by the verifier again.
