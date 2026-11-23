# End-to-end test with real Tailscale clients

This rig proves, with real `tailscaled` clients, that a Tailscale `derper`
admits or refuses clients **because of** derp-admit (the verifier). It uses
[Headscale](https://github.com/juanfont/headscale) as the control server, so
no real tailnet, account or public relay is involved.

## Layout

| Part | Where | What |
| --- | --- | --- |
| `postgres` | compose, network `backend` (internal) | verifier database |
| `verifier` | compose, `backend` | built from this tree (`builder/derp_admit/Dockerfile`) |
| `derper` | compose, `backend` + `edge` | tailscale v1.84.3 (`builder/derp_admit/derper.Dockerfile`), `--verify-client-url=http://verifier:8080/verify/e2e --verify-client-url-fail-open=false` |
| `headscale` | compose, `edge` | control server, DERP map = only our derper |
| `tools` | compose, `backend` | `e2etool` (Go, stdlib only): throwaway CA, admin API calls, JSON templating |
| `derp-e2e-a`, `-b`, `-c` | OrbStack Linux machines (Ubuntu 24.04 LTS, arm64) | real `tailscaled` 1.104.7 with kernel TUN, from pkgs.tailscale.com |

Compose project `derp-admit-e2e`; no `container_name`, no fixed subnets. Everything generated at run time (CA, derper key, Headscale
and PostgreSQL state) lives in named volumes; every secret is a throwaway
value in `docker-compose.yml`.

Pinned versions:

- Headscale `0.29.7` (`ghcr.io/juanfont/headscale:0.29.7`, the GitHub
  Container Registry copy of `docker.io/headscale/headscale:0.29.7`).
  Its release notes state "Minimum supported Tailscale client version:
  v1.80.0" and recommend Tailscale v1.104.4 or newer; its `go.mod` uses
  `tailscale.com v1.104.4`.
- Tailscale client `1.104.7` (apt package from `pkgs.tailscale.com/stable`).
- derper from `tailscale.com v1.84.3` (the version in this repo's `go.mod`).
- PostgreSQL `postgres:16-alpine`.

### TLS and the DERP map

The DERP map (`headscale/derp.yaml`) has one region (900, `e2e-derp`) with
one node: `HostName: derp.e2e.test`, `DERPPort: 39443`, `STUNPort: 39478`, `IPv6: none`,
no `CertName`, no `InsecureForTests`. Headscale is configured with
`derp.server.enabled: false` and `derp.urls: []`, so clients get no public
Tailscale region and no embedded Headscale DERP.

`derp.e2e.test` is the same in four places: the DERP map, the certificate SAN
(made by `e2etool pki` in the `tools` container, signed by a CA created at
run time; the CA private key is never written), `derper --hostname`
(`--certmode=manual --certdir=/pki`, which loads `/pki/derp.e2e.test.crt`
and checks the hostname against it), and the `/etc/hosts` entry `run.sh`
writes inside each machine (see below).
The CA goes into each machine's system trust store
(`/usr/local/share/ca-certificates`, `update-ca-certificates`), which is what
the client's `tlsdial` verifies against.

### How the machines reach the services

Measured on OrbStack 2.2.5: a machine cannot reach a container's IP address
(timeouts on ICMP and TCP) and cannot resolve `*.orb.local` container names,
and `docker.orb.internal` did not reach a port published on `127.0.0.1`. What
works is a port published on the Docker host's loopback (`127.0.0.1:PORT`),
reached from the machine through `host.orb.internal`, which the OrbStack docs
describe as the way machines reach servers on the Mac
(<https://docs.orbstack.dev/machines/network>). So:

- headscale publishes `127.0.0.1:39080` (tcp), derper `127.0.0.1:39443` (tcp,
  DERP over TLS) and `127.0.0.1:39478` (udp, STUN). Each listens on the same
  port number inside its container, so one number is used everywhere. Loopback
  binding keeps them off the LAN.
- In each machine `run.sh` resolves `host.orb.internal` (IPv4) and writes
  `derp.e2e.test` and `headscale.e2e.test` with that address into `/etc/hosts`.
- derper therefore sees every client with the same source address (the
  OrbStack port forwarder); clients are told apart by node key.
- Isolated machines (`--isolated`) cannot reach the macOS host (OrbStack docs, <https://docs.orbstack.dev/machines/isolated>; an isolated machine here also timed out on container IPs), so the
  machines are regular (non-isolated) machines. Every command runs as
  `orb run -m <machine> -u root -w / ...` and writes only to `/etc`, `/var`,
  `/usr/local` and `/run` inside the machine, never to the macOS mount.

### Machines

`run.sh` creates a missing machine with `orb create ubuntu:noble derp-e2e-X`
and installs the pinned `tailscale` package (plus curl, jq, nftables, ping)
from pkgs.tailscale.com and the Ubuntu archive. It runs every command in a
machine as `orb run -m derp-e2e-X -u root -w / bash -c '<script>' e2e <args>`,
passing data (the CA) on stdin. A machine that already exists is reused: each
run wipes `/var/lib/tailscale` (so every run gets new node keys), rewrites the
two `/etc/hosts` entries, replaces the CA and the firewall table, and restarts
`tailscaled`. Teardown undoes those changes and stops the machines.

Each machine gets an nftables table `inet derp_e2e` that drops all traffic,
IPv4 and IPv6, to and from the other two machines' addresses. The only path
between clients is therefore through derper (precondition P2 checks it with
plain `ping`). STUN (udp/39478) to our derper is allowed on purpose: it is the
only STUN server in the DERP map and lets each client choose region 900 as its
home; no public STUN or DERP server is used.

## Running

```bash
e2e/run.sh            # build if needed, start, provision, assert, tear down
e2e/run.sh --keep     # leave the stack and the machines running afterwards
e2e/run.sh --build    # rebuild the local images
e2e/down.sh           # remove the compose project, clean and stop the machines
e2e/down.sh --machines  # also delete derp-e2e-a, -b, -c
```

Requirements: Docker with Compose v2, OrbStack (`orb`), bash (3.2 is enough),
coreutils and awk. Without `--prebuilt`, the host needs Docker Hub and the
Go module proxy for the builds, and new machines need the OrbStack image CDN,
the Ubuntu archive and pkgs.tailscale.com.

If the Docker host cannot reach Docker Hub but can reach a mirror, point the
Go base images used by the Dockerfiles at a mirror of the official image, for
example `E2E_GOLANG_IMAGE=public.ecr.aws/docker/library/golang:1.24.0` and
`E2E_GOLANG_DERPER_IMAGE=public.ecr.aws/docker/library/golang:1.24` (they are
substituted through BuildKit named contexts; the Dockerfiles are unchanged).
`E2E_POSTGRES_IMAGE` and `E2E_HEADSCALE_IMAGE` override the other images.

### Test host with a slow or filtered network

Prepare images and machines on another arm64 Mac with OrbStack and ship them:

```bash
# images: build and pull here, stream them over ssh (no files on either side)
docker compose -p derp-admit-e2e -f e2e/docker-compose.yml build
docker pull ghcr.io/juanfont/headscale:0.29.7   # and postgres:16-alpine if missing there
docker save derp-admit-e2e-verifier:local derp-admit-e2e-derper:v1.84.3 \
  derp-admit-e2e-tools:local ghcr.io/juanfont/headscale:0.29.7 \
  | ssh TEST_HOST docker load

# machine template: create, provision (same script run.sh uses), scrub, export
orb create ubuntu:noble derp-e2e-template
# run the PROVISION_SCRIPT from run.sh in it, then:
orb run -m derp-e2e-template -u root -w / sh -c \
  'systemctl stop tailscaled; rm -rf /var/lib/tailscale; : > /etc/machine-id; apt-get clean'
orb stop derp-e2e-template
orb export derp-e2e-template /path/to/scratch/derp-e2e-template.tar.zst
# on the test host (orb import needs a file path; stdin does not work):
#   copy it to e2e/.cache/ (ignored by git), then
#   orb import -n derp-e2e-a e2e/.cache/derp-e2e-template.tar.zst
#   orb clone derp-e2e-a derp-e2e-b; orb clone derp-e2e-a derp-e2e-c
#   rm e2e/.cache/derp-e2e-template.tar.zst
orb delete -f derp-e2e-template
```

The template has no openssh-server (no host keys to share) and an empty
`/etc/machine-id`, which systemd regenerates on first boot, so each clone gets
its own machine id; `tailscaled` state is wiped at every run, so node keys
differ too. Then run `e2e/run.sh --prebuilt` (or `E2E_PREBUILT=1 e2e/run.sh`):
it never builds or pulls (`docker compose up --no-build --pull never`) and
reuses the existing machines; the provisioning step sees the pinned
`tailscale` version already installed and downloads nothing.

Every assertion prints `PASS`/`FAIL`/`SKIP` with its evidence; the script
exits non-zero on any failure.

## What each assertion proves

Evidence is always taken from after a timestamp read just before the action,
so a row or log line from an earlier step cannot satisfy a later one.

- **P1** a machine reaches `https://derp.e2e.test:39443/derp/probe` with
  certificate verification against the system store (`ssl_verify_result=0`).
- **P2** no direct IP path between any two machines (IPv4 and IPv6).
- **A** `a` (registered, user with access) holds a DERP connection:
  tailscaled logs `magicsock: derp-900 connected` (logged only after derper
  sends ServerInfo, i.e. after admission), `tailscale status` shows home relay
  `e2e-derp`, derper logs `register single client` for a's short key
  (`DERP_DEBUG_LOGS=true`), and the newest verify audit row is `allowed=true`
  on relay `e2e`.
- **B** `a` and `c` exchange traffic (`tailscale ping` and ICMP over
  `tailscale0`) only via `DERP(e2e-derp)`; the peer has no direct `CurAddr`.
- **C** unregistered `b` is refused: derper logs
  `client nodekey:... rejected: admission controller: ... not allowed`, the
  audit row says `not registered`, b's tailscaled never logs `connected` and
  reports the "Relay server unavailable" health warning, and `a` cannot ping it.
- **D** after `POST /register` for b's node key, b's own retry is admitted
  (same three kinds of evidence) and `a` pings `b` via DERP.
- **E** derper calls the verifier only when a client connects (see below).
  After revoking `a`, its open connection keeps working (`a` still pings `c`
  via DERP, no new audit row for a). After `tailscale debug break-derp-conns`
  the reconnect is refused with reason `revoked`.
- **F** derper is pointed at relay `e2e` for the whole run (relay `e2e` and
  role `e2e-access` are created, and alice and carol bound to it, before any
  client starts). Carol's roles are then set to `["standard"]` (granted on
  `default` only): after `break-derp-conns`, `c` is refused with
  `policy denied`; after binding carol to `e2e-access` again, `c`'s own retry
  is admitted.
- **G** with the verifier stopped, a reconnecting client is refused by derper
  (fail-open off; derper logs the failed `POST` to the verifier); once the
  verifier is back, the client gets in again.

### When derper calls the verifier

In tailscale v1.84.3, `derp/derp_server.go` calls `verifyClient` from
`(*Server).accept` (line 925), once per new connection, after reading the
client key and before `registerClient`; there is no periodic re-check. The
only other caller (line 2281) is the `--verify-clients` health check for the
local-tailscaled mode. So revoking a device, disabling a user, or removing a
grant affects only **new** connections: a client that is already connected
keeps relaying until it reconnects (network change, derper restart, client
restart).

## What this does not prove

- Behaviour with several derper instances, DERP meshing, or a derper behind a
  load balancer.
- Anything about direct (non-relayed) WireGuard paths: admission control only
  gates the relay; two clients that can reach each other directly do not need
  derper at all.
- Rate limiting, the verify cache (`VERIFY_CACHE_TTL` is `0s` here),
  multi-instance policy sync, or upgrade behaviour.
- Other Tailscale client versions or operating systems.
- That the verifier is safe to expose: in this rig only derper and the tools
  container can reach it.
- The built-in relay `default` with a real client: derper uses `/verify/e2e`
  throughout (plain `/verify` is covered by the unit tests only).
