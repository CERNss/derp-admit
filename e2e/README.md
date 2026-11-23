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
| `derp-e2e-a`, `-b`, `-c` | OrbStack Linux machines (Ubuntu 24.04, `--isolated`) | real `tailscaled` with kernel TUN, from pkgs.tailscale.com |

Compose project `derp-admit-e2e`; no published host ports, no `container_name`,
no fixed subnets. Everything generated at run time (CA, derper key, Headscale
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
one node: `HostName: derp.e2e.test`, `DERPPort: 8443`, `STUNPort: 3478`,
no `CertName`, no `InsecureForTests`. Headscale is configured with
`derp.server.enabled: false` and `derp.urls: []`, so clients get no public
Tailscale region and no embedded Headscale DERP.

`derp.e2e.test` is the same in four places: the DERP map, the certificate SAN
(made by `e2etool pki` in the `tools` container, signed by a CA created at
run time; the CA private key is never written), `derper --hostname`
(`--certmode=manual --certdir=/pki`, which loads `/pki/derp.e2e.test.crt`
and checks the hostname against it), and the `/etc/hosts` entry `run.sh`
writes inside each machine (pointing at derper's container IP on `edge`).
The CA goes into each machine's system trust store
(`/usr/local/share/ca-certificates`, `update-ca-certificates`), which is what
the client's `tlsdial` verifies against.

### Machines

`run.sh` creates a missing machine with
`orb create --isolated ubuntu:noble derp-e2e-X` (isolated: no macOS file
sharing inside the machine) and runs every command in it as
`orb run -m derp-e2e-X -u root -w / bash -c '<script>' e2e <args>`, passing
data (the CA) on stdin, so nothing is ever written to a macOS path. An
existing machine is reused: each run wipes `/var/lib/tailscale`, rewrites the
two `/etc/hosts` entries, replaces the CA and the firewall table.

Each machine gets an nftables table `inet derp_e2e` that drops all traffic,
IPv4 and IPv6, to and from the other two machines' addresses. The only path
between clients is therefore through derper (precondition P2 checks it with
plain `ping`). STUN (udp/3478) to our derper is allowed on purpose: it is the
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

Requirements: Docker with Compose v2, OrbStack (`orb`), bash, coreutils and
awk. The machines need internet access the first time (Ubuntu and Tailscale
package repositories).

If the Docker host cannot reach Docker Hub, point the Go base image used by
the Dockerfiles at a mirror of the official image, for example
`E2E_GOLANG_IMAGE=public.ecr.aws/docker/library/golang:1.24.0` and
`E2E_GOLANG_DERPER_IMAGE=public.ecr.aws/docker/library/golang:1.24` (they are
substituted through BuildKit named contexts; the Dockerfiles are unchanged).
`E2E_POSTGRES_IMAGE` and `E2E_HEADSCALE_IMAGE` override the other images.

Every assertion prints `PASS`/`FAIL`/`SKIP` with its evidence; the script
exits non-zero on any failure.

## What each assertion proves

Evidence is always taken from after a timestamp read just before the action,
so a row or log line from an earlier step cannot satisfy a later one.

- **P1** a machine reaches `https://derp.e2e.test:8443/derp/probe` with
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
- **F** derper is pointed at relay `e2e`. With only role `standard` (granted
  on `default`), carol's device `c` is refused with `policy denied` on its next
  connect; after binding carol to `e2e-access` (granted on `e2e`) it is
  admitted.
- **G** with the verifier stopped, a reconnecting client is refused by derper
  (fail-open off); once the verifier is back, the client gets in again.

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
