#!/usr/bin/env bash
# Tear down the e2e rig.
#
#   e2e/down.sh             remove the compose project (containers, networks,
#                           volumes), clean and stop the derp-e2e-* machines
#   e2e/down.sh --machines  additionally DELETE the machines derp-e2e-a,
#                           derp-e2e-b and derp-e2e-c (matched by exact name)
set -euo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
DELETE=0
for arg in "$@"; do
  case $arg in
    --machines) DELETE=1 ;;
    -h|--help) sed -n '2,8p' "$0"; exit 0 ;;
    *) echo "unknown argument: $arg" >&2; exit 2 ;;
  esac
done

"$HERE/run.sh" --down

if [ "$DELETE" = 1 ] && command -v orb >/dev/null 2>&1; then
  for n in derp-e2e-a derp-e2e-b derp-e2e-c; do
    if orb list -q 2>/dev/null | grep -qx "$n"; then
      echo "deleting machine $n"
      orb delete -f "$n"
    fi
  done
fi
