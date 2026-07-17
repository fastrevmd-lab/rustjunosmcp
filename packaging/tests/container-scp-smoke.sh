#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
APP_IMAGE="${JMCP_CONTAINER_IMAGE:-rust-junosmcp:container-smoke}"
FIXTURE_IMAGE="rust-junosmcp-scp-fixture:container-smoke"
SUFFIX="${GITHUB_RUN_ID:-$$}-${RANDOM}"
NETWORK="jmcp-scp-$SUFFIX"
FIXTURE_CONTAINER="jmcp-scp-fixture-$SUFFIX"
STATE_VOLUME="jmcp-scp-state-$SUFFIX"
KEY_VOLUME="jmcp-scp-keys-$SUFFIX"
WORK="$(mktemp -d)"

cleanup() {
    docker rm -f "$FIXTURE_CONTAINER" >/dev/null 2>&1 || true
    docker network rm "$NETWORK" >/dev/null 2>&1 || true
    docker volume rm "$STATE_VOLUME" "$KEY_VOLUME" >/dev/null 2>&1 || true
    rm -rf "$WORK"
}
trap cleanup EXIT

command -v docker >/dev/null 2>&1 || { echo "docker is required" >&2; exit 1; }
command -v ssh-keygen >/dev/null 2>&1 || { echo "ssh-keygen is required" >&2; exit 1; }

if [[ -z "${JMCP_CONTAINER_IMAGE:-}" ]]; then
    echo ">> Building rust-junosmcp runtime image"
    docker build --tag "$APP_IMAGE" "$ROOT"
else
    docker image inspect "$APP_IMAGE" >/dev/null
fi

image_config="$(docker image inspect --format '{{json .Config}}' "$APP_IMAGE")"
for expected in \
    '"User":"65532:65532"' \
    '"/var/lib/jmcp":{}' \
    '"--staging-dir"' \
    '"/var/lib/jmcp/staging"' \
    '"--known-hosts-file"' \
    '"/var/lib/jmcp/known_hosts"' \
    '"--device-lease-dir"' \
    '"/var/lib/jmcp/device-leases"' \
    '"Healthcheck":{"Test":["CMD-SHELL","kill -0 1"]'; do
    [[ "$image_config" == *"$expected"* ]] || {
        echo "application image config missing: $expected" >&2
        exit 1
    }
done

echo ">> Building isolated OpenSSH/SCP fixture"
docker build --tag "$FIXTURE_IMAGE" \
    "$ROOT/packaging/tests/fixtures/scp-server"

fixture_image_config="$(docker image inspect --format '{{json .Config}}' "$FIXTURE_IMAGE")"
# The image metadata must retain this command literally; do not expand $(...).
# shellcheck disable=SC2016
[[ "$fixture_image_config" == *'"Healthcheck":{"Test":["CMD-SHELL","test -s /run/sshd.pid && kill -0 \"$(cat /run/sshd.pid)\""]'* ]] || {
    echo "SCP fixture image config missing healthcheck" >&2
    exit 1
}

ssh-keygen -q -t ed25519 -N '' -f "$WORK/client_key"
printf '%s\n' 'container upload payload' >"$WORK/upload.bin"
printf '%s\n' 'container fetch payload' >"$WORK/from-device.bin"

docker network create "$NETWORK" >/dev/null
docker volume create "$STATE_VOLUME" >/dev/null
docker volume create "$KEY_VOLUME" >/dev/null
docker run -d --name "$FIXTURE_CONTAINER" \
    --network "$NETWORK" \
    -v "$WORK/client_key.pub:/fixture/client_key.pub:ro" \
    "$FIXTURE_IMAGE" >/dev/null

ready=0
for _ in $(seq 1 100); do
    if docker exec "$FIXTURE_CONTAINER" sh -c \
        'test -s /etc/ssh/ssh_host_ed25519_key.pub && test -s /run/sshd.pid && kill -0 "$(cat /run/sshd.pid)"' \
        >/dev/null 2>&1; then
        ready=1
        break
    fi
    sleep 0.1
done
if [[ "$ready" != "1" ]]; then
    docker logs "$FIXTURE_CONTAINER" >&2
    echo "SCP fixture did not become ready" >&2
    exit 1
fi

read -r host_key_type host_key_data _ < <(
    docker exec "$FIXTURE_CONTAINER" cat /etc/ssh/ssh_host_ed25519_key.pub
)
printf '%s %s %s\n' "$FIXTURE_CONTAINER" "$host_key_type" "$host_key_data" \
    >"$WORK/known_hosts"

# Populate named volumes as root, then exercise the application image using
# its default non-root UID/GID 65532.
docker run --rm --user 0:0 \
    --entrypoint /bin/sh \
    -v "$STATE_VOLUME:/var/lib/jmcp" \
    -v "$KEY_VOLUME:/etc/jmcp/keys" \
    -v "$WORK:/fixture:ro" \
    "$APP_IMAGE" -ec '
        cp /fixture/known_hosts /var/lib/jmcp/known_hosts
        cp /fixture/upload.bin /var/lib/jmcp/staging/upload.bin
        cp /fixture/client_key /etc/jmcp/keys/id_ed25519
        chown -R 65532:65532 /var/lib/jmcp /etc/jmcp/keys
        chmod 0700 /var/lib/jmcp/device-leases /etc/jmcp/keys
        chmod 0600 /var/lib/jmcp/known_hosts /etc/jmcp/keys/id_ed25519
    '

docker run --rm \
    --entrypoint /bin/sh \
    -v "$STATE_VOLUME:/var/lib/jmcp" \
    -v "$KEY_VOLUME:/etc/jmcp/keys:ro" \
    "$APP_IMAGE" -ec '
        test "$(id -u)" = 65532
        test "$(id -g)" = 65532
        test -x /usr/bin/scp
        test -w /var/lib/jmcp/staging
        test -w /var/lib/jmcp/known_hosts
        test -w /var/lib/jmcp/device-leases
    '

scp_in_runtime() {
    docker run --rm \
        --network "$NETWORK" \
        --entrypoint /usr/bin/scp \
        -v "$STATE_VOLUME:/var/lib/jmcp" \
        -v "$KEY_VOLUME:/etc/jmcp/keys:ro" \
        "$APP_IMAGE" \
        -O -P 22 \
        -i /etc/jmcp/keys/id_ed25519 \
        -o BatchMode=yes \
        -o IdentitiesOnly=yes \
        -o StrictHostKeyChecking=yes \
        -o UserKnownHostsFile=/var/lib/jmcp/known_hosts \
        -o ConnectTimeout=5 \
        "$@"
}

echo ">> Verifying legacy SCP upload from the application image"
scp_in_runtime \
    /var/lib/jmcp/staging/upload.bin \
    "fixture@$FIXTURE_CONTAINER:/home/fixture/upload.bin"
expected_upload="$(sha256sum "$WORK/upload.bin" | awk '{print $1}')"
actual_upload="$(docker exec "$FIXTURE_CONTAINER" sha256sum /home/fixture/upload.bin | awk '{print $1}')"
[[ "$actual_upload" == "$expected_upload" ]]

docker cp "$WORK/from-device.bin" "$FIXTURE_CONTAINER:/home/fixture/from-device.bin"
docker exec "$FIXTURE_CONTAINER" chown fixture:fixture /home/fixture/from-device.bin

echo ">> Verifying legacy SCP fetch into writable application state"
scp_in_runtime \
    "fixture@$FIXTURE_CONTAINER:/home/fixture/from-device.bin" \
    /var/lib/jmcp/staging/fetched.bin
expected_fetch="$(sha256sum "$WORK/from-device.bin" | awk '{print $1}')"
actual_fetch="$(docker run --rm \
    --entrypoint /usr/bin/sha256sum \
    -v "$STATE_VOLUME:/var/lib/jmcp" \
    "$APP_IMAGE" /var/lib/jmcp/staging/fetched.bin | awk '{print $1}')"
[[ "$actual_fetch" == "$expected_fetch" ]]

echo ">> Container runtime dependency, non-root state, upload, and fetch passed"
