#!/bin/sh
set -eu

if [ ! -s /fixture/client_key.pub ]; then
    echo "missing /fixture/client_key.pub" >&2
    exit 1
fi

install -d -m 0700 -o fixture -g fixture /home/fixture/.ssh
install -m 0600 -o fixture -g fixture \
    /fixture/client_key.pub /home/fixture/.ssh/authorized_keys
ssh-keygen -A >/dev/null

exec /usr/sbin/sshd -D -e -f /etc/ssh/sshd_config
