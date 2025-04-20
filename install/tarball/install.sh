#!/usr/bin/env bash

set -eu

SRC_DIR=$(dirname -- "$(readlink -f -- "$0")")

cp -vRf ${SRC_DIR}/usr/local/* /usr/local/

cp -vf ${SRC_DIR}/usr/lib/systemd/system/bombini.service /usr/lib/systemd/system/bombini.service

install -d /var/log/bombini

systemctl daemon-reload
systemctl enable bombini
systemctl start bombini

echo "Bombini installed successfully!"