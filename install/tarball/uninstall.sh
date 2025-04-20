#!/usr/bin/env bash

set -xu

if [ "$(id -u)" -ne 0 ]; then
        echo "Error: to uninstall Bombini please run as root." >&2
        exit 1
fi

systemctl stop bombini
systemctl disable bombini

rm -f /etc/systemd/system/default.target.wants/bombini.service

rm -rf /usr/lib/systemd/system/bombini.service
systemctl daemon-reload

rm -rf /usr/local/bin/bombini
rm -rf /usr/local/lib/bombini/