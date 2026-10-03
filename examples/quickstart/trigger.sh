#!/bin/sh
# Generates events for the quickstart config. Run it on the host
# in another terminal while Bombini is running.

echo "[1] sudo reads /etc/shadow: Setuid and FileOpen events"
sudo head -c 0 /etc/shadow

echo "[2] exec a binary from /tmp: blocked by the sandbox"
cp /bin/true /tmp/bombini-quickstart
/tmp/bombini-quickstart || echo "    blocked: exit code $?"
rm -f /tmp/bombini-quickstart

echo "[3] connect to the cloud metadata service: Egress event"
curl -s -o /dev/null -m 1 http://169.254.169.254/ || true
