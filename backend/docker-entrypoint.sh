#!/bin/sh
set -eu

# Dokploy creates named volumes as root before mounting them over the image's
# pre-created /data directory. Repair only this application-owned volume while
# still running as root, then drop privileges for the service process.
install -d -o 10001 -g 10001 -m 0750 /data
chown -R 10001:10001 /data

exec runuser -u ryu-mail -- "$@"
