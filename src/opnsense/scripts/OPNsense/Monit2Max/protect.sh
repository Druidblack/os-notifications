#!/bin/sh
# Only root may read the configd-rendered credentials.
set -eu
file=/usr/local/etc/monit2max/settings.conf
[ -f "$file" ] || exit 1
/bin/chmod 0600 "$file"
/bin/chmod 0700 /usr/local/etc/monit2max
