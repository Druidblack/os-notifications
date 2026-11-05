#!/bin/sh
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
[ "$(id -u)" -eq 0 ] || { echo 'Run as root' >&2; exit 1; }
[ "$(uname -s)" = FreeBSD ] || { echo 'Requires OPNsense / FreeBSD' >&2; exit 1; }
if [ -x /usr/local/etc/rc.d/monit2max ]; then
  /usr/local/etc/rc.d/monit2max onestop >/dev/null 2>&1 || true
fi
for sub in opnsense etc; do
  cd "$ROOT/src/$sub"
  find . -type f | while IFS= read -r file; do
    /bin/rm -f "/usr/local/$sub/${file#./}"
  done
done
/bin/rm -f /tmp/opnsense_menu_cache.xml /tmp/opnsense_acl_cache.json /var/lib/php/tmp/opnsense_menu_cache.xml /var/lib/php/tmp/opnsense_acl_cache.json
/bin/rm -f /var/db/monit2max/delivery-test.log
if [ "${1:-}" = "--purge-runtime" ]; then
  /bin/rm -f /usr/local/etc/monit2max/settings.conf
  /bin/rm -f /var/db/monit2max/state.json /var/db/monit2max/stop-notification.json
  /bin/rmdir /var/db/monit2max /usr/local/etc/monit2max 2>/dev/null || true
fi
/bin/rm -f /usr/local/opnsense/scripts/OPNsense/Monit2Max/restore_monit_actions.php
/bin/rm -f /usr/local/opnsense/mvc/app/controllers/OPNsense/Monit2Max/forms/general.xml
/usr/sbin/service configd restart
printf '%s\n' 'OPNsense Notifications plugin and service files removed.' \
  'Settings in /conf/config.xml are preserved.'
