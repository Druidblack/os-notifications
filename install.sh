#!/bin/sh
# Source installer for OPNsense / FreeBSD; not a signed pkg.
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
[ "$(id -u)" -eq 0 ] || { echo 'Run as root' >&2; exit 1; }
[ "$(uname -s)" = FreeBSD ] || { echo 'Requires OPNsense / FreeBSD' >&2; exit 1; }
[ -x /usr/local/sbin/configctl ] || { echo 'OPNsense configctl missing' >&2; exit 1; }
[ -x /usr/local/bin/python3 ] || { echo 'Python 3 missing' >&2; exit 1; }

/bin/mkdir -p /usr/local/etc/monit2max /var/db/monit2max
/bin/chmod 0700 /usr/local/etc/monit2max /var/db/monit2max

# Stop the old watcher before replacing its running code.
if [ -x /usr/local/etc/rc.d/monit2max ]; then
    /usr/local/etc/rc.d/monit2max onestop >/dev/null 2>&1 || true
fi

# The watcher initializes the cursor before a test is submitted.
/usr/bin/install -m 0600 /dev/null /var/db/monit2max/delivery-test.log

for sub in opnsense etc; do
    cd "$ROOT/src/$sub"
    find . -type f | while IFS= read -r file; do
        destination="/usr/local/$sub/${file#./}"
        /bin/mkdir -p "$(dirname "$destination")"
        case "$file" in
            ./scripts/OPNsense/Monit2Max/*.py|./scripts/OPNsense/Monit2Max/*.php|./scripts/OPNsense/Monit2Max/*.sh|./rc.d/*|./rc.syshook.d/*)
                /usr/bin/install -m 0755 "$file" "$destination" ;;
            *)  /usr/bin/install -m 0644 "$file" "$destination" ;;
        esac
    done
done
/bin/rm -f /usr/local/opnsense/scripts/OPNsense/Monit2Max/restore_monit_actions.php
# Keep forms/general.xml: it now holds the first, general settings section.
/usr/sbin/service configd restart
/usr/local/sbin/configctl template reload OPNsense/Monit2Max
/usr/local/sbin/configctl monit2max protect
/usr/local/sbin/configctl monit2max apply
# OPNsense 26.7 stores MVC menu/ACL caches under application.tempDir,
# normally /var/lib/php/tmp (not /tmp). Remove both locations for upgrades.
/bin/rm -f /var/lib/php/tmp/opnsense_menu_cache.xml /var/lib/php/tmp/opnsense_acl_cache.json \
    /tmp/opnsense_menu_cache.xml /tmp/opnsense_acl_cache.json
# Verify the new menu file was installed and does not contain a Monit submenu.
MENU=/usr/local/opnsense/mvc/app/models/OPNsense/Monit2Max/Menu/Menu.xml
if ! /usr/bin/grep -q '<SystemNotifications ' "$MENU"; then
    echo 'Error: Notifications menu was not installed correctly' >&2
    exit 1
fi
printf '%s\n' 'OPNsense Notifications v0.6.9 installed.' \
  'Open Services -> Notifications and save settings.' \
  'Existing notification settings and monitored services are preserved.'
