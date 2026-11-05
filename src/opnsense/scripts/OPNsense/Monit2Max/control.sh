#!/bin/sh
# Apply the auto-started watcher after settings changes; never alter Monit.
set -eu
rc=/usr/local/etc/rc.d/monit2max
settings=/usr/local/etc/monit2max/settings.conf
case "${1:-}" in
  apply)
    if [ ! -f "$settings" ]; then
      echo '{"status":"failed","message":"Save settings first"}'
      exit 1
    fi
    "$rc" onestop >/dev/null 2>&1 || true
    if /usr/bin/grep -q '^Enabled=1$' "$settings"; then
      if "$rc" onestart >/dev/null 2>&1; then
        echo '{"status":"ok","message":"Settings applied; notification log watcher started"}'
      else
        echo '{"status":"failed","message":"Could not start notification watcher; check system log"}'
        exit 1
      fi
    else
      echo '{"status":"ok","message":"Settings applied; notifications disabled"}'
    fi
    ;;
  *) echo '{"status":"failed","message":"Invalid control action"}'; exit 1 ;;
esac
