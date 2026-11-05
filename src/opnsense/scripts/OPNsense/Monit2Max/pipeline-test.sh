#!/bin/sh
# Verify watcher -> notification queue -> all enabled destinations.
# Uses a private test inbox, independent of OPNsense syslog routing.
exec /usr/local/bin/python3 /usr/local/opnsense/scripts/OPNsense/Monit2Max/watcher.py --pipeline-test
