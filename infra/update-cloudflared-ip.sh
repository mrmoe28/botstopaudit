#!/bin/bash
# Runs every 5 min via cron in CT104.
# If SpiderFoot's Docker container IP changed, patches config.yml and restarts cloudflared.

CONFIG=/etc/cloudflared/config.yml
CONTAINER_NAME="zbxmyxhv9q2o3d3zjynjqvic-004311268127"
PORT=5001

NEW_IP=$(docker inspect "$CONTAINER_NAME" --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' 2>/dev/null | head -1)

if [ -z "$NEW_IP" ]; then
    echo "ERROR: could not get IP for $CONTAINER_NAME"
    exit 1
fi

CURRENT=$(grep -A1 'hostname: botstopaudit.com' "$CONFIG" | grep 'service:' | grep -oP '\d+\.\d+\.\d+\.\d+')

if [ "$CURRENT" = "$NEW_IP" ]; then
    echo "IP unchanged ($NEW_IP), nothing to do"
    exit 0
fi

sed -i "s|service: http://${CURRENT}:${PORT}|service: http://${NEW_IP}:${PORT}|" "$CONFIG"
systemctl restart cloudflared
echo "Updated $CURRENT -> $NEW_IP, restarted cloudflared"
