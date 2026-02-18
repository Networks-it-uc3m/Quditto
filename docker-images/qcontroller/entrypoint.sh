#!/usr/bin/env bash
set -euo pipefail

# Start RabbitMQ if not running; bind using node name that matches hostname
if ! sudo rabbitmqctl status >/dev/null 2>&1; then
  sudo RABBITMQ_NODENAME="rabbit@$(hostname)" rabbitmq-server -detached
fi

for i in {1..60}; do
  sudo rabbitmqctl status >/dev/null 2>&1 && break || sleep 1
done

exec sudo "$@"
