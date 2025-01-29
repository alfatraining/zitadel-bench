#!/usr/bin/env bash

set -euo pipefail

zitcli create-users --username-prefix="$(hostname)" || true
zitcli authenticate --username="$(hostname)"-0@example.com
