#!/bin/bash
# system_cache_update.sh
# 202508_24 (0.1)

# Arguments:
#   - 1: distro package manager (default: apt-get | dnf | yum)
#   - 2: user type (default: sudo | root)

set -euo pipefail

PACKAGE_MANAGER=${1:-""}
USER_TYPE=${2:-""}

# NOTE: FUNCTION
case "$PACKAGE_MANAGER" in
  apt-get)  "$USER_TYPE" apt-get update -y ;;
  dnf)      "$USER_TYPE" dnf makecache -y ;;
  yum)      "$USER_TYPE" yum makecache -y ;;
  *)        echo "[ERROR] Unknown package manager: $PACKAGE_MANAGER"
            exit 1 ;;

esac
