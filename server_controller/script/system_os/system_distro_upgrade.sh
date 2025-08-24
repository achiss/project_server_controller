#!/bin/bash
# system_distro_upgrade.sh
# 202508_24 (0.1)

set -euo pipefail

PACKAGE_MANAGER=${1:-""}
USER_TYPE=${2:-""}

# NOTE: FUNCTION
case "$PACKAGE_MANAGER" in
  apt-get)  "$USER_TYPE" apt-get dist-upgrade -y ;;
  dnf)      ;;
  yum)      ;;
  *)        echo "[ERROR] Unknown package manager: $PACKAGE_MANAGER"
            exit 1 ;;

esac
