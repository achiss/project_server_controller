#!/bin/bash
# system_package_upgrade.sh
# 202508_24 (0.1)

set -euo pipefail

PACKAGE_MANAGER=${1:-""}
USER_TYPE=${2:-""}

# NOTE: FUNCTION
case "$PACKAGE_MANAGER" in
  apt-get)  "$USER_TYPE" apt-get upgrade -y ;;
  dnf)      "$USER_TYPE" dnf upgrade -y ;;
  yum)      "$USER_TYPE" yum upgrade -y ;;
  *)        echo "[ERROR] Unknown package manager: $PACKAGE_MANAGER"
            exit 1 ;;

esac
