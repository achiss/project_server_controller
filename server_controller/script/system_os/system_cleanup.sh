#!/bin/bash
# system_package_dependencies.sh
# 202508_24 (0.1)

set -euo pipefail

PACKAGE_MANAGER=${1:-""}
USER_TYPE=${2:-""}

# NOTE: FUNCTION
case "$PACKAGE_MANAGER" in
  apt-get)  "$USER_TYPE" apt-get autoremove -y
            "$USER_TYPE" apt-get autoclean -y
            "$USER_TYPE" apt-get clean -y ;;
  dnf)      "$USER_TYPE" dnf autoremove -y
            "$USER_TYPE" dnf clean all ;;
  yum)      "$USER_TYPE" yum autoremove -y
            "$USER_TYPE" yum clean all ;;
  *)        echo "[ERROR] Unknown package manager: $PACKAGE_MANAGER"
            exit 1 ;;

esac
