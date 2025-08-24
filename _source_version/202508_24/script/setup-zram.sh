#!/bin/bash

# Script (bash): install and settings zram-tools (package) | DEBIAN 12
# 202508.24 (0.3)


# NOTE: SCRIPT VARIABLES
PATH_LOG_DIR="logs"
PATH_LOG_FILE="$PATH_LOG_DIR/setup-zram.log"

PATH_CONFIG_FILE="/etc/default/zramswap"
CONFIG_ALGO="zstd"
CONFIG_SIZE="50"
CONFIG_PRIORITY="100"

# NOTE: CHECK USER TYPE
if [ "$(id -u)" -eq 0 ]; then
  SUDO=""
else
  SUDO="sudo"
fi

# NOTE: GET ZRAM CONFIG DATA
ZRAM_CONFIG="# Automatically created by a script
# Script version: 202508.24 (0.3)

ALGO=$CONFIG_ALGO
PERCENT=$CONFIG_SIZE
PRIORITY=$CONFIG_PRIORITY
"

# NOTE: FUNCTIONS
prepare_logs() {
  if [ ! -d "$PATH_LOG_DIR" ]; then
    mkdir -p "$PATH_LOG_DIR"
    echo "[INFO] Log directory has been created: $PATH_LOG_DIR"
  fi

  if [ ! -f "$PATH_LOG_FILE" ]; then
    touch "$PATH_LOG_FILE"
    echo "[INFO] Log file has been created: $PATH_LOG_FILE"
  fi

  if [ ! -w "$PATH_LOG_FILE" ]; then
    echo "[INFO] No permissions to write, change rights (640)"
    $SUDO chmod 640 "$PATH_LOG_FILE"
    $SUDO chown "$(id -un)":"$(id -gn)" "$PATH_LOG_FILE"
  fi
}

progress_task() {
  local MSG="$1"
  shift
  echo -n "[TASK] $MSG ... "
  {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $MSG"
    "$@"
  } >>"$PATH_LOG_FILE" 2>&1
  if [ $? -eq 0 ]; then
    echo "OK"
  else
    echo "FAIL ($PATH_LOG_FILE)"
  fi
}

# NOTE: INSTALL
prepare_logs

progress_task "Packages list update" $SUDO apt-get update -y
progress_task "Install package: zram-tools" $SUDO apt-get install -y zram-tools
progress_task "Installing configuration file" \
  bash -c "$SUDO cp -f $PATH_CONFIG_FILE{,.bak-$(date +%F-%H%M%S)} 2>/dev/null || true; \
           echo \"$ZRAM_CONFIG\" | $SUDO tee $PATH_CONFIG_FILE >/dev/null"
progress_task "Restart zram-tools service" $SUDO systemctl restart zramswap.service
progress_task "Enable zram-tools service"  $SUDO systemctl enable zramswap.service
progress_task "Cache cleaning" $SUDO bash -c "apt-get -f install -y && apt-get autoremove -y && apt-get autoclean -y"
progress_task "Show swap status" $SUDO swapon --show
progress_task "Show zramctl status" $SUDO zramctl
