#   SECTION: BASE COMMAND
BASE_UPDATE_UPGRADE: str = 'sudo apt update && sudo apt -y upgrade && sudo apt -f install && sudo apt -y autoremove'

BASE_APP_INSTALL: str = 'sudo apt install {} -y && sudo apt -f install && sudo apt -y autoremove'

BASE_APP_REMOVE: str = 'sudo apt remove {} -y && sudo apt -y autoremove'


#   SECTION: USER
USER_ADD: str = 'sudo adduser --gecos "" --home /home/{} {}'

USER_ADD_SUDO: str = 'sudo adduser --gecos "" --home /home/{} {} && sudo usermod -aG sudo {}'

USER_DELETE: str = 'sudo deluser {}'

USER_ADD_GROUP: str = 'sudo usermod -aG {} {}'

USER_DELETE_GROUP: str = 'sudo deluser {} {}'

USER_LIST: str = 'cut -d: -f1 /etc/passwd'

USER_GROUP_LIST = 'groups {}'

#   SECTION: HOSTS COMMAND
HOST_SHOW_NAME: str = ''

HOST_SET_NAME: str = ''

#   SECTION: FIREWALL COMMAND (UFW)
#   SECTION: FIREWALL COMMAND (IPTABLES)
#   SECTION: FIREWALL COMMAND (NFTABLES)

