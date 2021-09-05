#!/usr/bin/bash

if [ "$EUID" -ne 0 ]
  then echo "Please run as root"
  exit
fi

function dependancy {
  echo -e "\nInstall dependancy\n"
  sudo apt install nmap
  sudo apt install git
}

function install_vulns {
  cd /usr/share/nmap/scripts/

  echo -e "\ninstall nmap-vulners\n"
  git clone https://github.com/vulnersCom/nmap-vulners.git

  echo -e "\ninstall vulnscan\n"
  git clone https://github.com/scipag/vulscan.git

  cd vulscan/utilities/updater/
  chmod +x updateFiles.sh
  echo -e "\nupdating vulnerabilites databases\n"
  ./updateFiles.sh
}

dependancy
install_vulns
