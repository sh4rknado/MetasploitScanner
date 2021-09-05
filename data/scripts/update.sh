#!/usr/bin/bash

curent_path=$(pwd)

if [ "$EUID" -ne 0 ]
  then echo "Please run as root"
  exit
fi

db_path='/usr/share/nmap/scripts/vulscan/utilities/updater'
cd $db_path

echo -e "\nupdating vulnerabilites databases\n"
chmod -v +x updateFiles.sh
bash updateFiles.sh

echo -e "\nSaving the DataBase\n"
cd /usr/share/nmap/scripts/vulscan/
ls -l *.csv | awk '{ print $9 }' > "$curent_path"/data/db_scan
