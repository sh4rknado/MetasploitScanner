# !/usr/bin/env python33
# -*- coding: utf-8 -*-

__author__ = "Jordan BERTIEAUX"
__copyright__ = "Copyright 2021, Metasploit Framework"
__credits__ = ["Jordan BERTIEAUX"]
__license__ = "GPL"
__version__ = "1.0"
__maintainer__ = "Jordan BERTIEAUX"
__email__ = "jordan.bertieaux@std.heh.be"
__status__ = "Production"

import os
from Model.Scanner import Scanner
from Utils.Level import Level
from nmap.nmap import PortScanner


class ScannerNmap(Scanner):

    def __init__(self, speed, sudo_pass, metasploitClient, main_observer):
        Scanner.__init__(self, metasploitClient, main_observer)
        self._speed = speed
        self._sudo_password = sudo_pass
        self._db = []
        self._init_db()
        self._output_dir = os.getcwd() + "/data/output"
        self._scripts = os.getcwd() + "/data/scripts"
        self.scan_IsBusy = False

    # ------------------------------------------- < INIT FUNCTION > -------------------------------------------

    # Set scan speed
    def set_speed(self, speed):
        if 0 > speed > 5:
            self.ShowMessage(Level.error, "value scan speed wrong")
        else:
            self._speed = speed

    # Init the DataBase
    def _init_db(self):
        path = os.getcwd() + "/data/db_scan"
        if not os.path.isfile(path):
            self.ShowMessage(Level.error, "Could not initialize the vulnerabilities databases")
            exit(0)
        else:
            self.ShowMessage(Level.info, "Initialize the vulnerabilities databases")

            temp = open(path, 'r').read().split('\n')

            for x in temp:
                if x != '':
                    self._db.append(str(x))

            self.ShowMessage(Level.success, "Initialization databases completed")

    # Update the databaseFile
    def update_db(self):
        path = self._scripts + "/update.sh"

        if not os.path.isfile(path):
            self.ShowMessage(Level.error, f"database could not update reason is File not found : {path}")
            exit(0)
        else:
            self.ShowMessage(Level.info, "update the db now ...")
            os.system(f"echo  {self._sudo_password}  | sudo -S bash {path}")

    # ------------------------------------------- < REPORT ANALYSE > -------------------------------------------

    def _get_port(self, report, ip):
        dir_port_list = f"{self._output_dir}/{ip}-portlist"

        cmd = "python3 " + self._scripts + "/nmap_xml_parser.py -f " + report + " -pu | sed -e " + "'" \
              + "s/[^0-9]/ /g" + "'" + " -e " + "'" + "s/^ *//g" + "'" + " -e " + "'" + "s/ *$//g" + "'" \
              + " | tr -s " + "' " + "'" + " | sed " + "'" + "s/ /" + "\\n" + "/g" + "'" + " >> " + dir_port_list
        return os.system(cmd)

    def _get_port_list(self, ip):
        dir_port_list = f"{self._output_dir}/{ip}-portlist"
        ports = []
        if not os.path.isfile(dir_port_list):
            self.ShowMessage(Level.error, f"port list not found : {dir_port_list}")
        else:
            self.ShowMessage(Level.info, "Get list of scanned hosts\n")
            temp = open(dir_port_list, 'r').read().split('\n')

            for x in temp:
                if x != '' and not ports.__contains__(x):
                    ports.append(str(x))
            self.ShowMessage(Level.success, f"enumerate port completed : \n{ports}\n")

        return ports

    # ------------------------------------------- < PORT DISCOVERY > -------------------------------------------

    # Port scanner
    def _port_discovery(self, ip):
        if self.validate_ip(ip):

            if self.client.client_Isbusy:
                self.client.waitclient()

            self.ShowMessage(Level.info, "Port discovery starting...")
            self.client.send_cmd(f"db_nmap --save -sS -T {self._speed} -v {ip} -oX output/{ip}.xml")
        else:
            self.ShowMessage(Level.error, f"not ip valid : {ip}")

        test = self._get_port("/root/.msf4/local/*.xml", ip)
        toto = ""

    # Port scanner NO PING
    def _port_discovery_passive(self, ip):
        if self.validate_ip(ip):

            if self.client.client_Isbusy:
                self.client.waitclient()

            self.ShowMessage(Level.info, "starting passive port discovery (no ping)...")
            self.client.send_cmd(f"db_nmap --save -Pn -T {self._speed} -v {ip}")
        else:
            self.ShowMessage(Level.error, f"ip is not valid {ip}")

        self._get_port("/root/.msf4/local/*.xml", ip)

    # Scan service version UDP
    def _port_dicovery_udp(self, ip):
        if self.validate_ip(ip):

            if self.client.client_Isbusy:
                self.client.waitclient()

            self.ShowMessage(Level.info, "Starting port discovery (udp)")
            self.client.send_cmd(f"db_nmap --save -sUV -T {self._speed} -F --version-intensity 0 -v {ip} ")
        else:
            self.ShowMessage(Level.error, f"ip is not valid {ip}")

        self._get_port("/root/.msf4/local/*.xml", ip)

    # ------------------------------------------- < VERSION DISCOVERY > -------------------------------------------

    # OS probe scanner
    def _os_discovery(self, ip):
        if self.validate_ip(ip):

            if self.client.client_Isbusy:
                self.client.waitclient()

            self.ShowMessage(Level.info, "Starting os discovery")
            self.client.send_cmd(f"db_nmap -sV -A -O --osscan-guess -T {self._speed} -v {ip}")
        else:
            self.ShowMessage(Level.error, f"ip is not valid {ip}")

    # Scan service version TCP
    def _scan_version(self, ip, port):
        if self.validate_ip(ip):

            if self.client.client_Isbusy:
                self.client.waitclient()

            self.ShowMessage(Level.info, f"starting service discover  on {port}")
            self.client.send_cmd(f"db_nmap -sS -sV -p {port} -T {self._speed} -v {ip}")
        else:
            self.ShowMessage(Level.error, "IP is not valid : {ip}")

    # Scan service version UDP
    def _scan_version_passive(self, ip, port):
        if self.validate_ip(ip):

            if self.client.client_Isbusy:
                self.client.waitclient()

            self.ShowMessage(Level.info, f"starting passive service (udp) discover on {port}")
            self.client.send_cmd(f"db_nmap -Pn -sV -p {port} -T {self._speed} -v {ip}")
        else:
            self.ShowMessage(Level.error, f"ip is not valid {ip}")

    # Scan service version UDP
    def _scan_version_udp(self, ip, port):
        if self.validate_ip(ip):

            if self.client.client_Isbusy:
                self.client.waitclient()

            self.ShowMessage(Level.info, f"discover service (udp) on {port}")
            self.client.send_cmd(f"db_nmap -sUV -p {port} -T {self._speed} -v {ip}")
        else:
            self.ShowMessage(Level.error, f"ip is not valid {ip}")

    # ------------------------------------------- < VULNERABILTY DISCOVERY > -------------------------------------------

    # Vulnerabilities Scanner
    def _vuln_discovery(self, ip, port):
        if self.validate_ip(ip):
            cpt = 0
            self.ShowMessage(Level.info, "Starting vulnerabilities scanner...")

            for db in self._db:

                if self.client.client_Isbusy:
                    self.client.waitclient()

                cpt += 1
                self.ShowMessage(Level.info, "Processing vuln-scan on {port} with {db} : {cpt}/{len(self._db)}")
                self.client.send_cmd(f"db_nmap --script nmap-vulners,vulscan --script-args vulscandb={db} -sV -p {port} {ip} ")
        else:
            self.ShowMessage(Level.error, f"ip is not valid {ip}")

    # ------------------------------------------- < SMART DISCOVERY > -------------------------------------------

    def port_discovery(self, ip_scan):
        self.scan_IsBusy = True

        # Discovery Port
        self._port_discovery(ip_scan)
        # self._port_discovery_passive(ip_scan)
        # self._port_dicovery_udp(ip_scan)

        # Discover OS
        # self._os_discovery(ip_scan)

    def get_ports(self, ip_scan):
        ports = self._get_port_list(ip_scan)
        self.scan_IsBusy = False
        return ports

    def service_discovery(self, ip_scan, ports):
        self.scan_IsBusy = True
        os.system("clear")
        self.ShowMessage(Level.info, "starting discovery service...")

        # Scan TCP Version
        cpt = 0
        for p in ports:
            cpt += 1
            self.ShowMessage(Level.info, f"[PROCESS] scan service TCP : {cpt}/{len(ports)}")
            self._scan_version(ip=ip_scan, port=p)

            self.ShowMessage(Level.info, f"[PROCESS] discovery service (passive TCP) : {cpt}/{len(ports)}")
            self._scan_version_passive(ip=ip_scan, port=p)

            self.ShowMessage(Level.info, f"[PROCESS] discovery service (UDP) : {cpt}/{len(ports)}")
            self._scan_version_udp(ip=ip_scan, port=p)

        self.scan_IsBusy = False

    def vuln_discovery(self, ip_scan, port):
        self.scan_IsBusy = True
        os.system("clear")
        self.ShowMessage(Level.info, "Running Vulns discovery...")

        # Scan vulns
        cpt = 0
        for p in port:
            cpt += 1
            os.system("clear")
            self.ShowMessage(Level.info, f"[PROCESS] scan vulnerabilities {cpt}/{len(port)}...")
            self._vuln_discovery(port=p, ip=ip_scan)

        self.scan_IsBusy = False
