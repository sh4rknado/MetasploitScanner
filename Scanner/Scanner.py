import os
import socket
from Metasploit.Metasploit import Metasploit


class Scanner:

    def __init__(self):
        self._speed = 3
        self._db = []
        self._init_db()
        self._output_dir = os.getcwd() + "/output"
        self._NmapParser = os.getcwd() + "/utilities"
        self._client = Metasploit(user="msf", password="zerocool")

    # ------------------------------------------- < INIT FUNCTION > -------------------------------------------

    # Set scan speed
    def set_speed(self, speed):
        if 0 > speed > 5:
            print("[ERROR] value scan speed wrong")
        else:
            self._speed = speed

    # Init the DataBase
    def _init_db(self):
        path = os.getcwd() + "/data/db_scan"
        if not os.path.isfile(path):
            print("[ERROR] Can't initialize the Vulnerabilities Databases")
            exit(0)
        else:
            print("[INFOS] Initialize the Vulnerabilities Databases")

            temp = open(path, 'r').read().split('\n')

            for x in temp:
                if x != '':
                    self._db.append(str(x))

            print("[SUCESS] Initialize db completed\n")

    # Check if IP is Valid
    def _validate_ip(self, ip):
        try:
            socket.inet_aton(ip)
            check = True
        except socket.error:
            check = False
        return check

    # Update the databaseFile
    def update_db(self):
        path = os.getcwd() + "/utilities/update.sh"

        if not os.path.isfile(path):
            print("[ERROR] FILE NOT FOUND : " + str(path))
            exit(0)
        else:
            print("[INFOS] update the db now ...")
            password = input("What is the sudo password ?")
            os.system("echo " + password + " | sudo -S bash " + path)

    # ------------------------------------------- < REPORT ANALYSE > -------------------------------------------

    def _get_port(self, report, ip):
        dir_port_list = self._output_dir + "/" + ip + "-portlist"

        cmd = "python " + self._NmapParser + "/nmap_xml_parser.py -f " + report + " -p | awk '{ print $3 }' >> " \
              + dir_port_list

        os.system(cmd)

    def _get_port_list(self, ip):
        dir_port_list = self._output_dir + "/" + ip + "-portlist"
        ports = []
        if not os.path.isfile(dir_port_list):
            print("[ERROR] Can't get list of port")
        else:
            print("[INFOS] Get list of scanned hosts")

            temp = open(dir_port_list, 'r').read().split('\n')

            for x in temp:
                if x != '' and not ports.__contains__(x):
                    ports.append(str(x))

            print("[SUCESS] list of port completed\n")

        return ports

    # ------------------------------------------- < PORT DISCOVERY > -------------------------------------------

    # Port scanner
    def _port_discovery(self, speed, ip):
        if self._validate_ip(ip):
            print("[INFOS] Running Port Discovery\n")
            cmd = "db_nmap --save -sS -T" + str(speed) + " -v " + ip
            self._client.send_cmd(cmd)
        else:
            print("[ERROR] IP is not valid : " + str(ip))
        self._get_port("/root/.msf4/local/*.xml", ip)

    # Port scanner NO PING
    def _port_discovery_passive(self, speed, ip):
        if self._validate_ip(ip):
            print("\n[INFOS] Running Port Discovery no ping\n")
            cmd = "db_nmap --save -Pn -T" + str(speed) + " -v " + ip
            self._client.send_cmd(cmd)
        else:
            print("[ERROR] IP is not valid : " + str(ip))
        self._get_port("/root/.msf4/local/*.xml", ip)

    # Scan service version UDP
    def _port_dicovery_udp(self, speed, ip):
        if self._validate_ip(ip):
            print("\n[INFOS] Running Port Discovery udp\n")
            cmd = "db_nmap --save -sUV -T" + str(speed) + " -F --version-intensity 0 -v " + ip
            self._client.send_cmd(cmd)
        else:
            print("[ERROR] IP is not valid : " + str(ip))
        self._get_port("/root/.msf4/local/*.xml", ip)

    # ------------------------------------------- < VERSION DISCOVERY > -------------------------------------------

    # OS probe scanner
    def _os_discovery(self, speed, ip):
        if self._validate_ip(ip):
            print("\n[INFOS] Running OS discovery")
            cmd = "db_nmap -sV -A -O --osscan-guess -T" + str(speed) + " -v " + ip
            self._client.send_cmd(cmd)
        else:
            print("[ERROR] IP is not valid : " + str(ip))

    # Scan service version TCP
    def _scan_version(self, speed, ip, port):
        if self._validate_ip(ip):
            print("\n[INFOS] discover service TCP on : " + port + "\n")
            cmd = "db_nmap -sS -sV -p" + port + " -T" + str(speed) + " -v " + ip
            self._client.send_cmd(cmd)
        else:
            print("[ERROR] IP is not valid : " + str(ip))

    # Scan service version UDP
    def _scan_version_passive(self, speed, ip, port):
        if self._validate_ip(ip):
            print("\n[INFOS] discover service TCP Passive on : " + port + "\n")
            cmd = "db_nmap -Pn -sV -p" + str(port) + "-T" + str(speed) + " -v " + ip
            self._client.send_cmd(cmd)
        else:
            print("[ERROR] IP is not valid : " + str(ip))

    # Scan service version UDP
    def _scan_version_udp(self, speed, ip, port):
        if self._validate_ip(ip):
            print("\n[INFOS] discover service UDP on : " + port + "\n")
            cmd = "db_nmap -sUV -p" + str(port) + "-T" + str(speed) + " -v " + ip
            self._client.send_cmd(cmd)
        else:
            print("[ERROR] IP is not valid : " + str(ip))

    # ------------------------------------------- < VULNERABILTY DISCOVERY > -------------------------------------------

    # Vulnerabilities Scanner
    def _vuln_discovery(self, ip, port):
        if self._validate_ip(ip):
            cpt = 0
            print("\n[INFOS] Running vulnerabilities scanner\n")

            for db in self._db:
                cpt += 1
                print("[PROCESS] Processing vuln-scan " + str(cpt) + "/" + str(len(self._db)) + " \n")
                cmd = "db_nmap --script nmap-vulners,vulscan --script-args vulscandb=" + str(db) + " -sV -p " + port + " " + ip
                self._client.send_cmd(cmd)
        else:
            print("[ERROR] IP is not valid : " + str(ip))

    # ------------------------------------------- < SMART DISCOVERY > -------------------------------------------

    def port_discovery(self, ip_scan):
        # Discovery Port
        self._port_discovery(speed=5, ip=ip_scan)
        self._port_discovery_passive(speed=5, ip=ip_scan)
        self._port_dicovery_udp(speed=5, ip=ip_scan)

        # Discover OS
        self._os_discovery(speed=5, ip=ip_scan)

        # Get list of ports
        ports = self._get_port_list(ip=ip_scan)
        # print(ports)
        return ports

    def service_discovery(self, ip_scan, ports):
        os.system("clear")
        print("[PROCESS] Running Service discovery ...")

        # Scan TCP Version
        cpt = 0
        for p in ports:
            cpt += 1
            print("[PROCESS] scan service TCP : " + str(cpt) + "/" + str(len(ports)))
            self._scan_version(speed=5, ip=ip_scan, port=p)

            print("[PROCESS] scan service passive TCP : " + str(cpt) + "/" + str(len(ports)))
            self._scan_version_passive(speed=5, ip=ip_scan, port=p)

            print("[PROCESS] scan service udp : " + str(cpt) + "/" + str(len(ports)))
            self._scan_version_udp(speed=5, ip=ip_scan, port=p)

    def vuln_discovery(self, ip_scan, port):
        os.system("clear")
        print("[PROCESS] Running Vulns discovery ...")

        # Scan vulns
        cpt = 0
        for p in port:
            cpt += 1
            os.system("clear")
            print("[PROCESS] scan vulnerabilities : " + str(cpt) + "/" + str(len(port)))
            self._vuln_discovery(port=p, ip=ip_scan)
