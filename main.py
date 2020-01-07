from Scanner.Scanner import Scanner
import os

if __name__ == "__main__":
    scanner = Scanner()

    # scanner.update_db()
    ip_scan = "192.168.2.254"

    # Discovery Port
    scanner.port_discovery(speed=5, ip=ip_scan)
    scanner.port_discovery_passive(speed=5, ip=ip_scan)
    scanner.port_dicovery_udp(speed=5, ip=ip_scan)

    # Discover OS
    scanner.os_discovery(speed=5, ip=ip_scan)

    # Get list of port
    port = scanner.get_port_list(ip=ip_scan)
    # print(port)

    # Scan TCP Version
    cpt = 0
    for p in port:
        cpt += 1
        os.system("clear")
        print("[PROCESS] scan service TCP : " + str(cpt) + "/" + str(len(port)))
        scanner.scan_version(speed=5, ip=ip_scan, port=p)

    # Scan TCP Passive
    cpt = 0
    for p in port:
        cpt += 1
        os.system("clear")
        print("[PROCESS] scan service passive TCP : " + str(cpt) + "/" + str(len(port)))
        scanner.scan_version(speed=5, ip=ip_scan, port=p)

    # Scan UDP Version
    cpt = 0
    for p in port:
        cpt += 1
        os.system("clear")
        print("[PROCESS] scan service udp : " + str(cpt) + "/" + str(len(port)))
        scanner.scan_version_udp(speed=5, ip=ip_scan, port=p)

    # Scan vulns
    cpt = 0
    for p in port:
        cpt += 1
        os.system("clear")
        print("[PROCESS] scan vulnerabilities : " + str(cpt) + "/" + str(len(port)))
        scanner.scan_version_udp(speed=5, ip=ip_scan, port=p)
        scanner.vuln_discovery(port=p, ip=ip_scan)
