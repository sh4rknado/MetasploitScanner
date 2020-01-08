from Scanner.Scanner import Scanner
import os
import argparse
import time

if __name__ == "__main__":
    scanner = Scanner()

    parser = argparse.ArgumentParser()
    parser.add_argument("--update", help="update the database of vulns")
    parser.add_argument("--ip", help="Set the ip to scanner")
    args = parser.parse_args()

    if args.update:
        scanner.update_db()

    elif args.ip:
        ip = args.ip

        # Discovery Port
        ports = scanner.port_discovery(ip)
        time.sleep(60)

        # Discovery Services
        scanner.service_discovery(ip, ports)
        time.sleep(60)

        # Discovery Vulns
        scanner.vuln_discovery(ip, ports)
        time.sleep(60)

        scanner.logout()
        print("----------------------------------")
        print("Author : zerocool")
        print("Github : SH4RKNANDO")
        print("----------------------------------")
        print("use msfconsole and use (vulns), hosts for showing the gatering Informations")
        exit(0)
    else:
        print("Usage : sudo python3.7 MetasploitScanner.py --ip <Your IP>")
        print("--ip : <Target IP>")
        print("--update : True (update vulnaribilities db)")
