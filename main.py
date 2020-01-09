from Scanner.Scanner import Scanner
import os
import argparse
import time

if __name__ == "__main__":
    scanner = Scanner()

    parser = argparse.ArgumentParser()
    parser.add_argument("--update", help="update the database of vulns")
    parser.add_argument("--ip", help="Set the ip to scanner")
    parser.add_argument("--type", help="Type of scanner")

    args = parser.parse_args()

    if args.update:
        scanner.update_db()

    elif args.ip:
        ip = args.ip

        ports = scanner.get_ports(ip)

        if args.type == "discovery":

            # Discovery Port
            scanner.port_discovery(ip)

            ports = scanner.get_ports(ip)

            while scanner.scan_IsBusy:
                print("[INFOS] WAIT SCAN FINISHED ! ")
                time.sleep(5)

            # Discovery Services
            scanner.service_discovery(ip, ports)

            while scanner.scan_IsBusy:
                print("[INFOS] WAIT SCAN FINISHED ! ")
                time.sleep(5)

        if args.type == "vulnerability":
            # Discovery Vulns
            scanner.vuln_discovery(ip, ports)

            while scanner.scan_IsBusy:
                print("[INFOS] WAIT SCAN FINISHED ! ")
                time.sleep(5)

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
        print("--type : discovery / vulnerability (update vulnaribilities db)")

