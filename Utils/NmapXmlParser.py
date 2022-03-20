# !/usr/bin/env python3
# -*- coding: utf-8 -*-

__author__ = "Jordan BERTIEAUX"
__copyright__ = "Copyright 2021, Metasploit Framework"
__credits__ = ["Jordan BERTIEAUX"]
__license__ = "GPL"
__version__ = "1.0"
__maintainer__ = "Jordan BERTIEAUX"
__email__ = "jordan.bertieaux@std.heh.be"
__status__ = "Production"

import xml.etree.ElementTree as etree
import os
import csv
import argparse
from collections import Counter


class NmapXmlParser:

    def __init__(self, file):
        self.fileToParse = file

    def _parse_xml(self):
        try:
            tree = etree.parse(self.fileToParse)
            root = tree.getroot()
            return self._get_host_data(root)
        except Exception as error:
            print("[-] A an error occurred. The XML may not be well formed. "
                  "Please review the error and try again: {}".format(error))
            exit()

    def _get_host_data(self, root):
        host_data = []
        hosts = root.findall('host')
        for host in hosts:
            addr_info = []

            # Ignore hosts that are not 'up'
            if not host.findall('status')[0].attrib['state'] == 'up':
                continue

            # Get IP address and host info. If no hostname, then ''
            ip_address = host.findall('address')[0].attrib['addr']
            host_name_element = host.findall('hostnames')
            try:
                host_name = host_name_element[0].findall('hostname')[0].attrib['name']
            except IndexError:
                host_name = ''

            # If we only want the IP addresses from the scan, stop here
            if args.ip_addresses:
                addr_info.extend((ip_address, host_name))
                host_data.append(addr_info)
                continue

            # Get the OS information if available, else ''
            try:
                os_element = host.findall('os')
                os_name = os_element[0].findall('osmatch')[0].attrib['name']
            except IndexError:
                os_name = ''

            # Get information on ports and services
            try:
                port_element = host.findall('ports')
                ports = port_element[0].findall('port')
                for port in ports:
                    port_data = []

                    if args.udp_open:
                        # Display both open ports and open}filtered ports
                        if not 'open' in port.findall('state')[0].attrib['state']:
                            continue
                    else:
                        # Ignore ports that are not 'open'
                        if not port.findall('state')[0].attrib['state'] == 'open':
                            continue

                    proto = port.attrib['protocol']
                    port_id = port.attrib['portid']

                    print("portID : " + port_id)

                    service = port.findall('service')[0].attrib['name']
                    try:
                        product = port.findall('service')[0].attrib['product']
                    except (IndexError, KeyError):
                        product = ''
                    try:
                        servicefp = port.findall('service')[0].attrib['servicefp']
                    except (IndexError, KeyError):
                        servicefp = ''
                    try:
                        script_id = port.findall('script')[0].attrib['id']
                    except (IndexError, KeyError):
                        script_id = ''
                    try:
                        script_output = port.findall('script')[0].attrib['output']
                    except (IndexError, KeyError):
                        script_output = ''

                    # Create a list of the port data
                    port_data.extend(port_id)

                    # Add the port data to the host data
                    host_data.append(port_data)

            # If no port information, just create a list of host information
            except IndexError:
                addr_info.extend((ip_address, host_name))
                host_data.append(addr_info)
        return host_data

    def _parse_to_csv(self, data):
        if not os.path.isfile(csv_name):
            csv_file = open(csv_name, 'w', newline='')
            csv_writer = csv.writer(csv_file)
            top_row = [
                'IP', 'Host', 'OS', 'Proto', 'Port',
                'Service', 'Product', 'Service FP',
                'NSE Script ID', 'NSE Script Output', 'Notes'
            ]
            csv_writer.writerow(top_row)
            print('\n[+] The file {} does not exist. New file created!\n'.format(
                csv_name))
        else:
            try:
                csv_file = open(csv_name, 'a', newline='')
            except PermissionError as e:
                print("\n[-] Permission denied to open the file {}. "
                      "Check if the file is open and try again.\n".format(csv_name))
                print("Print data to the terminal:\n")
                if args.debug:
                    print(e)
                for item in data:
                    print(' '.join(item))
                exit()
            csv_writer = csv.writer(csv_file)
            print('\n[+] {} exists. Appending to file!\n'.format(csv_name))
        for item in data:
            csv_writer.writerow(item)
        csv_file.close()

    def list_ip_addresses(self, data):
        """Parses the input data to return only the IP address information"""
        ip_list = [item[0] for item in data]
        sorted_set = sorted(set(ip_list))
        addr_list = [ip for ip in sorted_set]
        return addr_list

    def print_web_ports(self, data):
        """Examines the port information and prints out the IP and port
        info in URL format (https://ipaddr:port/).
        """

        # http and https port numbers came from experience as well as
        # searching for http on th following website:
        # https://en.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers
        http_port_list = ['80', '280', '81', '591', '593', '2080', '2480', '3080',
                          '4080', '4567', '5080', '5104', '5800', '6080',
                          '7001', '7080', '7777', '8000', '8008', '8042', '8080',
                          '8081', '8082', '8088', '8180', '8222', '8280', '8281',
                          '8530', '8887', '9000', '9080', '9090', '16080']
        https_port_list = ['832', '981', '1311', '7002', '7021', '7023', '7025',
                           '7777', '8333', '8531', '8888']
        for item in data:
            ip = item[0]
            port = item[4]
            if port.endswith('43') and port != "143" or port in https_port_list:
                print("https://{}:{}".format(ip, port))
            elif port in http_port_list:
                print("http://{}:{}".format(ip, port))
            else:
                continue

    def least_common_ports(self, data, n):
        """Examines the port index from data and prints the least common ports."""
        c = Counter()
        for item in data:
            try:
                port = item[4]
                c.update([port])
            except IndexError as e:
                if args.debug:
                    print(e)
                continue
        print("{0:8} {1:15}\n".format('PORT', 'OCCURENCES'))
        for p in c.most_common()[:-n - 1:-1]:
            print("{0:5} {1:8}".format(p[0], p[1]))

    def most_common_ports(self, data, n):
        """Examines the port index from data and prints the most common ports."""
        c = Counter()
        for item in data:
            try:
                port = item[4]
                c.update([port])
            except IndexError as e:
                if args.debug:
                    print(e)
                continue
        print("{0:8} {1:15}\n".format('PORT', 'OCCURENCES'))
        for p in c.most_common(n):
            print("{0:5} {1:8}".format(p[0], p[1]))

    def print_filtered_port(self, data, filtered_port):
        """Examines the port index from data and see if it matches the
        filtered_port. If it matches, print the IP address.
        """
        for item in data:
            try:
                port = item[4]
            except IndexError as e:
                if args.debug:
                    print(e)
                continue
            if port == filtered_port:
                print(item[0])

    def print_data(self, data):
        """Prints the data to the terminal."""
        for item in data:
            print(' '.join(item))

    def ParseFile(self):
        data = self._parse_xml()

        """Main function of the script."""
        for filename in args.filename:

            if not data:
                print("[*] Zero hosts identitified as 'Up' or with 'open' ports. "
                      "Use the -u option to display ports that are 'open|filtered'. "
                      "Exiting.")
                exit()
            if args.csv:
                parse_to_csv(data)
            if args.ip_addresses:
                addrs = list_ip_addresses(data)
                for addr in addrs:
                    print(addr)
            if args.print_all:
                print_data(data)
            if args.filter_by_port:
                print_filtered_port(data, args.filter_by_port)
            if args.print_web_ports:
                print_web_ports(data)
            if args.least_common_ports:
                print("\n{} LEAST COMMON PORTS".format(filename.upper()))
                least_common_ports(data, args.least_common_ports)
            if args.most_common_ports:
                print("\n{} MOST COMMON PORTS".format(filename.upper()))
                most_common_ports(data, args.most_common_ports)
