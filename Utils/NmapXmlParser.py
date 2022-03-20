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
from Model.Device import Device
from collections import Counter
import traceback


class NmapXmlParser:

    def __init__(self, file):
        self.fileToParse = file

    def _parse_xml(self):
        try:
            tree = etree.parse(self.fileToParse)
            root = tree.getroot()
            return self._get_available_hosts(root)
        except Exception as error:
            traceback.print_exc()
            print("[-] A an error occurred. when parse the report "
                  "Please review the error and try again: {}".format(error))
            exit()

    def _get_os_discover(self, root_host):
        try:
            os_element = root_host.findall('os')
            os_name = os_element[0].findall('osmatch')[0].attrib['name']
        except IndexError:
            os_name = "unknow"
        return os_name

    def _set_ports_service(self, root_host, device):
        port_element = root_host.findall('ports')
        root_ports = port_element[0].findall('port')
        protocols = []
        ports = []
        services_name = []
        services_product = []

        for port in root_ports:

            #     # Display both open ports and open}filtered ports
            #     if not 'open' in port.findall('state')[0].attrib['state']:
            #         continue

            # only if port is open
            if not port.findall('state')[0].attrib['state'] == 'open':
                continue

            protocols.append(port.attrib['protocol'])
            ports.append(port.attrib['portid'])
            services_name.append(port.findall('service')[0].attrib['name'])

            try:
                services_product.append(port.findall('service')[0].attrib['product'])
            except (IndexError, KeyError):
                services_product.append('unknow')

        device.set_services({
            'Protocol': protocols,
            'Port': ports,
            'ServiceName': services_name,
            'Product': services_product
        })

    def _set_ip_hostname(self, host, device):
        # Get IP a ddress and host info. If no hostname, then ''
        device.ip = host.findall('address')[0].attrib['addr']
        host_name_element = host.findall('hostnames')
        try:
            device.hostname = host_name_element[0].findall('hostname')[0].attrib['name']
        except IndexError:
            device.hostname = ''

    def _get_available_hosts(self, root):
        devices = []

        for host in root.findall('host'):
            # Ignore hosts that are not 'up'
            if host.findall('status')[0].attrib['state'] == 'up':
                device = Device()

                # set the hostname and ip address
                self._set_ip_hostname(host, device)

                # set the port and service with version
                self._set_ports_service(host, device)

                # get the OS Detection
                device.os = self._get_os_discover(host)

                devices.append(device)

        return devices

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
        return data

