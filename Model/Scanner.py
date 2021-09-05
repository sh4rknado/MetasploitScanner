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

from DesignPattern.Observer import Observer
import socket


class Scanner:

    def __init__(self, client, main_observer):
        self.client = client
        # Observer Pattern
        self.observer = Observer()
        self.observer.register(main_observer)

    # Check if IP is Valid
    def validate_ip(self, ip):
        try:
            socket.inet_aton(ip)
            check = True
        except socket.error:
            check = False
        return check

    def logout(self):
        self.client.logout()

    def ShowMessage(self, level, message):
        self.observer.update_observer(level, message)

