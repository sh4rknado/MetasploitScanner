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

import configparser
from Model.MetasploitModel import MetasploitModel
from Model.ScannerNmap import ScannerNmap


class ConfigurationParser:

    def __init__(self, configPath):
        self.config = configparser.ConfigParser()
        self.config.read(configPath)

    def GetConfigurationMetasploit(self):
        ip = self.config['Metasploit']['IP']
        port = self.config['Metasploit']['PORT']
        username = self.config['Metasploit']['USERNAME']
        password = self.config['Metasploit']['PASSWORD']
        return username, password, ip, port

    def GetConfigurationOpenVas(self):
        ip = self.config['OpenVas']['IP']
        port = self.config['OpenVas']['PORT']
        username = self.config['OpenVas']['USERNAME']
        password = self.config['OpenVas']['PASSWORD']

    def GetConfigurationScanner(self):
        speed = self.config['Scanner']['Speed']
        sudo_password = self.config['Scanner']['sudo_pass']
        return speed, sudo_password
