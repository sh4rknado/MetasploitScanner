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

    def __init__(self, config_path):
        self.config = configparser.ConfigParser()
        self.config.read(config_path)

    @staticmethod
    def get_metasploit_client(main_observer):
        return MetasploitModel(main_observer)

    def _get_configuration_metasploit_service(self):
        ip = self.config['MetasploitService']['IP']
        port = self.config['MetasploitService']['PORT']
        username = self.config['MetasploitService']['USERNAME']
        password = self.config['MetasploitService']['PASSWORD']
        return username, password, ip, port

    def _get_configuration_metasploit_database(self):
        username = self.config['MetasploitDatabase']['USERNAME']
        password = self.config['MetasploitDatabase']['PASSWORD']
        database = self.config['MetasploitDatabase']['DATABASE']
        ip = self.config['MetasploitDatabase']['IP']
        port = self.config['MetasploitDatabase']['PORT']
        return username, password, database, ip, port

    def GetConfigurationOpenVas(self):
        ip = self.config['OpenVas']['IP']
        port = self.config['OpenVas']['PORT']
        username = self.config['OpenVas']['USERNAME']
        password = self.config['OpenVas']['PASSWORD']

    def GetConfigurationScanner(self):
        speed = self.config['Scanner']['Speed']
        sudo_password = self.config['Scanner']['sudo_pass']
        return speed, sudo_password
