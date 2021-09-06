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

from View.console import Console
from DesignPattern.Subject import Subject
from DesignPattern.Observer import Observer
from Utils.ConfigurationParser import ConfigurationParser
from Model.ScannerNmap import ScannerNmap
from Model.MetasploitModel import MetasploitModel
from Utils.Level import Level


class Controller(Subject):

    def __init__(self):
        self._ui = Console()
        self.client, self.scanner = self.GetClients()

    def update(self, level, message):
        if level == Level.info:
            self._ui.ShowInfos(f"[INFOS] {message}")
        elif level == Level.success:
            self._ui.ShowSuccess(f"[SUCCESS] {message}")
        elif level == Level.warning:
            self._ui.ShowWarning(f"[WARNING] {message}")
        elif level == Level.error:
            self._ui.ShowError(f"[ERROR] {message}")

    def GetClients(self):
        config = ConfigurationParser("data/configuration.ini")
        username, password, ip, port = config.GetConfigurationMetasploit()
        speed, sudo_password = config.GetConfigurationScanner()

        client = MetasploitModel(username,password, port, self)
        scanner = ScannerNmap(speed, sudo_password, client, self)

        return client, scanner

    def GetPort(self):
        ports = self.scanner.port_discovery("127.0.0.1")
        toto = ""

