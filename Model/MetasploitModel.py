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
from pymetasploit3.msfrpc import MsfRpcClient
from Utils.ProcessManager import ProcessManager
from Utils.Level import Level
import os


class MetasploitModel:

    def __init__(self, main_observer):
        # Observer Pattern
        self._time = None
        self._observer = Observer()
        self._observer.register(main_observer)

        # Metasploit component
        self.client_Isbusy = False

    def send_cmd(self, cmd):
        # self._show_message(Level.info, f"[*] {cmd}")
        return os.system(cmd)

    def _show_message(self, level, message):
        self._observer.update_observer(level, message)

