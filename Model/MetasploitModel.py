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
from pymetasploit3.msfconsole import MsfRpcConsole
from Utils.ProcessManager import ProcessManager
from Utils.Level import Level
import os
import time


class MetasploitModel:

    def __init__(self, user, password, port, db_user, db_name, db_ip, db_port, main_observer):
        # Observer Pattern
        self._time = None
        self._observer = Observer()
        self._observer.register(main_observer)

        if not ProcessManager.service_is_running("metasploit.service"):
            self.ShowMessage(Level.info, f"Start metasploit service msfrpcd for {user}:{password}@127.0.0.1:{port} ...")
            os.system(f"systemctl start metasploit.service")

        self.ShowMessage(Level.info, f"Metasploit Authentication on {user}:{password}@127.0.0.1:{port}...")
        self._client = MsfRpcClient(password, port=port, username=user, ssl=True)
        self._client.login(user=user, password=password)
        
        if self._client.authenticated:
            self.ShowMessage(Level.success, "Authentication completed")
        else:
            self.ShowMessage(Level.error, "Authentication failed !")

        self.console = MsfRpcConsole(self._client, cb=self.read_console)

        print(self._client.db.connect(username=db_user, database=db_name, host=db_ip, port=db_port))
        print(self._client.db.status)
        self.client_Isbusy = False

    def read_console(self, console_data):
        console_read = list()

        self.client_Isbusy = console_data['busy']

        if '[+]' in console_data['data']:
            sigdata = console_data['data'].rstrip().split('\n')

            for line in sigdata:
                if '[+]' in line:
                    console_read.append(line)

        if 'Nmap done' in console_data['data']:
            self.ShowMessage(Level.info, "scan completed !")
            self.client_Isbusy = False

        print(console_data['data'])

    def wait_client(self):
        while self.client_Isbusy:
            time.sleep(5)
            if (self._time - time.time()) > 220:
                self.client_Isbusy = False
                self.ShowMessage(Level.error, "Metasploit client Timeout...")
                continue

    def send_cmd(self, cmd):
        self._time = time.time()

        if self._client.authenticated and not self.client_Isbusy:
            self.console.execute(cmd)
            time.sleep(1)
        elif self.client_Isbusy:
            self.wait_client()
            self.console.execute(cmd)
            time.sleep(1)
        else:
            self._observer.update_observer(Level.error, "Metasploit client was not authenticated !")

    def logout(self):
        self.ShowMessage(Level.info, "Metasploit client was not authenticated !")
        self._client.logout()

    def ShowMessage(self, level, message):
        self._observer.update_observer(level, message)

