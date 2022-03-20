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
import pickle
import os


class Scanner:

    def __init__(self, client, main_observer):
        self.client = client
        # Observer Pattern
        self.observer = Observer()
        self.observer.register(main_observer)
        self._output_dir = os.getcwd() + "/data/output"
        self._scripts = os.getcwd() + "/data/scripts"

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

    def _save_pickle(self, file, dump):
        filehandler = open(file, "wb")
        pickle.dump(dump, filehandler)
        filehandler.close()
        filehandler.flush()

    def _load_pickle(self, file):
        loaded = None
        if os.path.isfile(file):
            filehandler = open(file, "r")
            loaded = pickle.load(filehandler)
            filehandler.flush()
            filehandler.close()
        return loaded

    def _resume_scan(self, ip):
        devices = self._load_pickle(f"{self._output_dir}/{ip}/{ip}.pickle")
        scanned = self._load_pickle(f"{self._output_dir}/{ip}/{ip}_scanner.pickle")
        if scanned is None:
            scanned = []
        return devices, scanned

    def _save_scan(self, ip, devices, scanned):
        self._save_pickle(f"{self._output_dir}/{ip}/{ip}.pickle", devices)
        self._save_pickle(f"{self._output_dir}/{ip}/{ip}_scanner.pickle", scanned)

    def _check_directory(self, ip):
        out_dir = f"{self._output_dir}/{ip}"
        if not os.path.exists(out_dir):
            os.makedirs(out_dir)
        return out_dir
