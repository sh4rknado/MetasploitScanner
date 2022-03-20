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

import pandas as pd


class Device:

    def __init__(self):
        self.ip = ""
        self.hostname = ""
        self.os = ""
        self.service = pd.DataFrame()

    def set_services(self, d):
        self.service = pd.DataFrame(d)

