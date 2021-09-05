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


from DesignPattern.UI import UI
from Utils.Colors import Colors


class Console(UI):

    def __init__(self):
        UI.__init__(self)

    def ShowInfos(self, message):
        Colors.print_infos(message)

    def ShowError(self, message):
        Colors.print_error(message)

    def ShowWarning(self, message):
        Colors.print_sucess(message)

    def ShowSuccess(self, message):
        Colors.print_warning(message)
