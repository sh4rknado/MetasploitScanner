from pymetasploit3.msfrpc import MsfRpcClient
from pymetasploit3.msfconsole import MsfRpcConsole
import time


class Metasploit:

    def __init__(self, password, user):
        print("[INFOS] Authentification to Metasploit (msfrpcd) ...")
        self._client = MsfRpcClient(password=password, port=55556)
        self._client.login(user=user, password=password)

        if self._client.authenticated:
            print("[SUCESS] Authentification MSFRPC SUCESS")
        else:
            print("[ERROR] Authentification ERROR !")

        self._console = MsfRpcConsole(self._client, cb="read_console")
        self._console_busy = False
        self._console_read = list()

    def read_console(self, console_data):
        self._console_busy = console_data['busy']
        print("Console State : " + str(self._console_busy))

        if '[+]' in console_data['data']:
            sigdata = console_data['data'].rstrip().split('\n')

            for line in sigdata:
                if '[+]' in line:
                    self._console_read.append(line)

        print(console_data['data'])

    def send_cmd(self, cmd):
        if self._client.authenticated and not self._console_busy:
            self._console.execute(cmd)
            time.sleep(5)
        elif self._console_busy:
            print("Client was busy !")
        else:
            print("Client Was Not Authentificated !")

