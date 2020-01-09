from pymetasploit3.msfrpc import MsfRpcClient
from pymetasploit3.msfconsole import MsfRpcConsole
import time


class Metasploit:

    def __init__(self, password, user):
        print("[INFOS] Authentification to Metasploit (msfrpcd) ...")
        self._client = MsfRpcClient(password=password, port=55556)
        self._client.login(user=user, password=password)

        if self._client.authenticated:
            print("[SUCESS] Authentification MSFRPC SUCESS\n")
        else:
            print("[ERROR] Authentification ERROR !")
        self.console = MsfRpcConsole(self._client, cb=self.read_console)

        self.client_Isbusy = False

    def read_console(self, console_data):
        console_read = list()

        self.client_Isbusy = console_data['busy']
        # print("Console State : " + str(self._console_busy))

        if '[+]' in console_data['data']:
            sigdata = console_data['data'].rstrip().split('\n')

            for line in sigdata:
                if '[+]' in line:
                    console_read.append(line)
                if 'Nmap done' in line:
                    print("[INFOS] SCAN FINISHED !")
                    self.client_Isbusy = False

        print(console_data['data'])

    def send_cmd(self, cmd):

        if self._client.authenticated and not self.client_Isbusy:
            self.console.execute(cmd)
            time.sleep(1)
        elif self.client_Isbusy:
            print("[WAITING] Client was busy !")
            while self.client_Isbusy:
                print("[WAITING] Client was busy !")
                time.sleep(10)
            print("[INFOS] Client Available now !")
            self.console.execute(cmd)
            time.sleep(1)
        else:
            print("[ERROR] Client Was Not Authentificated !")

    def logout(self):
        print("[INFOS] Logout msfrpc client\n")
        self._client.logout()
