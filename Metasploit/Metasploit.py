from pymetasploit3.msfrpc import MsfRpcClient


class Metasploit:
    def __init__(self, password, user):
        self._client = MsfRpcClient(password=password, port=55556)
        self._client.login(user=user, password=password)
        if self._client.authenticated:
            print("[SUCESS] Authentification MSFRPC SUCESS")
        else:
            print("[ERROR] Authentification ERROR !")
        res = self._client.call('console.create')
        self._console_id = res['id']

    def send_cmd(self, cmd):
        if self._client.authenticated:
            self._client.call('console.write', [self._console_id, cmd])
        else:
            print("Client Was Not Authentificated !")
