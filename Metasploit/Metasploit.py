from pymetasploit3.msfrpc import MsfRpcClient


class Metasploit:
    def __init__(self, password, user):
        self._client = MsfRpcClient(password, port=55553)
        self._client.login(user, password)
        res = self._client.call('console.create')
        self._console_id = res['id']

    def send_cmd(self, cmd):
        if self._client.authenticated:
            self._client.call('console.write', [self._console_id, cmd])
        else:
            print("Client Was Not Authentificated !")
