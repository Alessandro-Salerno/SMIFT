import socket
import threading
from datetime import datetime
from collections import defaultdict


NEW_LINE = "\r\n"

class SMIFTMessage:
    def __init__(self, mtype):
        self.attributes = {}
        now = datetime.strftime(datetime.now(), "%Y-%m-%d %H:%M:%S")
        self.add_attr("Timestamp", now)
        self.type = mtype

    @staticmethod
    def from_existing(sm):
        m = SMIFTMessage(sm.mtype)
        m.attributes = sm.attributes.copy()
        return m

    @staticmethod
    def from_message(msg):
        lines = msg.split(NEW_LINE)
        header = lines[0]

        header_parts = header.split(" ")
        smift_version = header_parts[0]

        if smift_version != "SMIFT/0.1":
            return

        message_type = header_parts[1]

        header_tail = ""
        for part in header_parts[2:]:
            header_tail += part + " "
        header_tail = header_tail.strip()

        ret = None

        match (message_type):
            case "REQUEST":
                ret = SMIFTRequest()
                ret.set_command(header_tail)

            case "FORWARD":
                ret = SMIFTForward()
                ret.set_command(header_tail)

            case "RESPONSE":
                ret = SMIFTResponse()
                ret.set_message(header_tail)
                ret.set_code(header_tail.split(" ")[0])

            case _:
                print(message_type)

        for line in lines[2:]:
            parts = line.split(": ")
            if len(parts) < 2:
                continue
            key = parts[0]
            value = parts[1]
            ret.add_attr(key, value)
        
        return ret

    def add_attr(self, key, value):
        self.attributes.__setitem__(key, value)

    def rm_attr(self, key):
        self.attributes.pop(key)

    def get_attr(self, key):
        return self.attributes[key]

    def build_header(self):
        return ""

    def build(self):
        header = self.build_header()
        header += NEW_LINE
        header += NEW_LINE

        for key, value in self.attributes.items():
            header += f"{key}: {value}{NEW_LINE}"

        return header


class SMIFTRequest(SMIFTMessage):
    def __init__(self):
        super().__init__("REQUEST")
        self.command = "ECHO"

    def set_command(self, cmd):
        self.command = cmd

    def build_header(self):
        return f"SMIFT/0.1 REQUEST {self.command}"

class SMIFTResponse(SMIFTMessage):
    def __init__(self):
        super().__init__("RESPONSE")
        self.code = "000"
        self.message = "000 No message"

    def set_code(self, code):
        self.code = code

    def set_message(self, msg):
        self.message = msg

    def build_header(self):
        return f"SMIFT/0.1 RESPONSE {self.message}"


class SMIFTForward(SMIFTRequest):
    def __init__(self):
        super().__init__()

    @staticmethod
    def from_request(req):
        m = SMIFTForward()
        m.command = req.command
        m.attributes = req.attributes.copy()
        return m

    def build_header(self):
        return f"SMIFT/0.1 FORWARD {self.command}"


def recv(s: socket.socket):
    out = ""
    c = 1
    while c != "\0".encode("utf-8"):
        c = s.recv(1)
        out += c.decode('utf-8')

    return out

def send(s: socket.socket, msg):
    s.send((msg + "\0").encode("utf-8"))


server = input("SMIFT Routing Server address: ")
username = input("SMIFT Server Identifier: ")

conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
conn.connect((server, 5500))

login = SMIFTRequest()
login.set_command("AUTHENTICATE")
login.add_attr("Server-Identifier", username)

send(conn, login.build())


server_accounts = defaultdict(lambda: 0)

user_accounts = {
    "0011": 1000,
    "0022": 2000,
    "0033": 3000
}


def receive_thread():
    while True:
        msg = recv(conn)
        msgl = msg.split(NEW_LINE)
        print(msgl[0])

        pkt = SMIFTMessage.from_message(msg)

        if isinstance(pkt, SMIFTForward):
            match (pkt.command):
                case "TRANSFER":
                    dst = pkt.get_attr("Destination-Server")
                    sender = pkt.get_attr("Sender-Server")
                    qty = int(pkt.get_attr("Amount"))

                    if qty > server_accounts.setdefault(sender, 5000):
                        res = SMIFTResponse()
                        res.add_attr("Transaction-ID", pkt.get_attr("Transaction-ID"))
                        res.set_code("301")
                        res.set_message("301 Access denied")

                        send(conn, res.build())
                        continue

                    server_accounts[sender] -= qty

                    res = SMIFTResponse()
                    res.add_attr("Transaction-ID", pkt.get_attr("Transaction-ID"))
                    res.set_code("111")
                    res.set_message("111 Transfer authorised")

                    send(conn, res.build())

                    # time.sleep(2000) # simulates 24 hours
                    server_accounts[dst] += qty

                    res = SMIFTResponse()
                    res.add_attr("Transaction-ID", pkt.get_attr("Transaction-ID"))
                    res.set_code("112")
                    res.set_message("112 Transfer settled")

                    send(conn, res.build())
                
                case "CREDIT":
                    currency = pkt.get_attr("Currency")
                    # we ignore currency
                    # but you shouldn t ahahah
                    # this is just an example

                    dst_acc = pkt.get_attr("Destination-Account")
                    user_accounts[dst_acc] += int(pkt.get_attr("Amount"))

                    res = SMIFTResponse()
                    res.add_attr("Transaction-ID", pkt.get_attr("Transaction-ID"))
                    res.set_code("112")
                    res.set_message("210 Transfer credited")

                    send(conn, res.build())



def send_thread():
     while True:
         cmd = input()
         cms = cmd.split(" ")

         if cms[0] == "TRANSFER":
             amount = cms[1]
             currency = cms[2]
             dst = cms[3]
             acc = cms[4]

             req = SMIFTRequest()
             req.set_command("TRANSFER")
             req.add_attr("Amount", amount)
             req.add_attr("Currency", currency)
             req.add_attr("Destination-Server", dst)
             req.add_attr("Destination-Account", acc)
             req.add_attr("Note", "RANDOM TRANSFER")

             send(conn, req.build())


t1 = threading.Thread(target=receive_thread)
t1.start()

t2 = threading.Thread(target=send_thread)
t2.start()

