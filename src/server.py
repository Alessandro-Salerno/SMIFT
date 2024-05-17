import socket
import threading
import hashlib
from datetime import datetime


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


class Transaction:
    def __init__(self):
        self.request: SMIFTRequest = None
        self.sender = None
        self.req_hash = None
        self.status = None

# Server globals

transactions = {}
transaction_id = 1
transaction_lock = threading.Lock()

connected_nodes = {}

client_names = {}

mail_box = {}


routing_table = {
    "XUD": "UMSR",
    "XCL": "CCC"
}

def next_transaction():
    with transaction_lock:
        global transaction_id
        i = transaction_id
        transaction_id += 1
        return i

def try_send(dst, msg):
    if dst in connected_nodes:
        send(connected_nodes[dst], msg.build())
        return

    mail_box.setdefault(dst, []).append(msg)


def handle_request(node: socket.socket, req: SMIFTResponse, sha):
    match (req.command):
        case "AUTHENTICATE":
            connected_nodes.__setitem__(req.get_attr("Server-Identifier"), node)
            client_names[node] = req.get_attr("Server-Identifier")
            for msg in mail_box.setdefault(req.get_attr("Server-Identifier"), []):
                send(node, msg.build())
            mail_box.__setitem__(req.get_attr("Server-Identifier"), [])

            res = SMIFTResponse()
            res.set_code("200")
            res.set_message("200 Authenticated")
            send(node, res.build())

        case "TRANSFER":
            dst = routing_table[req.get_attr("Currency")]
            tid = next_transaction()

            frw = SMIFTForward.from_request(req)
            frw.rm_attr("Note")
            frw.add_attr("Sender-Server", client_names[node])
            frw.add_attr("Transaction-ID", tid)
            
            res = SMIFTResponse()
            res.set_code("110")
            res.set_message("110 Transfer routed")
            res.add_attr("Request-Hash", sha)
            res.add_attr("Transaction-ID", tid)

            trans = Transaction()
            trans.request = req
            trans.status = res.code
            trans.req_hash = sha
            trans.sender = client_names[node]

            transactions.__setitem__(tid, trans)

            send(node, res.build())
            try_send(dst, frw)

        case "CANCEL TRANSFER":
            pass

def handle_response(node: socket.socket, res: SMIFTResponse, sha):
    match (res.code):
        case "112":
            tid = int(res.get_attr("Transaction-ID"))
            transaction: Transaction = transactions[tid]

            credit = SMIFTForward.from_request(transaction.request)
            credit.set_command("CREDIT")
            credit.rm_attr("Destination-Server")
            credit.add_attr("Transaction-ID", str(tid))

            try_send(transaction.sender, res)
            try_send(transaction.request.get_attr("Destination-Server"), credit)

        case _:
            tid = int(res.get_attr("Transaction-ID"))
            transaction = transactions[tid]
            transaction.status = res.code

            try_send(transaction.sender, res)


def handle(node: socket.socket):
    while True:
        msg = recv(node)
        sm = SMIFTMessage.from_message(msg)

        sha = hashlib.sha256(msg.encode("utf-8"))
        
        if isinstance(sm, SMIFTRequest):
            handle_request(node, sm, sha)

        if isinstance(sm, SMIFTResponse):
            handle_response(node, sm, sha)



with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind(("127.0.0.1", 5500))
    s.listen()

    while True:
        node, addr = s.accept()
        
        t = threading.Thread(target=handle, args=(node,))
        t.start()

