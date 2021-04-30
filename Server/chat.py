import socket, pickle
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import serialization
class chat_server:

    def __init__(self, database, verb=False, debug=False, port=10002):
        self.verbose=verb
        self.debug_v=debug
        self.port=port
        self.database=database
        #{client_id:public_key_pem}
        self.registered_clients={}

    def log(self, out_string):
        if self.verbose:
            print("[Chat server]",out_string)

    def debug(self, out_string):
        if self.debug_v:
            print("[Chat server][debug]",out_string)

    def decrypt(self, key, obj):
        """
        decryption using furnet, which uses AES encryption
        """
        decryption_function=Fernet(key)
        decrypted=pickle.loads(decryption_function.decrypt(obj))
        return decrypted

    def encrypt(self, key, obj):
        """
        encrption using furnet, which uses AES encryption
        """
        encryption_function=Fernet(key)
        encrypted=encryption_function.encrypt(pickle.dumps(obj))
        return encrypted

    def auth_request_handler(self, client_id, public_key):
            """
            if this function is called then the key and ticket has
            been verified, add this client to the set of
            registered client and send ack.
            """
            self.conn.send("Authenticated".encode())
            self.log(str(client_id)+" authenticated!")
            
            self.debug("cllient "+ str(client_id) + "public key : " + str(public_key))
            #add to the list of registered clients
            self.registered_clients[client_id]=public_key
    
    def who_request_handler(self, client_id, k_temp):
        """
        Force client to call /auth first so that they could
        be added to the set of registered clients.
        Send the list of all registered clients encrypted by k_temp.
        """
        self.debug("Handling who reqeust from "+str(client_id))
        if client_id not in self.registered_clients:
            self.conn.send("Please authenticate first".encode())
        else:
            send_packet=self.encrypt(k_temp,tuple(self.registered_clients))
            self.debug(str(send_packet))
            self.debug(self.decrypt(k_temp,send_packet))
            self.debug("k_temp "+str(k_temp))
            self.conn.send(send_packet)
            


    def request_handler(self, request):
        """
        The format of any request will be (client_id, E(K_temp,(request_type, ...arguements..., ticket)))

        eg. 

        Authentication request: (ID, E(K_temp,("/auth",ticket)))
        """
        request_decoded=pickle.loads(request)
        client_id=int(request_decoded[0])
        self.log("got request from client: " + str(client_id))
        client_K_temp=self.database.get_session_key(client_id)
        self.debug("client k_temp: " + str(client_K_temp))
        client_ticket=self.database.get_ticket(client_id)
        arguements_decrypted=self.decrypt(client_K_temp, request_decoded[1])
        req_type=arguements_decrypted[0]
        self.debug("rec arguement:" + str(arguements_decrypted) )
        ticket_received=arguements_decrypted[-1]
        self.debug("Received ticket: " + str(ticket_received))
        self.debug("Stored ticket:   " + str(client_ticket))
        if ticket_received!=client_ticket:
            self.conn.send("Not Authenticated".encode())
            self.log("Client " + str(client_id) + " cannot be authenticated")
            return None
        self.log(req_type)
        if req_type=="/auth":
            pub_key=arguements_decrypted[1]
            self.auth_request_handler(client_id,pub_key)
        elif req_type=="/who":
            self.who_request_handler(client_id, client_K_temp)
        elif req_type=="/write-all":
            pass
        elif req_type=="/create_group":
            pass
        elif req_type=="/group_invite":
            pass
        elif req_type=="/group_invite_accept":
            pass
        elif req_type=="/request_public_key":
            pass
        elif req_type=="/send_public_key":
            pass
        elif req_type=="/init_group_dhxchg":
            pass
        
        

    def run(self):
        self.log("running")

        self.s = socket.socket()
        self.s.bind(('',self.port))

        
        self.s.listen(10)
        self.log("Listening on port "+str(self.port))

        while True:
            self.conn,self.addr = self.s.accept()
            client_request=self.conn.recv(4096)
            self.request_handler(client_request)

            self.conn.close()
