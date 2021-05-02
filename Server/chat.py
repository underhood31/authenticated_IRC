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
        self.groups={}
        self.group_names={}

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
            
    def write_all_request_handler(self, write_to, message):
        """
        1) get the listen port of the client
        2) send the packet to the client
        packet would be sent in the following format:
        ("/write_all", E(pub_key, (from_id,message)))
        """
        details=self.database.client_listen_details[int(write_to)]
        port=details[1]
        ip=details[0]
        s_client = socket.socket()
        s_client.connect((ip,int(port)))
        packet=("/write_all", message)
        s_client.send(pickle.dumps(packet))
        s_client.close()

    def request_public_key_handler(self, session_key,required_id):
        """
        send the public qey of the required client. The format
        of the response is:
        E(session_key,("/send_public_key",public_key_pem))
        """
        if required_id in self.registered_clients:
            key=self.encrypt(session_key,("/send_public_key",self.registered_clients[required_id]))
            self.conn.send(key)
        else:
            self.conn.send("Requested client not registered".encode())


    def create_group_request_handler(self, session_key,creator_id, name):
        """
        A list containing the id of the group creator
        is created in the self.groups dictionary
        with the id = max(id) + 1
        return packet is in the format:
        E(session_key,(id,"name of the group"))
        """
        id=None
        if(len(self.groups.keys())==0):
            id=0
        else:
            id=max(self.groups.keys())+1
        self.groups[id]=[creator_id]
        self.group_names[id]=name
        packet=self.encrypt(session_key,(id,name))
        self.conn.send(packet)
    
    def group_invite_request_handler(self, from_client, k_temp_from , to_client, group_id):
        """
        Send a request to to_client and listen for
        response, and pass the response to 
        from client.

        If the to_client accept the invite, add it to the 
        self.groups[group_id] list

        Packet format to to_client: 
            ("/group_invite",E(session_key_to, (from_client, group_id)))
        Response format from to_client:
            E(session_key_to,"/group_invite_accept")
            OR
            E(session_key_to, "Not accepted")
        
        Response to from_client
             E(session_key_from, ("/group_invite_accept",grp_id, accepted_client_id)) 
             OR
             E(session_key_from, "Not accepted" ) 
        """
        from_client=int(from_client)
        to_client=int(to_client)
        group_id=int(group_id)

        k_temp_to=self.database.get_session_key(to_client)
        packet_to = (from_client, group_id)
        packet_to_enc=self.encrypt(k_temp_to, packet_to)
        packet_to=pickle.dumps(("/group_invite",packet_to_enc))
        
        details=self.database.client_listen_details[int(to_client)]
        port=details[1]
        ip=details[0]
        s_client = socket.socket()
        s_client.connect((ip,int(port)))
        s_client.send(packet_to)
        response=s_client.recv(4096)

        s_client.close()
        response_dec=self.decrypt(k_temp_to,response)
        if response_dec=="/group_invite_accept":
            self.groups[int(group_id)].append(int(to_client))
            self.log("Client "+str(to_client)+" added to group "+str(group_id))
            packet_from=("/group_invite_accept",group_id, to_client)
            packet_from_enc=self.encrypt(k_temp_from,packet_from)
            self.conn.send(packet_from_enc)
        else:
            packet_from="Not accepted"
            packet_from_enc=self.encrypt(k_temp_from,packet_from)
            self.conn.send(packet_from_enc)
    
    def df_xchg_handler(self, from_client, k_temp_from, to_client, group_id, request):
        """
        1) Get the request from from_client and send to to_client in the following format
            (
                "/init_group_dhxchg",
                E(
                    k_temp_to,
                    (
                        request,
                        from_client,
                        group_id
                    )
                )
            )
        2) Listen for reply from from_client and send it to to_client in the 
        following format
            E(
                k_temp_from,
                reply,
            )
        """
        k_temp_to=self.database.get_session_key(to_client)
        inner_packet=(request, from_client, group_id)
        inner_packet_enc=self.encrypt(k_temp_to,inner_packet)
        outer_packet=("/init_group_dhxchg",inner_packet_enc)
        details=self.database.client_listen_details[int(to_client)]
        port=details[1]
        ip=details[0]
        s_client = socket.socket()
        s_client.connect((ip,int(port)))
        s_client.send(pickle.dumps(outer_packet))
        
        response=s_client.recv(4096)
        response_dec=self.decrypt(k_temp_to,response)
        s_client.close()

        response_enc_to=self.encrypt(k_temp_from,response_dec)
        self.conn.send(response_enc_to)

    def df_update_key(self, from_client, to_client, request, group_id):
        """
        1) Get the request from from_client and send to to_client in the following format
            (
                "/update_df_key",
                E(
                    k_temp_to,
                    (
                        request,
                        from_client,
                        group_id
                    )
                )
            )
        """
        to_client=int(to_client)
        from_client=int(from_client)
        group_id=int(group_id)
        k_temp_to=self.database.get_session_key(to_client)
        inner_packet=(request, from_client,group_id)
        inner_packet_enc=self.encrypt(k_temp_to,inner_packet)
        outer_packet=("/update_df_key", inner_packet_enc)
        details=self.database.client_listen_details[int(to_client)]
        port=details[1]
        ip=details[0]
        s_client = socket.socket()
        s_client.connect((ip,int(port)))
        s_client.send(pickle.dumps(outer_packet))
        
       
        s_client.close()

    def request_handler(self, request):
        """
        The format of any request will be (client_id, E(K_temp,(request_type, ...arguements..., ticket)))

        eg. 

        Authentication request: (ID, E(K_temp,("/auth",ticket)))
        """
        self.debug("Client request bin: " + str(request))
        request_decoded=pickle.loads(request)
        client_id=int(request_decoded[0])
        self.log("got request from client: " + str(client_id))
        client_K_temp=self.database.get_session_key(client_id)
        self.debug("client k_temp: " + str(client_K_temp))
        client_ticket=self.database.get_ticket(client_id)
        self.debug("decoded request" + str(request_decoded))
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
        elif req_type=="/write_all":
            self.write_all_request_handler(arguements_decrypted[1],arguements_decrypted[2])
        elif req_type=="/create_group":
            self.create_group_request_handler(client_K_temp,client_id,arguements_decrypted[1])
        elif req_type=="/group_invite":
            self.group_invite_request_handler(client_id,client_K_temp,arguements_decrypted[2],arguements_decrypted[1])
        elif req_type=="/request_public_key":
            response_id=int(client_id)
            req_id=int(arguements_decrypted[1])
            self.request_public_key_handler(client_K_temp,req_id)
        elif req_type=="/send_public_key":
            pass
        elif req_type=="/init_group_dhxchg":
            self.df_xchg_handler(client_id,client_K_temp,arguements_decrypted[2],arguements_decrypted[3],arguements_decrypted[1])
        elif req_type=="/update_df_key":
            self.df_update_key(client_id,arguements_decrypted[2],arguements_decrypted[1],arguements_decrypted[3])
        
        

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
