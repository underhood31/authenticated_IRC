import socket,time,pickle
import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet
import base64
import threading
import pyDH

#https://nitratine.net/blog/post/asymmetric-encryption-and-decryption-in-python/#:~:text=Asymmetric%20encryption%20uses%20two%20keys,key%20can%20decrypt%20the%20message.
#https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa/
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization

ID=0
g=2
P=32317006071311007300338913926423828248817941241140239112842009751400741706634354222619689417363569347117901737909704191754605873209195028853758986185622153212175412514901774520270235796078236248884246189477587641105928646099411723245426622522193230540919037680524235519125679715870117001058055877651038861847280257976054903569732561526167081339361799541336476559160368317896729073178384589680639671900977202194168647225871031411336429319536193471636533209717077448227988588565369208645296636077250268955505928362751121174096972998068410554359584866583291642136218231078990999448652468262416972035911852507045361090559


class client:
    def __init__(self,id, kdc_server_port, kdc_server_ip, chat_server_port, chat_server_ip,key,listening_port,debug=False):
        self.id=id
        self.kdc_server_port=kdc_server_port
        self.kdc_server_ip=kdc_server_ip
        self.chat_server_port=chat_server_port
        self.chat_server_ip=chat_server_ip
        self.key=key
        self.delta_time=0.5
        self.debug_v=debug
        self.listening_port=listening_port
        self.accept_response=True
        self.groups={} 
        self.group_keys={}
        self.group_members={}
        #assigning public and private keys
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        
        self.public_key = self.private_key.public_key()
        self.public_key_pem = self.public_key.public_bytes(
                                    encoding=serialization.Encoding.PEM,
                                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                                )
        print(self.public_key_pem)

    def debug(self, out_string):
        if self.debug_v:
            print("[debug]",out_string)

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
    
    def public_key_encryption(self, pub_key, obj):
        """
        performs rsa encryption using OAEP padding with SHA256 hash.
        OAEP: https://en.wikipedia.org/wiki/Optimal_asymmetric_encryption_padding
        """
        try:
            return pub_key.encrypt(pickle.dumps(obj), padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
        except:
            return pickle.dumps(obj)

    
    def private_key_encryption(self, priv_key, obj):
        """
        performs rsa signing using PSS padding with SHA256 hash.
        PSS: https://en.wikipedia.org/wiki/Probabilistic_signature_scheme
        """
        # return priv_key.sign(pickle.dumps(obj), padding.PSS(mgf=padding.MGF1(hashes.SHA256),salt_length=padding.PSS.MAX_LENGTH),hashes.SHA256())
        # return priv_key.encrypt(pickle.dumps(obj), padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
        return pickle.dumps(obj)

    def private_key_decryption(self, priv_key, obj):
        """
        performs rsa encryption using OAEP padding with SHA256 hash.
        OAEP: https://en.wikipedia.org/wiki/Optimal_asymmetric_encryption_padding
        """
        try:
            return pickle.loads(priv_key.decrypt(obj, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),algorithm=hashes.SHA256(),label=None)))
        except:
            return pickle.loads(obj)
    
    def public_key_decryption(self, pub_key, obj):
        """
        performs rsa verification using PSS padding with SHA256 hash.
        PSS: https://en.wikipedia.org/wiki/Probabilistic_signature_scheme
        """
        # pub_key.recover_data_from_signature(sig,padding.PKCS1v15(),algorithm=hashes.SHA256())
        # pub_key.verify(obj,to_verify,padding.PSS(mgf=padding.MGF1(hashes.SHA256()),salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256)
        # return pickle.loads(pub_key.decrypt(obj, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),algorithm=hashes.SHA256(),label=None)))
        return pickle.loads(obj)

    def pem_to_pub_key(self, pem):
        return serialization.load_pem_public_key(pem, backend=default_backend())

    def gen_session_key(self, K_c, TS, nonce):
        """
        Session key is the function of K_c, TS and nonce
        These values are hashed
        """
        derived_password=(str(K_c) + str(TS)).encode()
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256, length=32, salt=nonce, iterations=100000) #used to derive a key from password
        key = base64.urlsafe_b64encode(kdf.derive(derived_password)) #encode as utf-8 encode instead of binary
        return key

    def convert_to_key(self, obj):
        derived_password=pickle.dumps(obj)
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256, length=32, salt=b'0', iterations=100000) #used to derive a key from password
        key = base64.urlsafe_b64encode(kdf.derive(derived_password)) #encode as utf-8 encode instead of binary
        return key

    def hash(self, obj):
        """
        generate hash of the object by
        first pickling it then using SHA256
        from hashes library and convert it to
        urlsafe b64 encoding 
        """
        obj_p=pickle.dumps(obj)
        dig=hashes.Hash(hashes.SHA256())
        dig.update(obj_p)
        h=dig.finalize()
        return base64.urlsafe_b64encode(h)
    
    def authenticate(self):
       

        """
                Client                                                        KDC

            (ID_client, TS1)                ---------------->         
            
                                            <----------------           E(K_c, (E(K_temp, Ticket), Nonce, TS2))
            K_temp=gen_session_key()
            ticket=decrypt(K_temp, Ticket)
        """
        self.s_KDC = socket.socket()
        self.s_KDC.connect((self.kdc_server_ip,self.kdc_server_port))
        request=(self.id,time.time())
        self.s_KDC.send(pickle.dumps(request))

        response=self.s_KDC.recv(4096)
        if(response=="Not Authenticated".encode()):
            print("Unable to authenticate(wrong credentials), exiting...")
            self.disconnect()
            exit()

        ticket_enc, nonce, TS2 = self.decrypt(self.key,response)
        self.debug("My key is"+str(self.key))
        if time.time()-float(TS2)<self.delta_time and time.time()-float(TS2)>=0:
            self.K_temp=self.gen_session_key(self.key,TS2,nonce)
            self.debug("k_temp is"+str(self.K_temp))
            self.ticket=self.decrypt(self.K_temp,ticket_enc)
            self.debug("ticket is"+str(self.ticket))
        else:
            print("Unable to authenticate, exiting...")
            self.disconnect()
            exit()

        print("Authenticated!!")

    
    def connet_to_chat_server(self):
        """
        The client sould have a valid ticket and session_key before contacting the chat server.
        This can be done by calling the authenticate function of this class

        Client                                                    Chat Server
        ~~~~~~                                                    ~~~~~~~~~~~~

        (ID,E(k_temp,(request, pub_key,ticket))) ----------------->          
        #Here request would be /auth

                                        <-----------------         Acknowledgement
                                                                    "Authenticated"
                                                                          or
                                                                  "Not Authenticated"

        """
        self.s_CHAT = socket.socket()
        self.s_CHAT.connect((self.chat_server_ip,self.chat_server_port))
        packet=("/auth", self.public_key_pem,self.ticket)
        print("ticket", self.ticket)
        print("session key", self.K_temp)
        packet_enc=self.encrypt(self.K_temp, packet)
        packet_with_id=(self.id,packet_enc)
        self.s_CHAT.send(pickle.dumps(packet_with_id))
        response=self.s_CHAT.recv(4096)
        if(response=="Not Authenticated".encode()):
            print("Unable to authenticate(chat server), exiting...")
            self.disconnect()
            exit()
        else:
            print("Authentication with chat server complete successfully")
        self.disconnect()

    def who_request(self):
        print("who response: ")
        self.s_CHAT = socket.socket()
        self.s_CHAT.connect((self.chat_server_ip,self.chat_server_port))
        req=self.encrypt(self.K_temp,("/who",self.ticket))
        tosend=pickle.dumps((self.id,req))
        self.s_CHAT.send(tosend)
        response=self.decrypt(self.K_temp,self.s_CHAT.recv(4096))
        print(response)
        self.disconnect()
        return response
    def write_all_request(self, message):
        """
        1) get the list of connected clients
        2) get the public keys of those clients
        3) encrypt the message with public keys 
            and send to all connected

        The sent message would be in the following format:
        (   self.id, 
            E(
                k_temp,
                (
                    "/write_all",
                    send_to_id,
                    E(pub_key,(from,message)),
                    ticket
                )
            )
        )
        """
        client_list=self.who_request()
        for id in client_list:
            print("condition: ",id!=self.id)
            print(id, self.id)
            if(id!=self.id):
                pem=self.get_public_key_request(id)
                self.s_CHAT = socket.socket()
                self.s_CHAT.connect((self.chat_server_ip,self.chat_server_port))
        
                
                pub_key=self.pem_to_pub_key(pem)
                enc_message=self.public_key_encryption(pub_key,(self.id,message))
                inner_packet=("/write_all",id,enc_message,self.ticket)
                inner_enc=self.encrypt(self.K_temp,inner_packet)
                complete_packet=(self.id, inner_enc)
                print(complete_packet)
                packet_pickled=pickle.dumps(complete_packet)
                print(packet_pickled)
                self.s_CHAT.send(packet_pickled)

                self.disconnect()


    def get_public_key_request(self, req_id):
        """
        Request format: (ID, E(k_temp, ("/request_public_key", req_id ,ticket)))
        Response: E(k_temp,("/send_public_key",publickey_pem) )
        return: public key pem
        """
        self.s_CHAT = socket.socket()
        self.s_CHAT.connect((self.chat_server_ip,self.chat_server_port))
        inner=("/request_public_key", req_id, self.ticket)
        inner_enc=self.encrypt(self.K_temp, inner)
        print("inner: ", inner_enc)
        outer=pickle.dumps((self.id,inner_enc))
        self.s_CHAT.send(outer)
        response=self.s_CHAT.recv(4096)
        if(response=="Requested client not registered".encode()):
            print("Error public key for client not found, returned None")
            return None
        response_dec=self.decrypt(self.K_temp, response)
        self.disconnect()
        return response_dec[1]

    def create_group_request(self, name):
        """
        Request format: (ID, E(k_temp, ("/create_group", "name of the group" ,ticket)))
        Response format: E(k_temp, (group_id,"name of the group"))

        The dictionary self.group_members is updated with the the list
        self.group_members[group_id] = [self.id]

        After successful group creation a dpyDH.DiffieHellmanh is
        saved in self.groups as {<grp_id>: private_key}
        this key will be used for df key exchange.

        After DH key exchange the final key is saved in
        self.group_keys dictionary
        """
        self.s_CHAT = socket.socket()
        self.s_CHAT.connect((self.chat_server_ip,self.chat_server_port))
        inner_packet=("/create_group", name,self.ticket)
        inner_packet_enc=self.encrypt(self.K_temp,inner_packet)
        outer_packet=(self.id,inner_packet_enc)
        self.s_CHAT.send(pickle.dumps(outer_packet))
        response=self.s_CHAT.recv(4096)
        response_dec=self.decrypt(self.K_temp,response)
        print("Group with id:",response_dec[0],"and name:",response_dec[1],"is created")
        grp_id=int(response_dec[0])
        self.group_members[grp_id] = [self.id]
        self.groups[grp_id]=pyDH.DiffieHellman()

        self.disconnect()
        
    def group_invite_request(self, grp_id, client_id):
        """
        requst format: (ID, E(k_temp, ("/group_invite", grp_id, client_id, ticket)))
        response: E(k_temp, ("/group_invite_accept",grp_id, accepted_client_id)) 

        if the request is accepted then add the client to 
        self.group_members[grp_id].append(client_id)
        """
        self.s_CHAT = socket.socket()
        self.s_CHAT.connect((self.chat_server_ip,self.chat_server_port))

        inner_packet= ("/group_invite", grp_id, client_id,self.ticket)
        inner_packet_enc=self.encrypt(self.K_temp, inner_packet)
        outer_packet= (self.id, inner_packet_enc)
        self.s_CHAT.send(pickle.dumps(outer_packet))

        response=self.s_CHAT.recv(4096)
        response_dec=self.decrypt(self.K_temp,response)
        if response_dec[0]=="/group_invite_accept":
            print("Client:",response_dec[2],"accepted the invite to the group", response_dec[1])
            self.group_members[int(grp_id)].append(client_id)
        elif response_dec=="Not accepted":
            print("Group invite not accepeted")
        
        self.disconnect()

    def dh_key_xchange_request(self, group_id, to_client):
        """
        Initial key exchange(if group_id not in self.group_keys.keys()):
        1) get DH object from self.groups[grp_id]
        2) get the public key of to_client
        3) derive the public key for DH and send it to to_client via server 
        in the following format
            (
                self.ID, 
                E(
                    k_temp,
                    (
                        "/init_group_dhxchg".
                        E(
                            k_pub_to_client,
                            my_public_key_DH
                        ),
                        to_client,
                        grp_id,
                        ticket
                    )
                )
            )
        4) The to_client will send it's public key via server in the followint format
            E(
                k_temp,
                (
                    E(
                        private_key_to_client,
                        to_client_public_key_DH
                    ),
                    E(
                        my_public_key_DH,
                        sha256(K)
                    )
                )
            )
        5) calculate K and verify HMAC
        6) add key to self.group_keys

        Note: keys DH keys are always saved as integers, only while
        encrypting/decrypting they are converted to keys using 
        self.convert_to_key()

        For second and later diffie hellman
        1) get the group key K from self.group_keys
        2) send K to to_client via server 
        in the following format
            (
                self.ID, 
                E(
                    k_temp,
                    (
                        "/init_group_dhxchg".
                        E(
                            k_pub_to_client,
                            g^K
                        ),
                        to_client,
                        grp_id,
                        ticket
                    )
                )
            )
        3) The to_client will send it's public key via server in the followint format
            E(
                k_temp,
                (
                    E(
                        private_key_to_client,
                        to_client_public_key_DH
                    ),
                    E(
                        g^K,
                        sha256(new_K)
                    )
                )
            )
        4) calculate new K using to_client_public_key_DH^(K)=g^(K*U3) and verify HMAC
        5) Send new key to all the other members in the group in the following format
            (
                self.ID,
                E(
                    k_temp,
                    (
                        "/update_df_key",
                        E(
                            K #old,
                            new_K
                        ),
                        uid,
                        grp_id,
                        ticket
                    )
                )
            )
        6) add key to self.group_keys
        
        """
        
        if group_id not in self.group_keys.keys():
            # 1) get DH object from self.groups[grp_id]
            dh=self.groups[group_id]
            p=dh.p
            # 2) get the public key of to_client
            print("I AM HERE YOU 1")
            pub_key_to_client_pem=self.get_public_key_request(to_client)
            print("PEM", pub_key_to_client_pem)
            pub_key_to_client=self.pem_to_pub_key(pub_key_to_client_pem)
            print("KEY:",pub_key_to_client)
            my_pub_key_DH=dh.gen_public_key()
            print("Idh public:",my_pub_key_DH)
            #3)
            self.s_CHAT = socket.socket()
            self.s_CHAT.connect((self.chat_server_ip,self.chat_server_port))
            to_send=(
                self.id, 
                self.encrypt(
                    self.K_temp,
                    (
                        "/init_group_dhxchg",
                        self.public_key_encryption(
                            pub_key_to_client,
                            (my_pub_key_DH)
                        ),
                        to_client,
                        group_id,
                        self.ticket
                    )
                )
            )
            print("Sending", to_send)
            self.s_CHAT.send(pickle.dumps(to_send))
            #4
            response=self.s_CHAT.recv(4096)
            response=self.decrypt(
                self.K_temp,
                response
            )

            to_client_public_DH=self.public_key_decryption(pub_key_to_client, response[0] )

            DH_key=self.convert_to_key(my_pub_key_DH)
            hashed_K=self.decrypt(DH_key, response[1])

            #5
            # pow(g^c2, c1)
            K=pow(to_client_public_DH,dh.get_private_key(),dh.p)
            my_hashed_K=self.hash(K)
            if my_hashed_K!=hashed_K:
                raise Exception("K hash not equal")
            print("New key:",K)
            self.group_keys[group_id]=K
            self.disconnect()
        else: 
            
            #1
            old_K=self.group_keys[group_id]
            # 2) get the public key of to_client
            pub_key_to_client_pem=self.get_public_key_request(to_client)
            pub_key_to_client=self.pem_to_pub_key(pub_key_to_client_pem)

            global P
            global g
            my_pub_key_DH=pow(g,old_K,P)
            self.s_CHAT = socket.socket()
            self.s_CHAT.connect((self.chat_server_ip,self.chat_server_port))
            #3)
            to_send=(
                self.id, 
                self.encrypt(
                    self.K_temp,
                    (
                        "/init_group_dhxchg",
                        self.public_key_encryption(
                            pub_key_to_client,
                            my_pub_key_DH
                        ),
                        to_client,
                        group_id,
                        self.ticket
                    )
                )
            )
            self.s_CHAT.send(pickle.dumps(to_send))
            #4
            response=self.s_CHAT.recv(4096)
            response=self.decrypt(
                self.K_temp,
                response
            )
            
            to_client_public_DH=self.public_key_decryption(pub_key_to_client, response[0])

            DH_key=self.convert_to_key(my_pub_key_DH)
            hashed_K=self.decrypt(DH_key, response[1])

            #5
            # pow(g^c3, K)=g^(K*c3)
            K_new=pow(to_client_public_DH,old_K,P)
            my_hashed_K=self.hash(K_new)
            if my_hashed_K!=hashed_K:
                raise Exception("K hash not equal")
            
            self.disconnect()

            # send updated key to all others in the group
            for uid in self.group_members[group_id]:
                print("DATA",uid, to_client)
                if uid==self.id or int(uid)==int(to_client):
                    print("Not sending to",uid)
                    continue
                print("Sending to",uid)

                self.s_CHAT = socket.socket()
                self.s_CHAT.connect((self.chat_server_ip,self.chat_server_port))
                packet=(
                    self.id,
                    self.encrypt(
                        self.K_temp,
                        (
                            "/update_df_key",
                            self.encrypt(
                                self.convert_to_key(old_K),
                                K_new,
                            ),
                            uid,
                            group_id,
                            self.ticket
                        )
                    )
                )
                self.s_CHAT.send(pickle.dumps(packet))
                self.disconnect()
          
            print("Updated key:",K_new)
            
            self.group_keys[group_id]=K_new
           
    def write_group_request(self, group_id,message):
        """
        Send the request to all the client in the
        group via server. In the following format:
        (
            self.id
            E(
                k_temp,
                (
                    "/write_group",
                    E(
                        K, #from dh
                        message
                    ),
                    to_client,
                    group_id
                    self.ticket
                )
            )
        )
        """
        group_id=int(group_id)
        K=self.group_keys[group_id]
        for uid in self.group_members[group_id]:
            to_send=(
                self.id,
                self.encrypt(
                    self.K_temp,
                    (
                        "/write_group",
                        self.encrypt(
                            self.convert_to_key(K), #from dh
                            message
                        ),
                        uid,
                        group_id,   
                        self.ticket
                    )
                )
            )
            self.s_CHAT = socket.socket()
            self.s_CHAT.connect((self.chat_server_ip,self.chat_server_port))
            self.s_CHAT.send(pickle.dumps(to_send))

            self.disconnect()

    def show_IRC_UI(self):
        while True:
            total=input(">> ")
            total_split=total.split(" ")
            comm=total_split[0]
            if comm=="exit":
                break
            elif comm=="/who":
                self.who_request()
            elif comm=="/write_all":
                self.write_all_request(total[len(comm)+1:])
            elif comm=="/request_public_key":
                print(self.get_public_key_request(total_split[1]))
            elif comm=="/create_group":
                print(total_split[1])
                self.create_group_request(total_split[1])
            elif comm=="/group_invite":
                #format: /group_invite <grp_id> <client_id>
                self.group_invite_request(total_split[1], total_split[2])
            elif comm=="/group_invite_accept" :
                self.accept_response=True
            elif comm=="/group_invite_decline" :
                self.accept_response=False
            elif comm=="/init_group_dhxchg":
                #format: /init_group_dhxchg <grp_id> <client_id>
                self.dh_key_xchange_request(int(total_split[1]),int(total_split[2]))
            elif comm=="/write_group":
                #format /write_group <group> <message>
                self.write_group_request(total_split[1],total_split[2])




                
    def start_listening(self):
        """
        receives the forwarded message from server.
        message originated at indivisual clients

        for a /write_all: ("/write_all", E(pub_key, (from,message)))

        for a /group_invite: ("/group_invite",E(session_key_to, (from_client, group_id)))
            after a successful invite acceptance, a pyDH.DiffieHellman object is
            added to self.groups[group_id] dictionary. Final key will be saved in
            self.group_keys after successful DH key xchange

        for a "/init_group_dhxchg":
            recv format:
                (
                    "/init_group_dhxchg",
                    E(
                        k_temp_to,
                        (
                            E(
                                k_pub_this,
                                others_public_key_DH
                            ),
                            from_client,
                            group_id
                        )
                    )
                )
            
            send format:
                E(
                    k_temp,
                    (
                        E(
                            private_key_this_client,
                            this_client_public_key_DH
                        ),
                        E(
                            K,
                            sha256(new_K)
                        )
                    )
                )
            
        for "/update_df_key" request:
            (
                "/update_df_key",
                E(
                    k_temp_to,
                    (
                        E(
                            K #old,
                            new_K
                        ),
                        from_client,
                        group_id
                    )
                )
            )

        """
        print("Listening Started")
        self.s = socket.socket()
        self.s.bind(('',int(self.listening_port)))

        
        self.s.listen(1)
        
        while True:
            self.conn,self.addr = self.s.accept()
            server_message=pickle.loads(self.conn.recv(4096))
            print("Server message",server_message)
            print("")
            print(server_message[0])
            if(server_message[0]=="/write_all"):
                message=self.private_key_decryption(self.private_key,server_message[1])
                from_=message[0]
                message_text=message[1]
                print("Received from",from_,":",message[1])
            elif server_message[0]=="/group_invite":
                inner_dec=self.decrypt(self.K_temp,server_message[1])
                print("Got a group request from",inner_dec[0],"for group ",inner_dec[1])
                print("Sending auto response to accept response:",self.accept_response)
               
                if self.accept_response:
                    packet=self.encrypt(self.K_temp,"/group_invite_accept")
                    self.conn.send(packet)
                    self.groups[int(inner_dec[1])]=pyDH.DiffieHellman()
                else:
                    packet=self.encrypt(self.K_temp,"/Not accepted")
                    self.conn.send(packet)
            elif server_message[0]=="/init_group_dhxchg":
                inner_dec=self.decrypt(self.K_temp,server_message[1])
                group_id=int(inner_dec[2])
                from_id=int(inner_dec[1])
                mess=inner_dec[0]

                dh=self.groups[group_id]
                other_public_dh=self.private_key_decryption(self.private_key, mess)
                p=P

                #pow(g^c2, c1,p)=g^(c2*c1)mod(p)
                K=pow(other_public_dh,dh.get_private_key(), P)
                response=(
                    self.private_key_encryption(self.private_key,dh.gen_public_key()),
                    self.encrypt(
                        self.convert_to_key(other_public_dh),
                        self.hash(K)
                    )
                )
                response_enc=self.encrypt(self.K_temp,response)
                self.conn.send(response_enc)
                print("Generated key: ", K)
                self.group_keys[group_id]=K                    
            elif server_message[0]=="/update_df_key":
                inner_dec=self.decrypt(self.K_temp,server_message[1])
                group_id=int(inner_dec[2])
                mess=inner_dec[0]
                if group_id in self.group_keys.keys():
                    old_key=self.group_keys[group_id]
                    print("OLD KEY", old_key)
                    new_key=self.decrypt(self.convert_to_key(old_key),mess)
                    print("New key: ", new_key)
                    self.group_keys[group_id]=new_key
            elif server_message[0]=="/write_group":
                inner_dec=self.decrypt(self.K_temp,server_message[1])
                K=self.group_keys[inner_dec[1]]
                mess_dec=self.decrypt(self.convert_to_key(K),inner_dec[0])
                print("Message from group",inner_dec[1],":",mess_dec)
            else:
                pass
            self.conn.close()

    def disconnect(self):
        try:
            self.s_KDC.close()
            self.s_CHAT.close()
        except:
            pass


def loadData(name):
    f=open(name,'rb')
    return pickle.load(f)

if __name__=="__main__":

    filename="client_"+str(ID)+".info"
    id,key,listening_ip,listening_port=loadData(filename)
    server_info=loadData("../server.info")
    this_client=client(id, server_info['kdc_server_port'], server_info['kdc_server_ip'], server_info['chat_server_port'], server_info['chat_server_ip'], key,listening_port,debug=True)
    this_client.authenticate()
    this_client.connet_to_chat_server()
    # now open a another thread that will listen
    # for server messages
    listen_thread=threading.Thread(target=this_client.start_listening)
    listen_thread.start()
    this_client.show_IRC_UI()
    this_client.disconnect()