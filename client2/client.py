import socket,time,pickle
import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet
import base64

ID=2

class client:
    def __init__(self,id, kdc_server_port, kdc_server_ip, chat_server_port, chat_server_ip,key,debug=False):
        self.id=id
        self.kdc_server_port=kdc_server_port
        self.kdc_server_ip=kdc_server_ip
        self.chat_server_port=chat_server_port
        self.chat_server_ip=chat_server_ip
        self.key=key
        self.delta_time=0.5
        self.debug_v=debug
        

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
    
    def gen_session_key(self, K_c, TS, nonce):
        """
        Session key is the function of K_c, TS and nonce
        These values are hashed
        """
        derived_password=(str(K_c) + str(TS)).encode()
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256, length=32, salt=nonce, iterations=100000) #used to derive a key from password
        key = base64.urlsafe_b64encode(kdf.derive(derived_password)) #encode as utf-8 encode instead of binary
        return key
    
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
            self.disconnect
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

        (ID,E(k_temp,(request, ticket))) ----------------->          
        #Here request would be /auth

                                        <-----------------         Acknowledgement
                                                                    "Authenticated"
                                                                          or
                                                                  "Not Authenticated"

        """
        self.s_CHAT = socket.socket()
        self.s_CHAT.connect((self.chat_server_ip,self.chat_server_port))
        packet=("/auth", self.ticket)
        print("ticket", self.ticket)
        print("session key", self.K_temp)
        packet_enc=self.encrypt(self.K_temp, packet)
        packet_with_id=(self.id,packet_enc)
        self.s_CHAT.send(pickle.dumps(packet_with_id))
        response=self.s_CHAT.recv(4096)
        if(response=="Not Authenticated".encode()):
            print("Unable to authenticate(chat server), exiting...")
            self.disconnect
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
    
    def show_IRC_UI(self):
        while True:
            comm=input(">> ")
            if comm=="exit":
                break
            elif comm=="/who":
                self.who_request()
                
    
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
    id,key=loadData(filename)
    server_info=loadData("../server.info")
    this_client=client(id, server_info['kdc_server_port'], server_info['kdc_server_ip'], server_info['chat_server_port'], server_info['chat_server_ip'], key,debug=True)
    this_client.authenticate()
    this_client.connet_to_chat_server()
    this_client.show_IRC_UI()
    this_client.disconnect()