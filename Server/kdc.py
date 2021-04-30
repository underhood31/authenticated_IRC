import socket,pickle,time, random
import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet
import base64

#https://cryptography.io/en/latest/fernet/#using-passwords-with-fernet
#https://devqa.io/encrypt-decrypt-data-python/
#https://cryptography.io/en/latest/hazmat/primitives/cryptographic-hashes/


class kdc_server:

    def __init__(self, database, verb=False, debug=False, port=10001):
        self.verbose=verb
        self.debug_v=debug
        self.port=port
        self.client_data=database.client_secret_keys
        self.delta_time=0.5
        self.database=database

    def log(self, out_string):
        if self.verbose:
            print("[KDC server]",out_string)

    def debug(self, out_string):
        if self.debug_v:
            print("[KDC server][debug]",out_string)

    def gen_session_key(self, K_c, TS, nonce):
        """
        Session key is the function of K_c, TS and nonce
        These values are hashed
        """
        derived_password=(str(K_c) + str(TS)).encode()
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256, length=32, salt=nonce, iterations=100000) #used to derive a key from password
        key = base64.urlsafe_b64encode(kdf.derive(derived_password)) #encode as utf-8 encode instead of binary
        return key

    def gen_ticket(self, ID_client):
        """
        ticket is the function of client ID and a nonce
        """
        digest = hashes.Hash(hashes.SHA256())
        digest.update(str(ID_client).encode())  #client id
        digest.update(os.urandom(128))          #nonce
        ticket = base64.urlsafe_b64encode(digest.finalize())
        return ticket

    def encrypt(self, key, obj):
        """
        encrption using furnet, which uses AES encryption
        """
        encryption_function=Fernet(key)
        encrypted=encryption_function.encrypt(pickle.dumps(obj))
        return encrypted

    def authenticate(self,cleint_request):
        """
        Prereq: kdc and client will have a preshared key(K_c)

        KDC                                                        Client
                                         <----------------         (ID_client, TS1)
        
        K_temp=gen_session_key()
        ticket=gen_ticket()

        E(K_c, (E(K_temp, Ticket), Nonce, TS2))    ------------------>         
        """
        ID_client,TS1=pickle.loads(cleint_request)
        self.log("Processing request from client "+str(ID_client))
        try:
            K_c=self.client_data[int(ID_client)]
            self.debug("K_c is:"+str(K_c))
        except:
            pass
        #     self.log("Unable to verify client with id: "+str(ID_client))
        #     return None
        # finally 

        if time.time()-float(TS1)<self.delta_time and time.time()-float(TS1)>=0:
            TS2=time.time()
            nonce=os.urandom(128)
            K_temp=self.gen_session_key(K_c,TS2,nonce)
            self.debug("K_temp is:"+str(K_temp))
            ticket=self.gen_ticket(ID_client)
            self.debug("ticket is:"+str(ticket))
            #give the ticket to chat server for client verification
            self.database.add_ticket(ID_client,ticket)
            #give session key to the chat server for decryption
            self.database.add_session_key(ID_client,K_temp)
            #encrypt ticket
            enc_ticket=self.encrypt(K_temp, ticket)
            return self.encrypt(K_c, (enc_ticket, nonce, TS2))
        else:
            self.log("Unable to verify client with id(timeout): "+str(ID_client))
            return None
    
    def run(self):

        self.log("running")

        self.s = socket.socket()
        self.s.bind(('',self.port))

        
        self.s.listen(10)
        self.log("Listening on port "+str(self.port))

        while True:
            conn,addr = self.s.accept()
            self.log('Got Auth request from '+str(addr))
            
            client_request=conn.recv(4096)
            ret=self.authenticate(client_request)

            if ret==None:
                conn.send('Not Authenticated'.encode('utf-8'))
            else:
                conn.send(ret)

            conn.close()

