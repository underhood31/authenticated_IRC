import threading
import pickle

#https://www.studytonight.com/python/python-threading-lock-object#:~:text=Lock%20Object%3A%20Python%20Multithreading&text=This%20lock%20helps%20us%20in,we%20initialize%20the%20Lock%20object.


class Database:
    def __init__(self, client_key_dict):
        self.ticket_dict={}
        self.ticket_lock=threading.Lock()
        self.session_key_dict={}
        self.session_key_lock=threading.Lock()
        self.client_secret_keys=client_key_dict
    
    def add_ticket(self, client, ticket):
        """
        client should be of int type
        ticket should be of bytes type
        """

        #get lock
        self.ticket_lock.acquire()
        try:
            print("before",ticket)
            self.ticket_dict[client]=ticket
            print("after",self.ticket_dict[client])

        finally:
            self.ticket_lock.release()
    
    def get_ticket(self, client):
        """
        client should be of int type
        """

        #get lock
        self.ticket_lock.acquire()
        try:
            return self.ticket_dict[client]
        finally:
            self.ticket_lock.release()
    
    def add_session_key(self, client, session_key):
        """
        client should be of int type
        session_key should be of bytes type
        """

        #get lock
        self.session_key_lock.acquire()
        try:
            self.session_key_dict[client]=session_key
        finally:
            self.session_key_lock.release()

    def get_session_key(self, client):
        """
        client should be of int type
        """                         

        #get lock
        self.session_key_lock.acquire()
        try:
            return self.session_key_dict[client]
        finally:
            self.session_key_lock.release()

from kdc import kdc_server
from chat import chat_server
server_details_path="../server.info"
client_keys_path="all_client_secrets.info"

def loadData(name):
    f=open(name,'rb')
    return pickle.load(f)

if __name__=="__main__":

    server_details=loadData(server_details_path)
    client_keys=loadData(client_keys_path)
    database=Database(client_keys)

    my_kdc_server = kdc_server(verb=True,database=database,port=server_details['kdc_server_port'],debug=True)
    my_chat_server = chat_server(verb=True,database=database,port=server_details['chat_server_port'], debug=True)
    kdc_thread=threading.Thread(target=my_kdc_server.run)
    chat_thread=threading.Thread(target=my_chat_server.run)

    kdc_thread.start()
    chat_thread.start()

    kdc_thread.join()
    chat_thread.join()

    print("Shutting down server process")
