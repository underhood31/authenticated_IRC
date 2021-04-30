import pickle
from cryptography.fernet import Fernet
#https://devqa.io/encrypt-decrypt-data-python/

if __name__=='__main__':
    details={}

    details['kdc_server_ip']=input("KDC server IP: ")
    details['kdc_server_port']=int(input("KDC server port: "))

    details['chat_server_ip']=input("Chat server IP: ")
    details['chat_server_port']=int(input("Chat server port: "))

    f=open("server.info",'wb')
    pickle.dump(details,f)

    client_private_keys={}
    client_id=0

    # client creation
    while True:
        res=input("Wanna create client? (y/n)")
        if res=='N' or res=='n':
            break
        key = Fernet.generate_key()
        id=client_id
        client_private_keys[id]=key

        f=open("client_"+str(id)+".info","wb")
        pickle.dump((id,key),f)
        client_id+=1

    f=open("all_client_secrets.info",'wb')
    pickle.dump(client_private_keys,f)
    
