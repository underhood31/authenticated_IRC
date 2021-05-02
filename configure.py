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

    #format: {id:(ip, port)}
    client_listening_details={}
    client_id=0

    # client creation
    while True:
        res=input("Wanna create client? (y/n)")
        if res=='N' or res=='n':
            break
        key = Fernet.generate_key()
        id=client_id
        listening_ip=input("Enter listening ip for the client "+str(id)+" :")
        listening_port=input("Enter listening port for the client "+str(id)+" :")
        
        client_private_keys[id]=key
        client_listening_details[id]=(listening_ip,listening_port)

        f=open("client_"+str(id)+".info","wb")
        pickle.dump((id,key,listening_ip,listening_port),f)
        client_id+=1

    f=open("all_client_secrets.info",'wb')
    pickle.dump(client_private_keys,f)

    f=open("all_client_listening.info",'wb')
    pickle.dump(client_listening_details,f)
    
