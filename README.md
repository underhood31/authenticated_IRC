# NSSII Assignment 2

Manavjeet Singh, 2018295

## Part 1, IRC client

## Dependencies

The application is dependent on following python modules

- socket
- pickle
- cryptography
- threading
- s
- time
- random
- base64

## Running

- Use &quot;make server&quot; to run the server
- Use &quot;make c0&quot; to run the client 0
- Use &quot;make c1&quot; to run the client 1
- Use &quot;make c2&quot; to run the client 2
- Use &quot;make c3&quot; to run the client 3

## Configure

The server and clients are preconfigured.

But if you want to configure again, run &quot;python configure.py&quot; and enter the relevant details and follow the following steps:

- Move &quot;all\_client\_listening.info&quot; and &quot; all\_client\_secrets.info&quot; files generated in root folder to the Server folder.
- Move the respective client config info files to the client folders.

## Test Run

Run the programs as instructed in Running section and do the following:

![](RackMultipart20210502-4-sorlmw_html_555adba999b07c0d.png)

- Run &quot;/create\_group sample\_group&quot; on client0. A group id will be returned. Following steps are assuming that the group id is 0.
 ![](RackMultipart20210502-4-sorlmw_html_d294dc018c8b281a.png)
- Enter &quot;/group\_invite 0 1&quot; to invite client 1 to group 0. Similarly for client2, and client3
 ![](RackMultipart20210502-4-sorlmw_html_96a20bdd8416e584.png)
- Run &quot;/init\_group\_dhxchg 0 1&quot; to do a DH key exchange with client3 for group0. Repeat this for client2 and client3 to update the group key for their DH keys.
 ![](RackMultipart20210502-4-sorlmw_html_d0bd7d33c4fed864.png)
 ![](RackMultipart20210502-4-sorlmw_html_31545db2d891ae94.png)
 ![](RackMultipart20210502-4-sorlmw_html_f6280e2d03ec39fc.png)
- Run &quot;/write\_group 0 hello&quot; to write the message to the group0, encrypted by their DH key.
 ![](RackMultipart20210502-4-sorlmw_html_2c9c04fb7f102f73.png)
- Run &quot;/who&quot; to see all those on the server
 ![](RackMultipart20210502-4-sorlmw_html_a9c9a7581f3b81f9.png)
- Run &quot;/write\_all message&quot; to broadcast message to all the clients
 ![](RackMultipart20210502-4-sorlmw_html_5fa26d7bea2125f5.png)

- Run &quot;/request\_public\_key 3&quot; to get the public key of the client 3
 ![](RackMultipart20210502-4-sorlmw_html_55a7a9e13dcccaa9.png)

## Commands and assumptions

- &quot;/who&quot;: Who all are logged in to the chat server, along with a user IDs.
- &quot;/write\_all&quot;: Write message which gets broadcasted to all users.
- &quot;/create\_group \&lt;grp\_name\&gt;&quot;: Create a group to which users may be added. A group ID and name is returned.
- &quot;/group\_invite \&lt;grp\_id\&gt; \&lt;client\_to\_id\&gt;&quot;: Send an invite to individual users IDs.
- &quot;/group\_invite\_accept&quot;: Convert acceptance variable to true, all requests will be accepted
- &quot;/group\_invite\_decline&quot;: Convert acceptance variable to false, all requests will be denied
- &quot;/request public key&quot;: Send request for public key to a specific users.
- &quot;/send\_public\_key&quot;: Send back public key back as a response to the above request. This command works internally, the user cannot fill it.
- &quot;/init\_group\_dhxchg&quot;: This process initiates a DH exchange first with any two users and then adds more users to the set..
- &quot;/write\_group \&lt;grp\_id\&gt; message&quot;: Write messages to a group specifying its group ID.
- &quot;/list\_user\_files \&lt;ip addr\&gt; \&lt;port\&gt;&quot;: list the files in the client directory
- &quot;/request\_file \&lt;ip\_addr\&gt; \&lt;port\&gt; \&lt;file\_name\&gt;&quot;: loads the file into local client directory

##


## Documentation and Code

Some highlights of the documentation is given below:

### Client to KDC server

**KDC side:**

**&quot;&quot;&quot;**

**Prereq: kdc and client will have a preshared key(K\_c)**

**KDC Client**

**\&lt;---------------- (ID\_client, TS1)**

**K\_temp=gen\_session\_key()**

**ticket=gen\_ticket()**

**E(K\_c, (E(K\_temp, Ticket), Nonce, TS2)) ------------------\&gt;**

**&quot;&quot;&quot;**

**Client Side:**

**&quot;&quot;&quot;**

**Client KDC**

**(ID\_client, TS1) ---------------\&gt;**

**\&lt;---------------- E(K\_c, (E(K\_temp, Ticket), Nonce, TS2))**

**K\_temp=gen\_session\_key()**

**ticket=decrypt(K\_temp, Ticket)**

**&quot;&quot;&quot;**

**Session key is the function of K\_c, TS and nonce.**

### Client to Chat server authentication

&quot;&quot;&quot;

The client should have a valid ticket and session\_key before contacting

the chat server.

This can be done by calling the authenticate function of this class

Client Chat Server

~~~~~~~~~~~~~~~~~~

(

ID, ---------\&gt;

E(k\_temp,(request, pub\_key,ticket))

)

#Here request would be /auth

\&lt;------- Acknowledgement

&quot;Authenticated&quot;

or

ot Authenticated&quot;

&quot;&quot;&quot;

The chat server matches the ticket and authenticates the client.

There is a shared database data structure that keeps track of client session\_keys, ports, ip addresses and tickets.

For detailed information on diffie hellman key exchange, read documentation of **dh\_key\_xchange\_request** , **df\_xchg\_handler** and **start\_listening** from client, server\_chat and again client documentation from docs folder or the following links.

For detailed documentation and code open HTML files in the docs folder in the submissions or the following links. **(Ps, if some comment is not clear, click on the expand code button under to see the raw text that would be clear).**

- py: [https://underhood31.github.io/authenticated\_IRC/client.html](https://underhood31.github.io/authenticated_IRC/client.html)
- Server, main.py: [https://underhood31.github.io/authenticated\_IRC/server\_main](https://underhood31.github.io/authenticated_IRC/server_main)
- Server, kdc.py: [https://underhood31.github.io/authenticated\_IRC/server\_kdc](https://underhood31.github.io/authenticated_IRC/server_kdc)
- Server, chat.py: [https://underhood31.github.io/authenticated\_IRC/server\_chat](https://underhood31.github.io/authenticated_IRC/server_chat)

## References

[https://nitratine.net/blog/post/asymmetric-encryption-and-decryption-in-python/#:~:text=Asymmetric%20encryption%20uses%20two%20keys,key%20can%20decrypt%20the%20message](https://nitratine.net/blog/post/asymmetric-encryption-and-decryption-in-python/#:~:text=Asymmetric%20encryption%20uses%20two%20keys,key%20can%20decrypt%20the%20message).

[https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa/](https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa/)

[https://www.studytonight.com/python/python-threading-lock-object#:~:text=Lock%20Object%3A%20Python%20Multithreading&amp;text=This%20lock%20helps%20us%20in,we%20initialize%20the%20Lock%20object](https://www.studytonight.com/python/python-threading-lock-object#:~:text=Lock%20Object%3A%20Python%20Multithreading&amp;text=This%20lock%20helps%20us%20in,we%20initialize%20the%20Lock%20object)

[https://cryptography.io/en/latest/fernet/#using-passwords-with-fernet](https://cryptography.io/en/latest/fernet/#using-passwords-with-fernet)

[https://devqa.io/encrypt-decrypt-data-python/](https://devqa.io/encrypt-decrypt-data-python/)

[https://cryptography.io/en/latest/hazmat/primitives/cryptographic-hashes/](https://cryptography.io/en/latest/hazmat/primitives/cryptographic-hashes/)