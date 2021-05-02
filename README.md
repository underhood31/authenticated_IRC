
# Documention
For better documentation read IRC Client Documentation.pdf and the following links
- [client.py](https://underhood31.github.io/authenticated_IRC/client)
- [Server, main.py](https://underhood31.github.io/authenticated_IRC/client)
- [Server, kdc.py](https://underhood31.github.io/authenticated_IRC/client)
- [Server, chat.py](https://underhood31.github.io/authenticated_IRC/client)

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


