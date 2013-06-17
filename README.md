A simple Python chatroom with RSA keys authentication
=====================================================

About
-----

This is a simple chatserver that uses server-client RSA key based authentication.
The provided keys are server and client, encrypted with passphrase.
You need to generate your own keys with more secure passphrases.

You can do that like this:

    openssl genrsa -out server.pem -des3 4096
    openssl rsa -pubout -in server.pem -passin pass:"1234" -out server.pub

It is the same for clients.
Put server.pub file into client folder and let clients download it.
Have each client generate their own keypair, and send you the public part of it.
The public part is selected by client's name, so for client with name lukas, it will
look for lukas.pub file.

For server:
-----------
Goto line 78 in server.py, and edit passphrase to that of your key.
Goto line 35 in server.py, and change IP address where you want your server to run.
Goto line 27 in server.py, and change the port on what the server should run.

For clients:
------------
Goto line 36 in client.py, and change the passhprase to that of your key.

Client keypair needs to have name client.pem in client folder and client's name.pub in server folder.


Run python server.py on the server machine.
Clients run python client.py clientname serverIP serverPort

Note:
-----

This is just software example. It works for simple communication, but it is not user friendly.
If anyone would like to use it, you do it on your own risk.
Maybe in future I'll get back to it and make this software easier to use.
