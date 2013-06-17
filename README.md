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
    run python server.py listen_ip listen_port certificate_file certificate_password

For clients:
------------
    run python client.py username server_ip server_port client_certificate certificate_password

Client keypair needs to have name client.pem in client folder and client's name.pub in server folder.


Note:
-----
I found a simple chatserver recipe on the internet with some bugs. I fixed most of them,
added a encryption and message signing. If there are some bugs, you can report them to me,
but no promisses :)

This is just software example. It works for simple communication, but it is not user friendly.
If anyone would like to use it, you do it on your own risk.
Maybe in future I'll get back to it and make this software easier to use.
