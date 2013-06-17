# -*- encoding: utf-8 -*-

#! /usr/bin/env python

"""
Simple chat client for the chat server. Defines
a simple protocol to be used with chatserver.

"""

import socket
import sys
import select

from Crypto.PublicKey import RSA

from communication import send, receive


class ChatClient(object):
    """ A simple command line chat client using select """

    def __init__(self, name, host='127.0.0.1', port=3490):
        self.name = name
        # Quit flag
        self.flag = False
        self.port = int(port)
        self.host = host
        # Initial prompt
        self.prompt = '[' + '@'.join((name, socket.gethostname().split('.')[0])) + ']> '

        server_pubkey = open('server.pub', 'r').read()
        client_privkey = open('client.pem', 'r').read()

        self.encryptor = RSA.importKey(server_pubkey)
        self.decryptor = RSA.importKey(client_privkey, passphrase='heslo')

        # Connect to server at port
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.connect((host, self.port))
            print 'Connected to chat server@%d' % self.port
            # Send my name...
            send(self.sock, 'NAME: ' + self.name)
            data = receive(self.sock)
            # Contains client address, set it
            addr = data.split('CLIENT: ')[1]
            self.prompt = '[' + '@'.join((self.name, addr)) + ']> '
        except socket.error:
            print 'Could not connect to chat server @%d' % self.port
            sys.exit(1)

    def cmdloop(self):

        while not self.flag:
            try:
                sys.stdout.write(self.prompt)
                sys.stdout.flush()

                # Wait for input from stdin & socket
                inputready, outputready, exceptrdy = select.select([0, self.sock], [], [])

                for i in inputready:
                    if i == 0:
                        data = sys.stdin.readline().strip()

                        data = self.encryptor.encrypt(data, 0)

                        if data:

                            send(self.sock, data)
                    elif i == self.sock:

                        data = receive(self.sock)

                        if not data:
                            print 'Shutting down.'
                            self.flag = True
                            break

                        else:
                            if 'PLAIN:' in data:

                                data = data.strip('PLAIN:').strip()

                            else:

                                data = self.decryptor.decrypt(data)

                            sys.stdout.write(data + '\n')
                            sys.stdout.flush()

            except KeyboardInterrupt:
                print 'Interrupted.'
                self.sock.close()
                break


if __name__ == "__main__":

    if len(sys.argv) < 3:
        sys.exit('Usage: %s chatid host portno' % sys.argv[0])

    client = ChatClient(sys.argv[1], sys.argv[2], int(sys.argv[3]))
    client.cmdloop()
