The application pbproxy generated for this homework is a program which when executed on the server side at a listening port keeps on listening for incoming messages. When executed on the client side with the above said listening port as destination, a connection is established between the application on the client side and the server side.
This application supports only single connection.

The application on client side encrypts all the messages using standard AES encryption and sends it across to the server side application listening port. The listening port of the application on the server side the relays this message(after decryprtion) to the server as per the server post and destination address specified. Then relays the message back to the application on the client side(after encryption).

The application pbproxy can be build using the below command :

make

Sample command :

On server side :

pbproxy -l <listening port> -k <key_file> <destination> <destination_port>

On client side:

ssh -o "ProxyCommand pbproxy -k <key_file> <server address> <destination port>" localhost

This generates the application pbproxy. The additional library "lcrypto" is used in the make file to support AES encryption and decryption. To support the encryption and decryption standard APIs are used by using the Internet as a reference.

Also socket programming is used in the application for opening sockets both on the client and server side to establish communication across this channel. Socket programming  tutorial from RPI is used for reference to implement the sockets and their communication on both sides.