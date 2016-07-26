# plugboard_proxy
The application pbproxy is a "plugboard" proxy adds an extra
layer of encryption to connections towards TCP services. Instead of connecting
directly to the service, clients connect to pbproxy (running on the same
server), which then relays all traffic to the actual service. Before relaying
the traffic, pbproxy decrypts it using a static symmetric key. This
means that if the data of any connection towards the protected server is not
properly encrypted, then it will turn into garbage before reaching the
protected service.

Attackers who might want to exploit a zero day vulnerability in the protected
service will first have to know the secret key for having a chance to
successfully deliver their attack vector to the server.

Clients who want to access the protected server should proxy their traffic
through a local instance of pbroxy, which will encrypt the traffic using the
same symmetric key used by the server. In essence, pbproxy can act both as
a client-side proxy and as server-side reverse proxy.

Command Line format :

pbproxy [-l port] -k keyfile destination port

  -l  Reverse-proxy mode: listen for inbound connections on <port> and relay
      them to <destination>:<port>

  -k  Use the symmetric key contained in <keyfile> (as a hexadecimal string)

Data is encrypted/decrypted using AES in CTR mode. In client mode, plaintext traffic is read from stdin. In server mode, pbrpoxy should keep listening for incoming connections after  a previous session is terminated.

Example :

ssh -o "ProxyCommand pbproxy -k mykey vuln.cs.stonybrook.edu 2222" localhost

This will result in a data flow similar to the following:

ssh <--stdin/stdout--> pbproxy-c <--socket 1--> pbproxy-s <--socket 2--> sshd
\______________________________/                \___________________________/
             client                                        server           
