pbproxy: pbproxy.c
	gcc pbproxy.c -o pbproxy -lcrypto

clean:
	rm -f *.o mydump