#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <openssl/aes.h>
#include <openssl/rand.h> 
#include <openssl/buffer.h>

#define BUFF_LEN 4096

//Structure to contain all the command line arguments
typedef struct 
{
	int is_server_mode;
	int lport;
	char* dest;
	char* key_file;
	int dport;
}command_line_args;

struct ctr_state 
{
	unsigned char ivec[AES_BLOCK_SIZE];  
	unsigned int num; 
	unsigned char ecount[AES_BLOCK_SIZE]; 
};

//prototype of functions used
char* decryptString(char* str, AES_KEY key, struct ctr_state state, int len);
char* encryptString(char* str, AES_KEY key, struct ctr_state state, int len);
command_line_args* parse_command_line(int argc, char *argv[]);
void startInClientMode(char* dest, int dport, AES_KEY aes_key, struct ctr_state state);
void startInServerMode(int lport, char* dest, int dport, AES_KEY aes_key, struct ctr_state state);

//initialize the counter for encryption and decryption
int init_ctr(struct ctr_state *state, const unsigned char iv[8]) 
{
	state->num = 0;
	memset(state->ecount, 0, AES_BLOCK_SIZE);
	memset(state->ivec + 8, 0, 8);
	memcpy(state->ivec, iv, 8);
}

int main(int argc, char *argv[]) 
{
	char key[BUFF_LEN]; //holds the key read from key_file
	struct ctr_state state;
	
	//get the command line arguments
	command_line_args* args = parse_command_line(argc, argv);
	
	//read the key file and populate the AES key to be used across the program
	FILE* ptr_file =fopen(args->key_file,"r");
	if (!ptr_file)
	{
		printf("Unable to read the key file.Exiting the program\n");
		exit(1);
	}
	
	fgets(key,BUFF_LEN, ptr_file);
	fclose(ptr_file);
	
	AES_KEY aes_key;
	
	if (AES_set_encrypt_key(key, 128, &aes_key) < 0) 
	{
		printf("Unable to set the AES symmetric key.Exiting the program.\n");
		exit(1);
	}

	// pbproxy running in server mode
	if (args->is_server_mode) 
	{
		startInServerMode(args->lport, args->dest, args->dport, aes_key, state);
	}
	else //pbproxy running in client mode
	{
		startInClientMode(args->dest, args->dport, aes_key, state);
	}
	
	return 1;
}

//encrypts a string and return the encrypted string
char* encryptString(char* str, AES_KEY aes_key, struct ctr_state state, int len)
{
    unsigned char iv[8];
    if(!RAND_bytes(iv, 8)) 
    {
        printf("Unable to generate random bytes.Exiting the program.\n");
        exit(1);
    }
    
    char* temp = (char*)malloc(len + 8);
    memcpy(temp, iv,8);
    unsigned char encrypted_str[len];
    init_ctr(&state, iv);
    
    AES_ctr128_encrypt(str, encrypted_str, len, &aes_key, state.ivec, state.ecount, &state.num);
    memcpy(temp+8, encrypted_str, len);
    return temp;
}

//decrypts a string and returns the decrypted string
char* decryptString(char* str, AES_KEY aes_key, struct ctr_state state, int len)
{
    unsigned char iv[8];
    if(len < 8)
    {
        printf("Length of string to be decrypted is less than 8.\n");
        exit(1);
    }
    memcpy(iv, str, 8);
    unsigned char* decrypted_str = (char*)malloc(len - 8);
    init_ctr(&state, iv);   
    AES_ctr128_encrypt(str+8, decrypted_str, len-8, &aes_key, state.ivec, state.ecount, &state.num);
    return decrypted_str;
}

//parses the command line and return the command_line_args structure
command_line_args* parse_command_line(int argc, char *argv[])
{
	int opt;
	command_line_args* args = (command_line_args*)malloc(sizeof(command_line_args));
	args->is_server_mode = 0;
	while ((opt = getopt(argc, argv, "k:l:")) != -1) 
	{
		switch(opt) 
		{
			case 'l':
				args->lport = atoi(optarg);
				args->is_server_mode = 1;
				break;
			case 'k':
				args->key_file = optarg;
				break;
			case '?':
				// when user didn't specify argument
				if (optopt == 'l') 
				{
					printf("listening port number must be specified\n");
					exit(1);
				}
				else if (optopt == 'k') 
				{
					printf("Key file must be specified\n");
					exit(1);
				} 
				else 
				{
					printf("Unknown argument!\n");
					exit(1);
				}
			default:
				printf("Default case?!\n");
				exit(1);
		}
	}
	if (optind == argc - 2) 
	{
		args->dest = argv[optind];
		args->dport = atoi(argv[optind+1]);
	}
	return args;
}

//starts the application in client mode
void startInClientMode(char* dest, int dport, AES_KEY aes_key, struct ctr_state state)
{
	// pbproxy running in client mode
	int app_socket_client, length;
	char buffer[BUFF_LEN];
	struct sockaddr_in serverAddr;

	struct hostent *host_name_ent = gethostbyname(dest);
	
	if(host_name_ent == 0 || !host_name_ent)
	{
		printf("Unable to resolve host name %s. Exiting the program\n", dest);
		exit(1);
	}

	//create a socket at the client to communicate with the server
	app_socket_client = socket(AF_INET, SOCK_STREAM, 0);
	
	memset(&serverAddr, '\0', sizeof serverAddr);	
	serverAddr.sin_family = AF_INET;
	serverAddr.sin_port = htons(dport);
	serverAddr.sin_addr.s_addr = ((struct in_addr *)(host_name_ent->h_addr))->s_addr;
	
	int success = connect(app_socket_client, (struct sockaddr *)&serverAddr, sizeof(serverAddr));
	if (success == -1) 
	{
		printf("Connection to the server failed!\n");
		exit(1);
	}
	
	fcntl(STDIN_FILENO, F_SETFL, O_NONBLOCK);
	fcntl(app_socket_client, F_SETFL, O_NONBLOCK);
	
	while(1) 
	{
		while ((length = read(STDIN_FILENO, buffer, BUFF_LEN)) > 0) 
		{
			//encrypt the string and write it to the socket
			write(app_socket_client, encryptString(buffer, aes_key, state, length), length + 8);
			if (length < BUFF_LEN)
				break;
		}
		
		while ((length = read(app_socket_client, buffer, BUFF_LEN)) > 0) 
		{
			//decrypt the buffer and write to STDOUT
			write(STDOUT_FILENO, decryptString(buffer, aes_key, state, length), length-8);
			if (length < BUFF_LEN)
				break;
		}
	}	
}

//starts the application in server mode.Opens a port that keep on listening for an
//incoming connection and on receiving a connection passes it to server
void startInServerMode(int lport, char* dest, int dport, AES_KEY aes_key, struct ctr_state state)
{	
	int listen_socket, client_socket, addr_len;
	struct hostent *host_name_ent;
	struct sockaddr_in app_serv_addr, t_serv_addr;
	struct sockaddr address;
	char buffer[BUFF_LEN];
	int server_socket, length, success;
	
	printf("Starting in Server mode listening at port %d and connecting to destination %s at port %d.\n", lport, dest, dport);	
	
	listen_socket = socket(AF_INET, SOCK_STREAM, 0);
	host_name_ent = gethostbyname(dest);
	
	//populate the details of the app socket on server side
	app_serv_addr.sin_family = AF_INET;
	app_serv_addr.sin_addr.s_addr = htons(INADDR_ANY);
	app_serv_addr.sin_port = htons(lport);
	
	//populate the details of the socket on the server side to which the app connects
	t_serv_addr.sin_family = AF_INET;
	t_serv_addr.sin_port = htons(dport);
	t_serv_addr.sin_addr.s_addr = ((struct in_addr *)(host_name_ent->h_addr))->s_addr;
	
	bind(listen_socket, (struct sockaddr *)&app_serv_addr, sizeof(app_serv_addr));
	
	//support listening only on single connection
	if (listen(listen_socket, 1) < 0) 
	{
		printf("Listen failed.Exiting the program\n");
		exit(1);
	}

	//keeps on listening for incoming connections
	while (1) 
	{
		client_socket = accept(listen_socket, &address, &addr_len);
		
		//if valid incoming connection forward it for processing
		if (client_socket > 0) 
		{			
			//process the incoming command at the server from the application at server end
			//reads the text written by the listening socket of the application
			//decrypts this text and then 
			//encrypts this text and writes it to the application socket at the client end
			server_socket = socket(AF_INET, SOCK_STREAM, 0);
			
			success = connect(server_socket, (struct sockaddr *)&t_serv_addr, sizeof(t_serv_addr));
			
			if (success == -1) 
			{
				printf("Failed to connect to the server port\n");
				exit(1);
			}
			else 
			{
				printf("Connected to the server port\n");
			}
			
			//setting the control flag on both sockets to non-blocking mode
			fcntl(client_socket, F_SETFL, O_NONBLOCK);
			fcntl(server_socket, F_SETFL, O_NONBLOCK);
			
			struct  ctr_state state;
			while (1) 
			{
				while ((length = read(client_socket, buffer, BUFF_LEN)) > 0) 
				{
					write(server_socket, decryptString(buffer, aes_key, state, length), length-8);
					if (length < BUFF_LEN)
						break;
				}
				
				while ((length = read(server_socket, buffer, BUFF_LEN)) > 0) 
				{
					if (length > 0) 
					{
						write(client_socket, encryptString(buffer, aes_key, state, length), length + 8);
					}
				}
				if (length == 0)
					break;
			}
			close(client_socket);
			close(server_socket);
		}
	}
}