/**
 * David Costa <david.costa@ieee.org>, Giuliano Peraz <giuliano.peraz@gmail.com>
 */

/**
 * The server will open a socket and waits a client connection request. At the first
 * message the protocol is started. The server must wait until the socket is over.
 */

#include "../include/common.h"
#include "../include/protocol.h"
#include "../include/utils.h"

typedef struct server_state
{
    BIGNUM *Nb; // Server random nonce
    BIGNUM *Na; // Client-created random nonce
    struct sockaddr_in addr;
    uint8_t *session_key;
    uint8_t *buffer;
    int acc_skt; // Socket for accepting incoming requests
    int comm_skt; // Socket for communicating
} srv_state;

/**
 * Name of the messages of the protocol. For more information see report.pdf.
 */
typedef enum {
    M1, M2, M3, M4
} msg_name;

/**
 * This function is in charge of initializing the struct addrinfo with the hints for the operating
 * system when querying a port for the server.
 * \returns a struct addrinfo filled with the hints in order to query the operating system for
 * the socket to make client to connect to.
 */
struct addrinfo
init_hints (void)
{
    struct addrinfo hints;
    // Setup the socket for the server to listen to incoming connections
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE; // use my IP
    hints.ai_protocol = 0;
    hints.ai_addrlen = 0;
    hints.ai_addr = NULL;
    hints.ai_canonname = NULL;
    hints.ai_next = NULL;

    return hints;
}


/**
 * This function will initialize the server state to a known state: all pointers to NULL, integers
 * to 0 and it allocates a buffer of `#BUF_DIM` bytes.
 * \param ss a pointer to a server state structure. If it is NULL the function will print an error
 * and returns immediately.
 */
void
init_server_state (srv_state *ss)
{
    if (ss == NULL)
    {
        fprintf(stderr, "%s: Server state pointer can't be NULL", __func__);
        return;
    }
    ss -> Nb = NULL;
    ss -> session_key = NULL;
    ss -> buffer = malloc(BUF_DIM * sizeof(uint8_t));
    acc_skt = comm_skt = 0;
}

/**
 * This function is in charge of receiving the message msg of the D&G protocol.
 * \param msg the message of the protocol to be received. It could be M1, M2, M3, M4
 * \param ss a pointer to a server_state structure
 * \returns -1 if an error has occourred.
 * \returns 0 if the message is not valid, that is it doesn't contain what expected.
 * \returns 1 if all has gone as expected.
 */
int
receive_message (msg_name msg, srv_state *ss)
{
    int ret_val = 0;

    ret_val = recv(ss -> comm_skt, ss -> buffer, BUF_DIM, 0);
    if (ret_val == 0)
    {
        printf("Server: Client has closed the connection\n");
        ret_val = -1;
        goto exit_run_protocol;
    }
    else if (ret_val == -1)
    {
        perror("recv");
        goto exit_run_protocol;
    }

    switch(msg)
    {
        case M1:
            ret_val = verifymessage_m1(ss -> buffer);
            break;

        case M2:
            ret_val = verifymessage_m2(ss -> buffer);
            break;

        case M3:
            ret_val = verifymessage_m3(ss -> buffer);
            break;

        case M4:
            ret_val = verifymessage_m4(ss -> buffer);
            break;

        default:
            fprintf(stderr, "Invalid msg_name");
            ret_val = -1;
            break;
    }
exit_receive_message:
    return ret_val;
}

/**
 * This function makes the protocol to begin for establishing a session key between server and the
 * client in order to make them to communicate in a secure way thorugh a unsecure channel.
 * \param ss the server state that contains all the needed field for the communication to be started
 * \returns 0 if the protocol has success, -1 otherwise.
 */
int
run_protocol (srv_state *ss)
{
    uint64_t recv_bytes, msg_len;
    uint8_t ret_val = 0, *msg, *tmp;
    msg_name msg_name;

    // Receive and verify the first message
    ret_val = receive_message(msg_name.M1, ss);
    if (ret_val == -1)
    {
        perror("receive_message");
        goto exit_run_protocol;
    }
    else if (ret_val == 0)
    {
        fprintf(stderr, "Error validating message number 1");
        ret_val = -1;
        goto exit_run_protocol;
    }

    // Create and send message m2 and the key
    ss -> Nb = generate_random_nonce();
    msg = create_m2(&msg_len, 1, ss -> Nb);
    sendbuf(ss -> comm_skt, msg, msg_len); // It exits the program on error
    ss -> key = generate_key(ss -> Na, ss -> Nb)
    free(msg);

    // Receive and verify the message m3
    ret_val = receive_message(msg_name.M3, ss);
    if (ret_val == -1)
    {
        perror("receive_message");
        goto exit_run_protocol;
    }
    else if (ret_val == 0)
    {
        fprintf(stderr, "Error validating message number 3");
        ret_val = -1;
        goto exit_run_protocol;
    }

    // The last message of the protocol
    msg = create_m4(&msg_len, ss -> session_key, ss -> Na);
    sendbuf(ss -> comm_skt, msg, msg_len); // It exits the program on error
    ret_val = 0;

exit_run_protocol:
    if (msg != NULL) free(msg);
    return ret_val;
}

/**
 * It makes the server to wait an incoming connection on the socket passed by parameter.
 * After a client is connected, the function will return the connection socket for the communication
 * to begin.
 * \param socket_fd the socket file descriptor where the server has to wait a connection to.
 * \returns the file descriptor for the communication socket with the client.
 * \returns -1 if an error has occourred and sets errno.
 */
int
wait_connection (int socket_fd, struct sockaddr *addr)
{
    int comm_skt;
    char str_addr[INET_ADDRSTRLEN]; // for printing human readable IP
    socklen_t sin_size = sizeof(sockaddr_storage);
    struct sockaddr_storage client_addr;
    comm_skt = accept(socket_fd, addr, &sin_size);
    if (comm_skt == -1)
    {
        perror("accept");
        return -1;
    }
    inet_ntop(client_addr.ss_family, get_in_addr(addr, str_addr,
                  sizeof(char));
    printf("Server: got connection from %s\n", str_addr);
    return comm_skt;
}

/**
 * Useful function for retrieving the binary representation of the IP address (IPv4 or IPv6) in
 * order to print it successfully later with a call to inet_ntop().
 */
void
*get_in_addr (struct sockaddr *sa)
{
    void *in_addr;
    in_addr = (sa -> sa_family == AF_INET)? (void*)&(((struct sockaddr_in*) sa) -> sin_addr) :
                                            (void*)&(((struct sockaddr_in6*) sa) -> sin6_addr);
    return in_addr;
}

int
main (int argc, char **argv)
{
    srv_state sstate;
    int sock_fd, con_fd; // listen on sock_fd, new connection on con_fd
    struct addrinfo hints, *servinfo, *it;
    struct sockaddr_storage client_addr; // connector's address information
    int yes = 1, ret_val, i = 0;
    char str_addr[INET_ADDRSTRLEN]; // for printing human readable IP

    init_server_state(&sstate);
    // Initializing struct for binding
    hints = init_hints();

    // Get the list of available Internet addresses
    if ((ret_val = getaddrinfo(NULL, SRV_PORT, &hints, &servinfo)) != 0)
    {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(ret_val));
        return 1;
    }
    // loop through all the results of the list and bind to the first available
    for (it = servinfo; it != NULL; it = it -> ai_next)
    {
        if ((sstate.acc_skt = socket(it -> ai_family, it -> ai_socktype, it -> ai_protocol)) == -1)
        {
            continue;
        }
        if (setsockopt(sstate.acc_skt, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1)
        {
            perror("setsockopt");
            exit(1);
        }
        if (bind(sstate.acc_skt, it -> ai_addr, it -> ai_addrlen) == 0)
        {
            break;
        }
        close(sstate.acc_skt);
    }
    // If all the elements in the list aren't available to be bound exits with an error
    if (it == NULL) {
        fprintf(stderr, "Server: failed to bind the socket\n");
        return 2;
    }
    freeaddrinfo(servinfo); // Destroy the list
    if (listen(sstate.acc_skt, SRV_MAX_CONN) == -1)
    {
        perror("listen");
        exit(1);
    }
    while(1) {
        printf("Server: waiting for connections...\n");
        if (sstate.comm_skt = wait_connection(sstate.acc_skt) == -1)
        {
            perror("wait_connection");
            continue;
        }

        printf("Server: client connected");
        printf("Server: starting D&G protocol");
        ret_val = run_protocol(sstate);

        // TODO: now we wait here until the client doesn't send something creepy
    }
    close(sstate.acc_skt);
    close(sstate.comm_skt);
    free(sstate.buffer);

    return 0;
}
