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

#define CLI_FILE_NAME "received.bin"

typedef struct server_state
{
    BIGNUM *Nb; // Server random nonce
    BIGNUM *Na; // Client-created random nonce
    struct sockaddr_in addr;
    uint8_t *session_key, *iv;
    uint8_t *buffer;
    size_t buf_len, key_len, iv_len;
    int acc_skt; // Socket for accepting incoming requests
    int comm_skt; // Socket for communicating
} srv_state;

/**
 * Name of the messages of the protocol. For more information about messages client and server will
 * exvhange see report.pdf.
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
    ss -> buf_len = BUF_DIM * sizeof(uint8_t);
    ss -> key_len = KEY_LEN >> 3;
    ss -> acc_skt = ss -> comm_skt = 0;
}

/**
 * This function permits the user to receive a buffer or size \ref len. This function will call
 * recv() since \ref len hasn't reached or the socket \ref s has been closed. If the recv() returns
 * a value, this is stored into \ref recv_ret_val. In the case of error \ref recv_ret_val will
 * contain -1.
 * \param s The socket to receive data from.
 * \param len A variable that stores the length of the data will theorically arrive from the sender.
 * If \ref recv_ret_val is 0 (socket closed) then this parameter will store the length of the last
 * call to recv, otherwise
 * \returns a pointer to a buffer containing len bytes or NULL in case of error
 */
uint8_t*
receive_buf(int s, ssize_t* len, ssize_t* recv_ret_val)
{
    uint8_t* buf;
    ssize_t recvd = 0;
    ssize_t n = 0;

    if (s < 0 || len == NULL || recv_ret_val == NULL)
    {
        fprintf(stderr, "%s: Input parameter error\n", __func__);
        buf = NULL;
        goto exit_receive_buf;
    }

    buf = malloc(*len);
    if (buf == NULL)
    {
        fprintf(stderr, "%s: Out of memory\n", __func__);
        goto exit_receive_buf;
    }

    while (recvd != *len)
    {
        n = recv(s, buf, *len - recvd, 0);
        *recv_ret_val = n;
        if(n != -1)
        {
            recvd += n;
        }
        else if (n == 0)
        {
            // Connection closed
            *len = n;
        }
        else
        {
            perror("recv");
            free(buf);
            return NULL;
        }
    }
exit_receive_buf:
    return buf;
}

/**
 * This function is in charge of receiving the message msg of the D&G protocol.
 * \param msg the message of the protocol to be received. It could be M1, M2, M3, M4
 * \param ss a pointer to a server_state structure
 * \returns -1 if an error has occourred.
 * \returns 0 if the message is not valid, that is it doesn't contain what expected.
 * \returns 1 if all went as expected.
 */
int
receive_message (msg_name msg, srv_state *ss)
{
    int ret_val = 0;
    ssize_t msg_len, recv_ret_val;

    switch (msg)
    {
        case M1:
            msg_len = M1_SIZE;
            break;

        case M2:
            msg_len = M2_SIZE;
            break;

        case M3:
            msg_len = M3_SIZE;
            break;

        case M4:
            msg_len = M4_SIZE;
            break;

        default:
            fprintf(stderr, "Invalid msg_name");
            ret_val = -1;
            goto exit_receive_message;
            break;
    }
    ss -> buffer = receive_buf(ss -> comm_skt, &msg_len, &recv_ret_val);
    if (ss -> buffer == NULL)
    {
        fprintf(stderr, "Server: Receiving error\n");
        ret_val = -1;
        goto exit_receive_message;
    }
    else if (recv_ret_val == 0)
    {
        fprintf(stderr, "Connection closed\n");
    }

    switch (msg)
    {
        case M1:
            say("Verify M1");
            ret_val = verifymessage_m1(ss -> buffer, msg_len, &(ss -> Na));
            break;

        case M2:
            say("Verify M2");
            ret_val = verifymessage_m2(ss -> buffer, msg_len, ss -> Na, &(ss -> Nb), &(ss -> iv));
            break;

        case M3:
            say("Verify M3");
            ret_val = verifymessage_m3(ss -> buffer, msg_len, ss -> Nb, ss -> session_key,
                                       ss -> iv);
            break;

        case M4:
            say("Verify M");
            ret_val = verifymessage_m4(ss -> buffer, msg_len, ss -> Na, ss -> session_key, ss -> iv);
            break;

        default:
            fprintf(stderr, "Invalid msg_name");
            ret_val = -1;
            break;
    }
    free(ss -> buffer);
exit_receive_message:
    return ret_val;
}

/**
 * This function makes the protocol to start for establishing a session key between server and the
 * client in order to make them to communicate in a secure way thorugh a unsecure channel.
 * \param ss the server state that contains all the needed field for the communication to be started
 * \returns 0 if the protocol has success, -1 otherwise.
 */
int
run_protocol (srv_state *ss)
{
    size_t msg_len;
    uint8_t ret_val = 0, *msg;

    // Receive and verify the first message
    say("Receiving M1");
    ret_val = receive_message(M1, ss);
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
    say("Sending M2");
    msg = create_m2(&msg_len, 'B', ss -> Nb, ss -> Na, &(ss -> iv));
    if (msg == NULL)
    {
        ret_val = -1;
        goto exit_run_protocol;
    }
    if(sendbuf(ss -> comm_skt, msg, msg_len) == 0)
    {
        fprintf(stderr, "Sending buffer error\n");
        ret_val = -1;
        free(ss -> buffer);
        goto exit_run_protocol;
    }
    ss -> session_key = generate_key(ss -> Na, ss -> Nb);

    // Receive and verify the message m3
    say("Receiving M3");
    ret_val = receive_message(M3, ss);
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
    msg = create_m4(&msg_len, ss -> session_key, ss -> Na, ss -> iv);
    ret_val = 0;
    say("Sending M4");
    if (sendbuf(ss -> comm_skt, msg, msg_len) == 0)
    {
        fprintf(stderr, "Sending buffer error\n");
        ret_val = -1;
    }

exit_run_protocol:
    if (msg != NULL) free(msg);
    return ret_val;
}

/**
 * Useful function for retrieving the binary representation of the IP address (IPv4 or IPv6) in
 * order to print it successfully later with a call to inet_ntop().
 */
const void
*get_in_addr (struct sockaddr *sa)
{
    void *in_addr;

    in_addr = (sa -> sa_family == AF_INET)? (void*)&(((struct sockaddr_in*) sa) -> sin_addr) :
                                            (void*)&(((struct sockaddr_in6*) sa) -> sin6_addr);
    return in_addr;
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
wait_connection (int socket_fd)
{
    int comm_skt;
    char str_addr[INET_ADDRSTRLEN]; // for printing human readable IP
    socklen_t sin_size = sizeof(struct sockaddr);
    struct sockaddr client_addr;

    comm_skt = accept(socket_fd, &client_addr, &sin_size);
    if (comm_skt == -1)
    {
        perror("accept");
        return -1;
    }
    inet_ntop(client_addr.sa_family, get_in_addr(&client_addr), str_addr,
                  sizeof(char));
    printf("Server: got connection from %s\n", str_addr);
    return comm_skt;
}

/**
 * This function will destroy the connection on the server socket currenly being used for
 * communicating with a client. It will free Nb, Na, the buffer and the session key and will
 * allocate a new buffer for the server.
 * \param ss the server state structure which contains all the needed communicating informations.
 */
void
close_connection (srv_state *ss)
{
    close(ss -> acc_skt);
    if (ss -> session_key != NULL) free(ss -> session_key);
    if (ss -> Na != NULL) BN_clear_free(ss -> Na);
    if (ss -> Nb != NULL) BN_clear_free(ss -> Nb);
    free(ss -> buffer);
    // New buffer for the server
    ss -> buffer = malloc(BUF_DIM * sizeof(uint8_t));
}

int
main (int argc, char **argv)
{
    srv_state sstate;
    struct addrinfo hints, *servinfo, *it;
    int yes = 1, ret_val;
    FILE *file_received;
    uint8_t *plaintext, *file_buf;
    size_t plain_len, recv_bytes, file_buf_len;

    // Input error checking
    if (argc != 2)
    {
        fprintf(stderr, "Usage: server <file>\n"
                        "Server must receive a file from the client.\n");
        exit(EXIT_FAILURE);
    }

    init_server_state(&sstate);
    hints = init_hints();

    // Get the list of available Internet addresses
    if ((ret_val = getaddrinfo(NULL, SRV_PORT, &hints, &servinfo)) != 0)
    {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(ret_val));
        exit(EXIT_FAILURE);
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
            exit(EXIT_FAILURE);
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
        exit(EXIT_FAILURE);
    }
    freeaddrinfo(servinfo); // Destroy the list
    if (listen(sstate.acc_skt, SRV_MAX_CONN) == -1)
    {
        perror("listen");
        exit(EXIT_FAILURE);
    }
    while(1) {
        printf("Server: waiting for connections...\n");
        if ((sstate.comm_skt = wait_connection(sstate.acc_skt)) == -1)
        {
            perror("wait_connection");
            continue;
        }

        printf("Server: client connected");
        printf("Server: starting D&G protocol");
        ret_val = run_protocol(&sstate);
        if (ret_val != 0)
        {
            fprintf(stderr, "Error during the protocol execution. Abort this connection.");
            close_connection(&sstate);
            continue;
        }
        // Release and reallocate the buffer
        sstate.buffer = calloc(BUF_DIM, sizeof(uint8_t));
        if (sstate.buffer == NULL)
        {
            fprintf(stderr, "Out of memory");
            break;
        }
        // Try to create the file which will be written
        file_received = fopen(argv[1], "w");
        if (file_received == NULL)
        {
            perror("fopen");
            fprintf(stderr, "Can't open the file client sent. Exiting.\n");
            close_connection(&sstate);
        }
        say("Waiting for file");
        // Waiting for the client to be sent an encrypted file
        file_buf_len = sizeof(uint8_t) * BUF_DIM;
        recv_bytes = 0;
        file_buf = malloc(file_buf_len);
        if (file_buf == NULL)
        {
            fprintf(stderr, "Out of memory");
            break;
        }
        do
        {
            ret_val = recv(sstate.comm_skt, sstate.buffer, BUF_DIM, 0);
            if (ret_val == -1)
            {
                fprintf(stderr, "Receiving file error\n");
                free(file_buf);
                close_connection(&sstate);
                break;
            }
            if (recv_bytes + ret_val > file_buf_len)
            {
                file_buf = realloc(file_buf, recv_bytes + ret_val);
                file_buf_len = recv_bytes;
            }
            memcpy(file_buf + recv_bytes, sstate.buffer, ret_val);
            recv_bytes += ret_val;
        } while (ret_val > 0);
        say("Decrypting received file");
        plaintext = do_aes256_decrypt(file_buf, recv_bytes, sstate.session_key, sstate.iv,
                                      &plain_len);
        if (plaintext == NULL)
        {
            fprintf(stderr, "Decrypting ciphertext failed.\n");
            fprintf(stderr, "Abort the connection\n");
            close_connection(&sstate);
            fclose(file_received);
            continue;
        }
        say("Writing decrypted file");
        if (fwrite(plaintext, sizeof(uint8_t), plain_len, file_received) < plain_len)
        {
            fprintf(stderr, "Writing file failed.\n");
            fprintf(stderr, "Abort the connection.\n");
            close_connection(&sstate);
        }
        fclose(file_received);
    }
    close(sstate.acc_skt);
    close(sstate.comm_skt);
    free(sstate.buffer);

    return 0;
}
