/**
 * David Costa <david.costa@ieee.org>, Giuliano Peraz <giuliano.peraz@gmail.com>
 */

/**
 * The server will open a socket and waits a client connection request. At the first
 * message the protocol is started. The server must wait until the socket is over.
 */

#include "../include/common.h"
#include "../include/protocol.h"

struct addrinfo init_hints (void)
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
 * Useful function for retrieving the binary representation of the IP address (IPv4 or IPv6) in
 * order to print it successfully later with a call to inet_ntop().
 */
void *get_in_addr (struct sockaddr *sa)
{
    void *in_addr;
    in_addr = (sa -> sa_family == AF_INET)? (void*)&(((struct sockaddr_in*) sa) -> sin_addr) :
                                            (void*)&(((struct sockaddr_in6*) sa) -> sin6_addr);
    return in_addr;
}

int main (int argc, char **argv)
{
    int sock_fd, con_fd; // listen on sock_fd, new connection on con_fd
    struct addrinfo hints, *servinfo, *it;
    struct sockaddr_storage client_addr; // connector's address information
    socklen_t sin_size;
    int yes = 1, ret_val, recvd_bytes, sent_bytes;
    char str_addr[INET_ADDRSTRLEN]; // for printing human readable IP
    char recv_buffer[BUF_DIM];
    char send_buffer[BUF_DIM];

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
        if ((sock_fd = socket(it -> ai_family, it -> ai_socktype, it -> ai_protocol)) == -1)
        {
            continue;
        }
        if (setsockopt(sock_fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1)
        {
            perror("setsockopt");
            exit(1);
        }
        if (bind(sock_fd, it -> ai_addr, it -> ai_addrlen) == 0)
        {
            break;
        }
        close(sock_fd);
    }
    // If all the elements in the list aren't available to be bound exits with an error
    if (it == NULL) {
        fprintf(stderr, "Server: failed to bind the socket\n");
        return 2;
    }
    freeaddrinfo(servinfo); // Destroy the list
    if (listen(sock_fd, SRV_MAX_CONN) == -1)
    {
        perror("listen");
        exit(1);
    }

    printf("Server: waiting for connections...\n");
    sin_size = sizeof(client_addr);
    while(1) { // main accept() loop
        con_fd = accept(sock_fd, (struct sockaddr *)&client_addr, &sin_size);
        if (con_fd == -1) {
            perror("accept");
            continue;
        }
        inet_ntop(client_addr.ss_family, get_in_addr((struct sockaddr*)&client_addr), str_addr,
                  sizeof(str_addr));
        printf("Server: got connection from %s\n", str_addr);

        // Start the receiving of the client messages
        recvd_bytes = recv(con_fd, &recv_buffer, BUF_DIM, 0);
        if (recvd_bytes == 0)
        {
            printf("Server: Client has closed the connection\n");
            close(con_fd);
            break;
        }
        else if (recvd_bytes == -1)
        {
            perror("recv");
            continue;
        }
    }
    close(sock_fd);

    return 0;
}
