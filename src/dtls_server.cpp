#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/opensslv.h>

int generate_cookie(SSL *ssl, unsigned char *cookie, unsigned int *cookie_len)
{
    memcpy(cookie,  "cookie", 6);
    *cookie_len = 6;

    return 1;
}

int verify_cookie(SSL *ssl, const unsigned char *cookie, unsigned int cookie_len)
{
    return 1;
}

int dtls_verify_callback (int ok, X509_STORE_CTX *ctx) {
    /* This function should ask the user
     * if he trusts the received certificate.
     * Here we always trust.
     */
    return 1;
}

int main() {
    char buff[FILENAME_MAX];
    getcwd(buff, FILENAME_MAX);

    union {
        struct sockaddr_storage ss;
        struct sockaddr_in s4;
        struct sockaddr_in6 s6;
    } client_addr;

    struct sockaddr_in server_addr;

    const int on = 1, off = 0;

    memset(&server_addr, 0, sizeof(server_addr));
    memset(&client_addr, 0, sizeof(client_addr));

    int res;

    SSL *ssl;
    BIO *bio;
    int sock;
    struct timeval timeout;

    SSL_CTX *ctx = SSL_CTX_new(DTLS_server_method());
    SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_OFF);
/*
    if(!SSL_CTX_use_certificate_file(ctx, "certs/cert.crt", SSL_FILETYPE_PEM))
    {
        perror("cert");
        exit(EXIT_FAILURE);
    }

    if(!SSL_CTX_use_PrivateKey_file(ctx, "certs/key.key", SSL_FILETYPE_PEM))
    {
        perror("key");
        exit(EXIT_FAILURE);
    }
*/
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_CLIENT_ONCE, dtls_verify_callback);
    SSL_CTX_set_read_ahead(ctx, 1);
    SSL_CTX_set_cookie_generate_cb(ctx, generate_cookie);
    SSL_CTX_set_cookie_verify_cb(ctx, &verify_cookie);

    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(1114);

    if((sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
    {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    if(setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (const char*) &on, (socklen_t) sizeof(on)) < 0)
    {
        perror("set reuse address");
        exit(EXIT_FAILURE);
    }

    if(setsockopt(sock, SOL_SOCKET, SO_REUSEPORT, (const char*) &on, (socklen_t) sizeof(on)) < 0)
    {
        perror("set reuse port");
        exit(EXIT_FAILURE);
    }

    if(bind(sock, (const struct sockaddr *) &server_addr, sizeof(server_addr)) < 0)
    {
        perror("bind");
        exit(EXIT_FAILURE);
    }

    memset(&client_addr, 0, sizeof(struct sockaddr_storage));

    /* Create BIO */
    bio = BIO_new_dgram(sock, BIO_NOCLOSE);

    /* Set and activate timeouts */
    timeout.tv_sec = 5;
    timeout.tv_usec = 0;
    BIO_ctrl(bio, BIO_CTRL_DGRAM_SET_RECV_TIMEOUT, 0, &timeout);

    ssl = SSL_new(ctx);

    SSL_set_bio(ssl, bio, bio);
    SSL_set_options(ssl, SSL_OP_COOKIE_EXCHANGE);

 //   if(!SSL_set_fd(ssl, sock))
//    {
//        perror("set fd");
//        exit(EXIT_FAILURE);
//    }

res = 0;
while(res <= 0)
{
    res = DTLSv1_listen(ssl, (BIO_ADDR *) &client_addr);
    if(res < 0)
    {
        perror("dtls listen");
        exit(EXIT_FAILURE);
    }
}

    SSL_accept(ssl);

    printf("Hello, World!\n");
    return 0;
}
