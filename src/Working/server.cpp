/*
Usefull link:
https://wiki.openssl.org/index.php/SSL/TLS_Client


*/

#include <stdio.h>
#include <sys/types.h>
//#include <sys/socket.h>
//#include <sys/time.h>
//#include <netinet/in.h>
//#include <arpa/inet.h>
#include <stdio.h>
//#include <unistd.h>
#include <stdlib.h>
#include <string.h>
//#include <pthread.h>

#include <winsock2.h>
#include <Ws2tcpip.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/opensslv.h>

#define BUFFER_SIZE          (1<<16)

int generate_cookie(SSL *ssl, unsigned char *cookie, unsigned int *cookie_len)
{
	memcpy(cookie, "cookie", 6);
	*cookie_len = 6;

	return 1;
}

int verify_cookie(SSL *ssl, const unsigned char *cookie, unsigned int cookie_len)
{
	return 1;
}

int dtls_verify_callback(int ok, X509_STORE_CTX *ctx) {
	/* This function should ask the user
	 * if he trusts the received certificate.
	 * Here we always trust.
	 */
	return 1;
}

int main() {
	//char buff[FILENAME_MAX];
	//getcwd(buff, FILENAME_MAX);
	char buf[BUFFER_SIZE];

	WSADATA wsaData;
	WSAStartup(MAKEWORD(2, 2), &wsaData);


	union {
		struct sockaddr_storage ss;
		struct sockaddr_in s4;
		struct sockaddr_in6 s6;
	} client_addr;

	struct sockaddr_in server_addr;

	const int on = 1, off = 0;

	memset(&server_addr, 0, sizeof(server_addr));
	memset(&client_addr, 0, sizeof(client_addr));

	int ret;

	SSL *ssl;
	BIO *bio;
	int sock;


	struct timeval timeout;

	SSL_CTX *ctx = SSL_CTX_new(DTLS_server_method());
	//SSL_CTX_set_cipher_list(ctx, "ALL:NULL:eNULL:aNULL");
	SSL_CTX_set_cipher_list(ctx, "ALL:!ADH:!RC4:+HIGH:+MEDIUM:-LOW:-SSLv2:-SSLv3:-EXP");
	//SSL_CTX_set_cipher_list(ctx, "EECDH+AESGCM:EDH+AESGCM:AES256+EECDH:AES256+EDH");
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

	if (!SSL_CTX_use_certificate_file(ctx, "certs/server-cert.pem", SSL_FILETYPE_PEM))
		printf("\nERROR: no certificate found!");

	if (!SSL_CTX_use_PrivateKey_file(ctx, "certs/server-key.pem", SSL_FILETYPE_PEM))
		printf("\nERROR: no private key found!");

	if (!SSL_CTX_check_private_key(ctx))
		printf("\nERROR: invalid private key!");


	SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_CLIENT_ONCE, dtls_verify_callback);
	SSL_CTX_set_read_ahead(ctx, 1);
	SSL_CTX_set_cookie_generate_cb(ctx, generate_cookie);
	SSL_CTX_set_cookie_verify_cb(ctx, &verify_cookie);

	server_addr.sin_family = AF_INET;
	server_addr.sin_addr.s_addr = INADDR_ANY;
	//server_addr.sin_port = htons(1114);
	server_addr.sin_port = htons(8080);


	/*
	From: https://github.com/openssl/openssl/issues/7282
	The warning is formally warranted, but the implicit casts are safe to ignore. Quoting post from 2008 "Windows SOCKET is a 
	handler to kernel object and as such constitutes an offset in per-process handle table. As this table can accommodate not 
	more than 2^24 entries, it's always safe to cast/truncate SOCKET to 32-bit value and back. Even on 64-bit Windows." The 
	reason for why the warning is not addressed is because it's argued that it's better to not mask the warning in wait for 
	moment when it's appropriate to address it, between major releases. 
	*/

	if ((sock = (int)socket(AF_INET, SOCK_DGRAM, 0)) < 0)
	{
		perror("socket");
		exit(EXIT_FAILURE);
	}

	if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (const char*)&on, (socklen_t) sizeof(on)) < 0)
	{
		perror("set reuse address");
		exit(EXIT_FAILURE);
	}

	//if (setsockopt(sock, SOL_SOCKET, SO_REUSEPORT, (const char*)&on, (socklen_t) sizeof(on)) < 0)
	//{
	//	perror("set reuse port");
	//	exit(EXIT_FAILURE);
	//}

	if (bind(sock, (const struct sockaddr *) &server_addr, sizeof(server_addr)) < 0)
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

	//if(!SSL_set_fd(ssl, sock))
 //   {
 //       perror("set fd");
 //       exit(EXIT_FAILURE);
 //   }

	//res = 0;
	//while (res <= 0)
	//{
	//	res = DTLSv1_listen(ssl, (BIO_ADDR *)&client_addr);
	//	if (res < 0)
	//	{
	//		perror("dtls listen");
	//		exit(EXIT_FAILURE);
	//	}
	//}

	while (DTLSv1_listen(ssl, (BIO_ADDR *)&client_addr) <= 0);


	/* Set new fd and set BIO to connected */
	//BIO_set_fd(SSL_get_rbio(ssl), sock, BIO_NOCLOSE);
	//BIO_ctrl(SSL_get_rbio(ssl), BIO_CTRL_DGRAM_SET_CONNECTED, 0, &client_addr.ss);
	

//	SSL_accept(ssl);

	/* Finish handshake */
	do { ret = SSL_accept(ssl); } while (ret == 0);
	if (ret < 0) {
		perror("SSL_accept");
		printf("%s\n", ERR_error_string(ERR_get_error(), buf));
		goto cleanup;
	}

	printf("Hello, World!\n");

	//closesocket(sock);
	//WSACleanup();

cleanup:
	closesocket(sock);
	SSL_free(ssl);
	WSACleanup();




	return 0;
}













#if 0
#define _WINSOCK_DEPRECATED_NO_WARNINGS

#include <iostream>
#include <cstring>
#include <cstdio>
#include <winsock2.h>
#include <Ws2tcpip.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>


// Create a socket and return the file descriptor
int create_socket()
{
	int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	if (sockfd < 0) {
		perror("Failed to create socket");
		exit(EXIT_FAILURE);
	}

	return sockfd;
}

// Initialize OpenSSL and create a DTLS context
SSL_CTX* initialize_dtls()
{
	// Initialize OpenSSL
	SSL_library_init();
	SSL_load_error_strings();
	OpenSSL_add_all_algorithms();

	const SSL_METHOD *method = DTLS_client_method();

	// Create a DTLS context
	SSL_CTX *ctx = SSL_CTX_new(method);

	// Set the DTLS options
	SSL_CTX_set_options(ctx, SSL_OP_NO_QUERY_MTU);

	// Set the cipher list for the DTLS context
	SSL_CTX_set_cipher_list(ctx, "EECDH+AESGCM:EDH+AESGCM:AES256+EECDH:AES256+EDH");

	return ctx;
}

// Create an SSL object and perform the DTLS handshake
SSL* create_ssl_object(SSL_CTX* ctx, BIO* bio, struct sockaddr_in* dest_addr, int fd)
{
	// Create an SSL object
	SSL *ssl = SSL_new(ctx);

	connect(fd, (struct sockaddr *) &dest_addr, sizeof(struct sockaddr_in));
	BIO_ctrl(bio, BIO_CTRL_DGRAM_SET_CONNECTED, 0, &dest_addr->sin_addr);

	// Set the DTLS BIO for the SSL object
	SSL_set_bio(ssl, bio, bio);

	// Perform the DTLS handshake
	int ret = SSL_connect(ssl);
	if (ret != 1) {
		fprintf(stderr, "DTLS handshake failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
		exit(EXIT_FAILURE);
	}

	return ssl;
}

// Create an RTP packet and send it over DTLS
void send_rtp_packet(SSL* ssl, BIO* bio, struct sockaddr_in* dest_addr, int seq_num, int timestamp, char* ssrc, const char* payload_data, int payload_len)
{
	// Set the destination address for the DTLS BIO
	BIO_dgram_set_peer(bio, dest_addr);

	// RTP packet data
	char rtp_packet[1024];
	int rtp_packet_len = 1024;

	// Set the RTP header fields
	rtp_packet[0] = 0x80; // Version 2, Padding off, Extension off
	rtp_packet[1] = 96; // Payload type 96 (DynamicRTP-Type-96)
	rtp_packet[2] = seq_num >> 8; // Sequence number (high byte)
	rtp_packet[3] = seq_num & 0xFF; // Sequence number (low byte)
	rtp_packet[4] = timestamp >> 24; // Timestamp (most significant byte)
	rtp_packet[5] = (timestamp >> 16) & 0xFF; // Timestamp
	rtp_packet[6] = (timestamp >> 8) & 0xFF; // Timestamp
	rtp_packet[7] = timestamp & 0xFF; // Timestamp (least significant byte)
	memcpy(rtp_packet + 8, ssrc, 4); // SSRC
	memcpy(rtp_packet + 12, payload_data, payload_len); // Payload data

	// Set the RTP packet length
	rtp_packet_len = 12 + payload_len;

	// Send the RTP packet over DTLS
	int ret = SSL_write(ssl, rtp_packet, rtp_packet_len);
	if (ret <= 0) {
		// Send failed, handle the error
	}
}


int main(int argc, char *argv[])
{
	WSADATA wsaData;
	WSAStartup(MAKEWORD(2, 2), &wsaData);
	// Set the number of calls to send
	int num_calls = 5;

	// Create a socket
	int sockfd = create_socket();

	// Set the destination address
	struct sockaddr_in dest_addr;
	memset(&dest_addr, 0, sizeof(dest_addr));
	dest_addr.sin_family = AF_INET;
	dest_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
	dest_addr.sin_port = 8080;

	// Initialize DTLS
	SSL_CTX* ctx = initialize_dtls();

	// Create a DTLS BIO
	BIO* bio = BIO_new_dgram(sockfd, BIO_NOCLOSE);

	// Create an SSL object and perform the DTLS handshake
	SSL* ssl = create_ssl_object(ctx, bio, &dest_addr, sockfd);

	// Loop through the calls
	for (int i = 0; i < num_calls; i++) {
		// Set the sequence number and timestamp for the RTP packet
		int seq_num = (i + 1) * 100;
		int timestamp = (i + 1) * 1000;

		// Set the SSRC for the RTP packet
		char ssrc[4] = { 0xDE, 0xF0, 0x12, 0x34 };

		// Set the payload data for the RTP packet
		const char* payload_data = "RTP payload data";
		int payload_len = strlen(payload_data);

		// Send the RTP packet over DTLS
		send_rtp_packet(ssl, bio, &dest_addr, seq_num, timestamp, ssrc, payload_data, payload_len);
	}

	// Clean up the resources used by DTLS
	SSL_free(ssl);
	SSL_CTX_free(ctx);
	BIO_free(bio);
	ERR_free_strings();
	EVP_cleanup();

	// Close the socket
	closesocket(sockfd);

	WSACleanup();

}

#endif
