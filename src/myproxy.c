#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <time.h>
#include <netdb.h>
#include <errno.h>
#include <netinet/in.h>
#include <signal.h>
#include <sys/wait.h>

#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define BUFFER_SIZE 8192
#define MAX_FORBIDDEN_SITES 1000
#define MAX_URL_LEN 512

// HTTP Error Codes
#define REQUEST_OK 200
#define BAD_REQUEST 400
#define FORBIDDEN 403
#define NOT_IMPLEMENTED 501
#define BAD_GATEWAY 502
#define GATEWAY_TIMEOUT 504

typedef struct {
	size_t len;
	char sites[MAX_FORBIDDEN_SITES][MAX_URL_LEN];
} forbidden_sites_list;

// Function Prototypes
void handle_client(int client_fd, struct sockaddr_in client_addr, forbidden_sites_list *acl, FILE *log_fd, SSL_CTX *ctx);
void get_timestamp(char *buf);
void log_event(FILE *log_fd, char *ip, char *req_line, int status, long size);

// --- HELPER FUNCTIONS ---
void get_timestamp(char *buf) {
	struct timespec ts;
	clock_gettime(CLOCK_REALTIME, &ts);
	struct tm *tm = gmtime(&ts.tv_sec);
	strftime(buf, 30, "%Y-%m-%dT%H:%M:%S", tm);
	sprintf(buf + strlen(buf), ".%03ldZ", ts.tv_nsec / 1000000);
}

void log_event(FILE *log_fd, char *ip, char *req_line, int status, long size) {
	char time_buf[64];
	get_timestamp(time_buf);
	fprintf(log_fd, "%s %s \"%s\" %d %ld\n", time_buf, ip, req_line, status, size);
	fflush(log_fd);
}

void send_error(int client_fd, int status, char *msg, FILE *log_fd, char *ip, char *req_line) {
	char resp[512];
	int len = sprintf(resp, "HTTP/1.1 %d %s\r\nConnection: close\r\n\r\n", status, msg);
	write(client_fd, resp, len);
	log_event(log_fd, ip, req_line, status, len);
}

// --- CORE LOGIC ---
int main(int argc, char *argv[]) {
	int opt, port = 0;
	char *forbidden_file = NULL, *log_file = NULL;

	while ((opt = getopt(argc, argv, "p:a:l:")) != -1) {
		switch (opt) {
			case 'p':
				port = atoi(optarg);
				break;
			case 'a':
				forbidden_file = optarg;
				break;
			case 'l':
				log_file = optarg;
				break;
			default:
				return EXIT_FAILURE;
		}
	}

	if (port == 0 || forbidden_file == NULL || log_file == NULL) {
		fprintf(stderr, "Usage: %s -p port -a forbidden_file -l log_file\n", argv[0]);
		return EXIT_FAILURE;
	}

	// Initialize SSL
	SSL_library_init();
	SSL_load_error_strings();
	OpenSSL_add_all_algorithms();
	SSL_CTX *ctx = SSL_CTX_new(SSLv23_client_method());

	// Load Forbidden Sites
	forbidden_sites_list acl;
	acl.len = 0;
	FILE *f_acl = fopen(forbidden_file, "r");
	if (f_acl) {
		char line[MAX_URL_LEN];
		while (fgets(line, sizeof(line), f_acl) && acl.len < MAX_FORBIDDEN_SITES) {
			if (line[0] == '#' || line[0] == '\n')
				continue;
			line[strcspn(line, "\r\n")] = 0;
			strncpy(acl.sites[acl.len++], line, MAX_URL_LEN);
		}
		fclose(f_acl);
	}

	FILE *log_fd = fopen(log_file, "a");

	int server_fd = socket(AF_INET, SOCK_STREAM, 0);
	int optval = 1;
	setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));

	struct sockaddr_in addr = { .sin_family = AF_INET, .sin_addr.s_addr = INADDR_ANY, .sin_port = htons(port) };
	bind(server_fd, (struct sockaddr *)&addr, sizeof(addr));
	listen(server_fd, 50);

	// Prevent zombie processes
	signal(SIGCHLD, SIG_IGN);

	printf("Proxy listening on port %d\n", port);

	while (1) {
		struct sockaddr_in client_addr;
		socklen_t client_len = sizeof(client_addr);
		int client_fd = accept(server_fd, (struct sockaddr *)&client_addr, &client_len);

		if (fork() == 0) { // Child Process
			close(server_fd);
			handle_client(client_fd, client_addr, &acl, log_fd, ctx);
			exit(0);
		}
		close(client_fd);
	}

	SSL_CTX_free(ctx);
	return 0;
}

void handle_client(int client_fd, struct sockaddr_in client_addr, forbidden_sites_list *acl, FILE *log_fd, SSL_CTX *ctx) {
	char buffer[BUFFER_SIZE], method[16], url[MAX_URL_LEN], protocol[16];
	char host[MAX_URL_LEN], path[MAX_URL_LEN], port_str[8] = "443";
	char *client_ip = inet_ntoa(client_addr.sin_addr);

	int n = read(client_fd, buffer, BUFFER_SIZE - 1);
	if (n <= 0) return;
	buffer[n] = '\0';

	char first_line[MAX_URL_LEN];
	sscanf(buffer, "%[^\r\n]", first_line);

	// 1. Parse Method & URL
	if (sscanf(first_line, "%s %s %s", method, url, protocol) < 3) {
		send_error(client_fd, BAD_REQUEST, "Bad Request", log_fd, client_ip, first_line);
		return;
	}

	// Requirement: Support only GET and HEAD
	if (strcmp(method, "GET") != 0 && strcmp(method, "HEAD") != 0) {
		send_error(client_fd, NOT_IMPLEMENTED, "Not Implemented", log_fd, client_ip, first_line);
		return;
	}

	// 2. Parse Host and Path from URL (e.g., http://example.com:80/index.html)
	char *host_start = strstr(url, "://");
	if (host_start) {
		host_start += 3;
		char *path_start = strchr(host_start, '/');
		if (path_start) {
			strcpy(path, path_start);
			*path_start = '\0';
		} else {
			strcpy(path, "/");
		}

		char *port_ptr = strchr(host_start, ':');
		if (port_ptr) {
			strcpy(port_str, port_ptr + 1);
			*port_ptr = '\0';
		}
		strcpy(host, host_start);
	} else {
		send_error(client_fd, BAD_REQUEST, "Absolute URL Required", log_fd, client_ip, first_line);
		return;
	}

	// 3. ACL Check
	for (size_t i = 0; i < acl->len; i++) {
		if (strstr(host, acl->sites[i])) {
			send_error(client_fd, FORBIDDEN, "Forbidden", log_fd, client_ip, first_line);
			return;
		}
	}

	// 4. Connect to Destination Server
	struct addrinfo hints = { .ai_family = AF_INET, .ai_socktype = SOCK_STREAM }, *res;
	if (getaddrinfo(host, port_str, &hints, &res) != 0) {
		send_error(client_fd, BAD_GATEWAY, "Bad Gateway", log_fd, client_ip, first_line);
		return;
	}

	int server_sock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
	if (connect(server_sock, res->ai_addr, res->ai_addrlen) < 0) {
		send_error(client_fd, GATEWAY_TIMEOUT, "Gateway Timeout", log_fd, client_ip, first_line);
		freeaddrinfo(res);
		return;
	}
	freeaddrinfo(res);

	// 5. SSL Handshake with Server
	SSL *ssl = SSL_new(ctx);
	SSL_set_fd(ssl, server_sock);
	if (SSL_connect(ssl) <= 0) {
		send_error(client_fd, BAD_GATEWAY, "SSL Handshake Failed", log_fd, client_ip, first_line);
		SSL_free(ssl);
		close(server_sock);
		return;
	}

	// 6. Transform Request and Add X-Forwarded-For
	// We rebuild the headers to change the path and add the proxy header
	char new_request[BUFFER_SIZE];
	int req_len = sprintf(new_request, "%s %s %s\r\nHost: %s\r\nX-Forwarded-For: %s, 127.0.0.1\r\nConnection: close\r\n\r\n", method, path, protocol, host, client_ip);

	SSL_write(ssl, new_request, req_len);

	// 7. Relay Response back to Client
	long total_bytes = 0;
	while ((n = SSL_read(ssl, buffer, sizeof(buffer))) > 0) {
		write(client_fd, buffer, n);
		total_bytes += n;
	}

	log_event(log_fd, client_ip, first_line, REQUEST_OK, total_bytes);

	// Cleanup
	SSL_shutdown(ssl);
	SSL_free(ssl);
	close(server_sock);
	close(client_fd);
}
