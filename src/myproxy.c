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

#define BUFFER_SIZE 16384
#define MAX_FORBIDDEN_SITES 1000
#define MAX_URL_LEN 1024

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

void get_timestamp(char *buf);
void log_event(const char *log_file_path, char *ip, char *req_line, int status, long size);
void send_error(int client_fd, int status, char *msg, const char *log_file, char *ip, char *req_line);
void handle_client(int client_fd, struct sockaddr_in client_addr, forbidden_sites_list *acl, const char *log_file, SSL_CTX *ctx);

void get_timestamp(char *buf) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    struct tm *tm = gmtime(&ts.tv_sec);
    strftime(buf, 30, "%Y-%m-%dT%H:%M:%S", tm);
    sprintf(buf + strlen(buf), ".%03ldZ", ts.tv_nsec / 1000000);
}

void log_event(const char *log_file_path, char *ip, char *req_line, int status, long size) {
    FILE *f = fopen(log_file_path, "a"); // Append mode
    if (!f) return;

    char time_buf[64];
    get_timestamp(time_buf);
    fprintf(f, "%s %s \"%s\" %d %ld\n", time_buf, ip, req_line, status, size);
    fclose(f);
}

void send_error(int client_fd, int status, char *msg, const char *log_file, char *ip, char *req_line) {
    char resp[512];
    int len = sprintf(resp, "HTTP/1.1 %d %s\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", status, msg);
    write(client_fd, resp, len);
    log_event(log_file, ip, req_line, status, 0); // Use the correct string path
}

// --- CORE HANDLER ---
void handle_client(int client_fd, struct sockaddr_in client_addr, forbidden_sites_list *acl, const char *log_file, SSL_CTX *ctx) {
    char buffer[BUFFER_SIZE];
    char *client_ip = inet_ntoa(client_addr.sin_addr);

	int n = recv(client_fd, buffer, BUFFER_SIZE - 1, 0);
    if (n <= 0) return;
    buffer[n] = '\0';

    char method[16], url[MAX_URL_LEN], protocol[16], first_line[MAX_URL_LEN];
    sscanf(buffer, "%[^\r\n]", first_line);

    if (sscanf(first_line, "%s %s %s", method, url, protocol) < 3) {
        send_error(client_fd, BAD_REQUEST, "Bad Request", log_file, client_ip, first_line);
        return;
    }

    if (strcmp(method, "GET") != 0 && strcmp(method, "HEAD") != 0) {
        send_error(client_fd, NOT_IMPLEMENTED, "Not Implemented", log_file, client_ip, first_line);
        return;
    }

    char host[MAX_URL_LEN] = {0}, path[MAX_URL_LEN] = {0}, port_str[8] = "443";
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
        send_error(client_fd, BAD_REQUEST, "Absolute URL Required", log_file, client_ip, first_line);
        return;
    }

    for (size_t i = 0; i < acl->len; i++) {
        if (strstr(host, acl->sites[i])) {
            send_error(client_fd, FORBIDDEN, "Forbidden", log_file, client_ip, first_line);
            return;
        }
    }

    struct addrinfo hints = { .ai_family = AF_INET, .ai_socktype = SOCK_STREAM }, *res;
    if (getaddrinfo(host, port_str, &hints, &res) != 0) {
        send_error(client_fd, BAD_GATEWAY, "Domain cannot be resolved", log_file, client_ip, first_line);
        return;
    }

    int server_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (connect(server_sock, res->ai_addr, res->ai_addrlen) < 0) {
        send_error(client_fd, GATEWAY_TIMEOUT, "Cannot connect to server", log_file, client_ip, first_line);
        freeaddrinfo(res);
        return;
    }
    freeaddrinfo(res);

    SSL *ssl = SSL_new(ctx);
    SSL_set_fd(ssl, server_sock);
    if (SSL_connect(ssl) <= 0) {
        send_error(client_fd, BAD_GATEWAY, "SSL Handshake Failed", log_file, client_ip, first_line);
        SSL_free(ssl); close(server_sock);
        return;
    }

    char new_request[BUFFER_SIZE];
    int req_len = sprintf(new_request, "%s %s %s\r\nHost: %s\r\nX-Forwarded-For: %s, 127.0.0.1\r\nConnection: close\r\n\r\n", 
                          method, path, protocol, host, client_ip);

    SSL_write(ssl, new_request, req_len);

    long total_bytes = 0;
    while ((n = SSL_read(ssl, buffer, sizeof(buffer))) > 0) {
        write(client_fd, buffer, n);
        total_bytes += n;
    }

    log_event(log_file, client_ip, first_line, REQUEST_OK, total_bytes);

    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(server_sock);
    close(client_fd);
}

int main(int argc, char *argv[]) {
    int opt, port = 0;
    char *forbidden_file = NULL, *log_file = NULL;

    while ((opt = getopt(argc, argv, "p:a:l:")) != -1) {
        switch (opt) {
            case 'p': port = atoi(optarg); break;
            case 'a': forbidden_file = optarg; break;
            case 'l': log_file = optarg; break;
        }
    }

    if (!port || !forbidden_file || !log_file) {
        fprintf(stderr, "Usage: %s -p <port> -a <acl> -l <log>\n", argv[0]);
        return EXIT_FAILURE;
    }

    SSL_library_init();
    SSL_load_error_strings();
    SSL_CTX *ctx = SSL_CTX_new(SSLv23_client_method());

    forbidden_sites_list acl = { .len = 0 };
    FILE *f_acl = fopen(forbidden_file, "r");
    if (f_acl) {
        char line[MAX_URL_LEN];
        while (fgets(line, sizeof(line), f_acl) && acl.len < MAX_FORBIDDEN_SITES) {
            if (line[0] == '#' || line[0] == '\n') continue;
            line[strcspn(line, "\r\n")] = 0;
            strncpy(acl.sites[acl.len++], line, MAX_URL_LEN);
        }
        fclose(f_acl);
    }

    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    int optval = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));

    struct sockaddr_in addr = { .sin_family = AF_INET, .sin_addr.s_addr = INADDR_ANY, .sin_port = htons(port) };
    if (bind(server_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("Bind failed");
        return EXIT_FAILURE;
    }
    listen(server_fd, 50);
    signal(SIGCHLD, SIG_IGN);

    while (1) {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        int client_fd = accept(server_fd, (struct sockaddr *)&client_addr, &client_len);

        if (fork() == 0) {
            close(server_fd);
            handle_client(client_fd, client_addr, &acl, log_file, ctx);
            exit(0);
        }
        close(client_fd);
    }
    return 0;
}