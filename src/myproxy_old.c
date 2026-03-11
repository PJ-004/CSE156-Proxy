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

#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define ENABLE_DEBUG

#ifdef ENABLE_DEBUG
#define DEBUG(FORMAT, ...) fprintf(stderr, "At Line: %d " FORMAT, __LINE__, ##__VA_ARGS__)
#else
#define DEBUG(FORMAT, ...)
#endif

#define BUFFER_SIZE 2048
#define MAX_FORBIDDEN_SITES 256
#define MAX_URL_LEN 256

// HTTP Error Codes
#define REQUEST_OK 200
#define BAD_REQUEST 400
#define FORBIDDEN 403
#define NOT_IMPLEMENTED 501
#define BAD_GATEWAY 502
#define GATEWAY_TIMEOUT 504

void print_usage(char *prog_name) {
	fprintf(stderr, "Usage: %s -p listen_port -a forbidden_sites_file_path -l access_log_file_path\n", prog_name);
}

void get_timestamp(char *buf) {
	struct timespec ts;
	clock_gettime(CLOCK_REALTIME, &ts);
	struct tm *tm = gmtime(&ts.tv_sec);
	strftime(buf, 30, "%Y-%m-%dT%H:%M:%S", tm);
	sprintf(buf + strlen(buf), ".%03ldZ", ts.tv_nsec / 1000000);
}

typedef struct {
	size_t len;
	char sites[MAX_FORBIDDEN_SITES][MAX_URL_LEN];
} forbidden_sites_list;

void create_forbidden_sites_list(FILE *forbidden_fd, forbidden_sites_list *list) {
	char line[MAX_URL_LEN];
	size_t site_number = 0;
	while (site_number < MAX_FORBIDDEN_SITES && fgets(line, sizeof(line), forbidden_fd) != NULL) {
		if (line[0] != '#') {
			strncpy(list->sites[site_number], line, strlen(line) - 1);
			list->sites[site_number][strlen(line) - 1] = '\0';
			printf("Added website %s to forbidden websites list\n", list->sites[site_number]);
		} else {
			continue;
		}
		site_number++;
	}
	list->len = site_number;
	printf("List len: %lu\n", list->len);
}

typedef struct {
	size_t request_size;
	char request_line[BUFFER_SIZE];
	char header[BUFFER_SIZE];
	char method[5];
	char domain[MAX_URL_LEN];
	char url[MAX_URL_LEN];
} http_request;

void make_domain_string(char *domain, char *url) {
	strcpy(domain, url + 7);
	strchr(domain, '/')[0] = '\0';
}

int make_request(http_request *req) {
	req->request_line[req->request_size] = '\0';
	//fprintf(stderr, "Request Line: %s\n", req->request_line);

	char *end_of_response_string = strchr(req->request_line, '\r');
	end_of_response_string[0] = '\0';
	strcpy(req->header, req->request_line);
	end_of_response_string[0] = '\r';
	//fprintf(stderr, "Header: %s\n", req->header);

	strcpy(req->url, strchr(req->header, ' ') + 1);
	strchr(req->url, ' ')[0] = '\0';
	DEBUG("URL: %s\n", req->url);
	make_domain_string(req->domain, req->url);
	DEBUG("Domain: %s\n", req->domain);

	char *end_of_method_string = strchr(req->header, ' ');
	end_of_method_string[0] = '\0';
	strncpy(req->method, req->header, sizeof(req->method));
	end_of_method_string[0] = ' ';
	//fprintf(stderr, "Method: %s\n", req->method);
	//printf("Request Line: %s\nDomain Name: %s\nHeader: %s\n", req->request_line, req->domain, req->header);

	return 0;
}

void make_response_string(char *response, size_t *response_size, int http_status) {
	switch (http_status) {
		case FORBIDDEN:
			*response_size = snprintf(response, *response_size, "HTTP/1.1 %d Forbidden\r\n", FORBIDDEN);
			break;
		case REQUEST_OK:
			*response_size = snprintf(response, *response_size, "HTTP/1.1 %d OK\r\n", REQUEST_OK);
			break;
		default:
			fprintf(stderr, "HTTP Status %d not implemented\n", http_status);
			exit(EXIT_FAILURE);
			break;
	}
}

int check_if_forbidden(forbidden_sites_list *list, char *url) {
	if (url == NULL || url == NULL + 1) {
		fprintf(stderr, "Incorrect URL\n");
		return -1;
	}

	printf("\nChecking URL: '%s'\n\n", url);

	for (size_t i = 0; i < list->len; i++) {
		printf("Testing URL:  %s | URL in the list: %s\n", url, list->sites[i]);
		if (strstr(url, list->sites[i]) != NULL) {
			printf("Forbidden URL found at %lu: '%s'\n", i, list->sites[i]);
			return 1;
		}
	}

	printf("Reached end of list, URL Allowed\n");
	return 0;
}

int main(int argc, char *argv[]) {
	int opt;
	int port = 0;
	char *forbidden_file = NULL;
	char *log_file = NULL;

	// "p:a:l:" means p, a, and l all require an argument (indicated by the colon)
	while ((opt = getopt(argc, argv, "p:a:l:")) != -1) {
		switch (opt) {
			case 'p':
				port = atoi(optarg); // Convert port string to integer
				break;
			case 'a':
				forbidden_file = optarg; // optarg points to the value after -a
				break;
			case 'l':
				log_file = optarg; // optarg points to the value after -l
				break;
			case '?':
				// getopt automatically prints an error message for unknown options
				print_usage(argv[0]);
				return EXIT_FAILURE;
			default:
				print_usage(argv[0]);
				return EXIT_FAILURE;
		}
	}

	// SSL Init
	SSL_library_init();
	SSL_load_error_strings();
	OpenSSL_add_all_algorithms();

	// Add SSL Method
	SSL_METHOD* meth = SSLv23_client_method();

	// Create SSL CTX(Context) with method created earlier
	SSL_CTX* ctx = SSL_CTX_new(meth);

	// Create SSL structure
	SSL* ssl = SSL_new(ctx);

	// Basic validation: ensure all arguments were provided
	if (port == 0 || forbidden_file == NULL || log_file == NULL) {
		fprintf(stderr, "Error: Missing required arguments.\n");
		print_usage(argv[0]);
		return EXIT_FAILURE;
	}

	// Create a socket for the server
	int proxy_fd = socket(AF_INET, SOCK_STREAM, 0);
	if (proxy_fd < 0) {
		perror("Socket creation failed");
		return EXIT_FAILURE;
	}


	// Open forbidden-sites file
	FILE *forbidden_fd = fopen(forbidden_file, "r");
	if (forbidden_fd == NULL) {
		fprintf(stderr, "Unable to open forbidden sites file: %s\n", forbidden_file);
		return EXIT_FAILURE;
	}

	forbidden_sites_list list;
	create_forbidden_sites_list(forbidden_fd, &list);

	// Open log file
	FILE *log_fd = fopen(log_file, "a");
	if (log_fd == NULL) {
		fprintf(stderr, "Unable to open log file: %s\n", log_file);
		return EXIT_FAILURE;
	}

	// Allow immediate reuse of the port after restart
	int optval = 1;
	setsockopt(proxy_fd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));

	// 3. Bind to Port
	struct sockaddr_in server_addr;
	server_addr.sin_family = AF_INET;
	server_addr.sin_addr.s_addr = INADDR_ANY; // Listen on all interfaces
	server_addr.sin_port = htons(port);

	if (bind(proxy_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
		perror("Bind failed");
		close(proxy_fd);
		return EXIT_FAILURE;
	}

	// 4. Listen
	if (listen(proxy_fd, 10) < 0) {
		perror("Listen failed");
		return EXIT_FAILURE;
	}

	printf("Server started on port %d...\n", port);
	printf("Logging to: %s\n", log_file);

	// 5. Main Server Loop
	while (1) {
		char response[4096];
		ssize_t bytes_recv, response_size;
		char site_body[4096];

		int http_status = 200;
		struct sockaddr_in client_addr;
		socklen_t addr_len = sizeof(client_addr);
		int client_fd = accept(proxy_fd, (struct sockaddr *)&client_addr, &addr_len);

		if (client_fd < 0) {
			perror("Accept failed");
			continue;
		}

		// Read the request
		http_request req;
		req.request_size = read(client_fd, req.request_line, BUFFER_SIZE - 1);
		make_request(&req);

		char time_buf[32];

		get_timestamp(time_buf);

		if (check_if_forbidden(&list, req.domain)) {
			printf("Forbidden website, returning response 403 Forbidden\n");
			http_status = FORBIDDEN;
			response_size = sizeof(response);
			make_response_string(response, &response_size, http_status);
		} else {
			const struct addrinfo hints = {
				.ai_family = AF_INET,
				.ai_socktype = SOCK_STREAM,
			};
			struct addrinfo *result;
			struct in_addr *addr;

			char port_str[] = "443";
			int status = getaddrinfo(req.domain, port_str, &hints, &result);

			if (status != 0) {
				if (status == EAI_SERVICE) {
					fprintf(stderr, "Invalid Port\n");
					http_status = BAD_REQUEST;
				}

				if (status == EAI_NONAME || status == EAI_NONAME) {
					fprintf(stderr, "Error: Hostname '%s' does not exist.\n", req.domain);
					http_status = BAD_GATEWAY;
				} else if (status == EAI_FAMILY) {
					fprintf(stderr, "Error: Invalid IP address format.\n");
					http_status = NOT_IMPLEMENTED;
				} else {
					fprintf(stderr, "DNS Resolution Error: %s\n", gai_strerror(status));
					http_status = BAD_REQUEST;
				}

			} else {
				// 6. Make a new socket for forwarding requests
				int request_fd = socket(AF_INET, SOCK_STREAM, 0);
				if (request_fd < 0) {
					perror("Socket creation failed");
					http_status = BAD_GATEWAY;
				}

				if (connect(request_fd, result->ai_addr, result->ai_addrlen) != 0) {
					http_status = BAD_REQUEST;
					printf("Connect not OK\n");
				} else {
					http_status = REQUEST_OK;
					printf("Connect OK\n");
				}

				SSL_set_fd(ssl, request_fd);

				response_size = sizeof(response);
				DEBUG("Before send\nResponse: %s\nHTTP Status: %d\n", req.request_line, http_status);

				if (SSL_write(ssl, req.request_line, req.request_size) < 0) {
					perror("Failed to send request\n");
					close(request_fd);
					http_status = GATEWAY_TIMEOUT;
				} else {
					DEBUG("After SSL_send before SSL_read\n");
					bytes_recv = SSL_read(ssl, response, sizeof(response) - 1);
					DEBUG("After SSL_read\n");
					if (bytes_recv >= 0) {
						response[bytes_recv] = '\0';
						response_size = bytes_recv;
					} else {
						// TODO: Send response in case recv failed
					}
				}
				SSL_shutdown(ssl);
				close(request_fd);
			}
			freeaddrinfo(result);
		}

		// date client_ip "request_line" http_status response_size
		fprintf(log_fd, "%s %s \"%s\" %d %lu\n", time_buf, inet_ntoa(client_addr.sin_addr), req.header, http_status, response_size);
		fflush(log_fd);

		printf("%s\n", response);
		write(client_fd, response, response_size);

		// Close connection
		close(client_fd);
	} // While loop end

	SSL_free(ssl);

	close(proxy_fd);
	fclose(log_fd);

	return EXIT_SUCCESS;
}
