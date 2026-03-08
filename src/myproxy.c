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

void make_response_string(char *response, size_t *response_size, int http_status) {
	switch (http_status) {
		case FORBIDDEN:
			*response_size = snprintf(response, *response_size, "HTTP/1.1 %d Forbidden\r\n", FORBIDDEN);
			break;
		default:
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

	// Basic validation: ensure all arguments were provided
	if (port == 0 || forbidden_file == NULL || log_file == NULL) {
		fprintf(stderr, "Error: Missing required arguments.\n");
		print_usage(argv[0]);
		return EXIT_FAILURE;
	}

	int server_fd = socket(AF_INET, SOCK_STREAM, 0);
	if (server_fd < 0) {
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
	setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));

	// 3. Bind to Port
	struct sockaddr_in server_addr;
	server_addr.sin_family = AF_INET;
	server_addr.sin_addr.s_addr = INADDR_ANY; // Listen on all interfaces
	server_addr.sin_port = htons(port);

	if (bind(server_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
		perror("Bind failed");
		close(server_fd);
		return EXIT_FAILURE;
	}

	// 4. Listen
	if (listen(server_fd, 10) < 0) {
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
		int client_fd = accept(server_fd, (struct sockaddr *)&client_addr, &addr_len);

		if (client_fd < 0) {
			perror("Accept failed");
			continue;
		}

		// Read the request (we just clear the buffer for this simple example)
		char request_line[BUFFER_SIZE];
		response_size = read(client_fd, request_line, BUFFER_SIZE - 1);
		request_line[response_size] = '\0';

		char time_buf[32];

		get_timestamp(time_buf);
		char *end_of_response_string = strchr(request_line, '\r');
		end_of_response_string[0] = '\0';
		// date client_ip "request_line" http_status response_size
		fprintf(log_fd, "%s %s \"%s\" %d %lu\n", time_buf, inet_ntoa(client_addr.sin_addr), request_line, http_status, response_size);
		fflush(log_fd);

		if (check_if_forbidden(&list, strchr(request_line, ' ') + 1)) {
			printf("Forbidden website, returning response 403 Forbidden\n");
			http_status = FORBIDDEN;
			response_size = sizeof(response);
			make_response_string(response, &response_size, http_status);
		} else {
			end_of_response_string[0] = '\r';

			const struct addrinfo hints = {
				.ai_family = AF_INET,
				.ai_socktype = SOCK_STREAM,
			};
			struct addrinfo *result;
			struct in_addr *addr;

			char hostname[] = "www.google.com";
			char port_str[] = "80";
			int status = getaddrinfo(hostname, port_str, &hints, &result);

			if (status != 0) {
				if (status == EAI_SERVICE) {
					fprintf(stderr, "Invalid Port\n");
					http_status = BAD_REQUEST;
				}

				if (status == EAI_NONAME || status == EAI_NONAME) {
					fprintf(stderr, "Error: Hostname '%s' does not exist.\n", hostname);
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

				if (send(request_fd, request_line, response_size, 0) < 0) {
					perror("Failed to send request\n");
					close(request_fd);
					http_status = GATEWAY_TIMEOUT;
				} else {
					bytes_recv = recv(request_fd, response, sizeof(response) - 1, 0);
					if (bytes_recv >= 0) {
						response[bytes_recv] = '\0';
						response_size = bytes_recv;
					} else {
						// TODO: Send response in case recv failed
					}
				}
				close(request_fd);
			}

			freeaddrinfo(result);
		}

		printf("%s\n", response);
		write(client_fd, response, response_size);


		// Close connection
		close(client_fd);
	}

	close(server_fd);
	fclose(log_fd);

	return EXIT_SUCCESS;
}
