#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <time.h>

#define BUFFER_SIZE 2048

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
	
	// Output results to verify
	/*
	printf("Configuration loaded:\n");
	printf("  - Port: %d\n", port);
	printf("  - Forbidden sites file: %s\n", forbidden_file);
	printf("  - Access log file: %s\n", log_file);
	*/

	int server_fd = socket(AF_INET, SOCK_STREAM, 0);
	if (server_fd < 0) {
		perror("Socket creation failed");
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
		ssize_t response_size = read(client_fd, request_line, BUFFER_SIZE - 1);
		request_line[response_size] = '\0';
		
		char time_buf[32];

		get_timestamp(time_buf);
		char *end_of_response_string = strchr(request_line, '\r');
		end_of_response_string[0] = '\0';
                printf("%s %s \"%s\" %d %lu\n", time_buf, inet_ntoa(client_addr.sin_addr), request_line, http_status, response_size);
		end_of_response_string[0] = '\r';
	
		// 6. Send simple HTTP response
		char *http_response = 
			"HTTP/1.1 200 OK\r\n"
			"Content-Type: text/html\r\n"
			"Content-Length: 26\r\n"
			"Connection: close\r\n"
			"\r\n"
			"<h1>Hello from myproxy</h1>";
	
		write(client_fd, http_response, strlen(http_response));
	
		// Close connection
		close(client_fd);
	}

	close(server_fd);	

	return EXIT_SUCCESS;
}
