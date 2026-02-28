#include <stdio.h>
#include <string.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void print_usage(char *prog_name) {
	fprintf(stderr, "Usage: %s -p listen_port -a forbidden_sites_file_path -l access_log_file_path\n", prog_name);
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
	printf("Configuration loaded:\n");
	printf("  - Port: %d\n", port);
	printf("  - Forbidden sites file: %s\n", forbidden_file);
	printf("  - Access log file: %s\n", log_file);
	
	return EXIT_SUCCESS;
}
