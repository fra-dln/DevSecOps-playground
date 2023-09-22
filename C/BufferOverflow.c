#include <stdio.h>
#include <string.h>

#define MAX_SIZE 256 // You can change the value as needed

int main() {
    char buf[64], in[MAX_SIZE];
    int bytes;

    printf("Enter buffer contents:\n");
    ssize_t bytesRead = read(0, in, MAX_SIZE - 1);

    if (bytesRead == -1) {
        perror("read");
        return 1; // Error handling: exit with an error code
    }

    in[bytesRead] = '\0'; // Null-terminate the input

    printf("Bytes to copy:\n");
    if (scanf("%d", &bytes) != 1 || bytes < 0 || bytes >= MAX_SIZE) {
        printf("Invalid input for 'bytes'. Please enter a valid number.\n");
        return 1; // Error handling: exit with an error code
    }

    if (bytes > bytesRead) {
        printf("Error: 'bytes' is greater than the input buffer size.\n");
        return 1; // Error handling: exit with an error code
    }

    memcpy(buf, in, bytes);

    printf("Copied %d bytes to 'buf':\n%s\n", bytes, buf);

    return 0;
}
