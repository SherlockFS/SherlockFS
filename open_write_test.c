// open_write_test.c
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
int main(int argc, char *argv[])
{
	// Try to open create a file and write to it
	int fd = open("mnt/file1", O_CREAT | O_WRONLY);

	if (fd == -1)
	{
		perror("open");
		return 1;
	}

	printf("FD number: %d\n", fd);
	char *buf = "Hello, world!";
	int bytes_written = write(fd, buf, 13);

	if (bytes_written == -1)
	{
		perror("write");
		printf("Error number: %d\n", errno);
		return 1;
	}

	close(fd);

	return 0;
}
