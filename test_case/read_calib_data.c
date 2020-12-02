#include "rs_spiflash.h"
#include <stdint.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>

int main(int argc, char **argv)
{
	unsigned char *outbuf = NULL;
	int size = 0;
	FILE *outfile = NULL;

	if (argc < 2) {
		printf("usage:%s outfile", argv[0]);
		goto exit;
	}

	outfile = fopen(argv[1], "w+");
	if (!outfile) {
		printf("opening %s file failure\n", argv[1]);
		goto exit;
	}

	size = rs_get_data_len();
	printf("data size: %d\n", size);

	outbuf = malloc(size);
	if (!outbuf) {
		printf("out of memory\n");
		goto exit;
	}

	if (!rs_read_data_from_flash(outbuf)) {
		printf("read data from flash failure\n");
		goto exit;
	}

	fwrite(outbuf, size, 1, outfile);

exit:
	if (outbuf)
		free(outbuf);
	if (outfile)
		fclose(outfile);
}

