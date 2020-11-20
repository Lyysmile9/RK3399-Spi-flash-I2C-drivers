#include "rs_spiflash.h"
#include <stdint.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>

int main(int argc, char **argv)
{
	unsigned char id[4] = {'w', '2', '5', '\0'};
	unsigned char version[4] = {'s', 'p', 'i', '\0'};
	unsigned char config[256];
	unsigned char *inbuf = NULL, *outbuf = NULL;
	FILE *infile = NULL, *outfile = NULL;
	unsigned int infile_size;
	unsigned char config_bak[256];

	if (argc < 3) {
		printf("usage:%s infile outfile", argv[0]);
		goto exit;
	}
	
	infile = fopen(argv[1], "r");
	if (!infile) {
		printf("opening %s file failure\n", argv[1]);
		goto exit;
	}

	outfile = fopen(argv[2], "w+");
	if (!outfile) {
		printf("opening %s file failure\n", argv[2]);
		goto exit;
	}

	fseek(infile, 0, SEEK_END);
	infile_size = ftell(infile);
	printf("file size:%d\n", infile_size);
	fseek(infile, 0, SEEK_SET);
	inbuf = malloc(infile_size);
	if (!inbuf) {
		printf("out of memory\n");
		goto exit;
	}
	outbuf = malloc(infile_size);
	if (!outbuf) {
		printf("out of memory\n");
		goto exit;
	}
	fread(inbuf, infile_size, 1, infile);

	if(!rs_dev_id_ops(id, 1))
		printf("set dev id failure\n");

	for (unsigned int i = 0; i < sizeof(config); i++)
		config[i] = i;

	if (!rs_write_common_config(config, sizeof(config))) {
		printf("write common config failure\n");
		goto exit;
	}
	
	if (!rs_write_data_to_flash(inbuf, infile_size)) {
		printf("write data to flash failure\n");
		goto exit;
	}

	if (!rs_read_data_from_flash(outbuf)) {
		printf("read data from flash failure\n");
		goto exit;
	}

	if (!rs_write_flash_info()) {
		printf("write flash info failure\n");
		goto exit;
	}

	fwrite(outbuf, infile_size, 1, outfile);

	if(!rs_read_common_config(config_bak))
		printf("read common config from flash failure\n");
	else {
		for (int i = 0; i < rs_get_config_len(); i++ )
			printf("config[%d]:%d\n", i, config_bak[i]);
	}

	if (!rs_read_flash_info()) {
		printf("read flash info failure\n");
		goto exit;
	}
exit:
	if (outbuf)
		free(outbuf);
	if (inbuf)
		free(inbuf);
	if (outfile)
		fclose(outfile);
	if (infile)
		fclose(infile);
}