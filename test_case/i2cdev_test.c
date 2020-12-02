#include <stdint.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <linux/types.h>
#include <linux/spi/spidev.h>
#include "w25q64.h"

#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))

uint8_t default_tx[] = {
	0x00, 0x00, 0x00, 0x00, 0x00, 0xFF,
	0x40, 0x00, 0x00, 0x00, 0x00, 0x95,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xF0, 0x0D,
};

uint8_t default_rx[ARRAY_SIZE(default_tx)] = {0, };

int main(void)
{
	int fd;
	int ret;
	unsigned int offset;

	fd = open("/dev/w25q64", O_RDWR);
	if (fd < 0) {
		printk("can't open device");
		return 0;
	}

	lseek(fd, 0, SEEK_SET);
	ioctl(fd, W25Q64_IOC_SECTOR_ERASE);
	read(fd, default_rx, sizeof(default_rx));
		for (int i = 0; i < ARRAY_SIZE(default_rx); i++)
			printf("revice data should be 0XFF:%x\t\n", default_rx[i]);
	for (int i = 0; i < 3; i++) {
			write(fd, default_tx, sizeof(default_tx));
			read(fd, default_rx, sizeof(default_rx));
			offset = sizeof(default_tx);
			ret = lseek(fd, offset, SEEK_CUR);
			printf("current addr:%d\n", ret);

			for (int i = 0; i < ARRAY_SIZE(default_rx); i++)
				printf("receive data:%x\t\n", default_rx[i]);
		}

	lseek(fd, 0x1000, SEEK_SET);
	ioctl(fd, W25Q64_IOC_32KB_BLOCK_ERASE);
	read(fd, default_rx, sizeof(default_rx));
		for (int i = 0; i < ARRAY_SIZE(default_rx); i++)
			printf("revice data should be 0XFF:%x\t\n", default_rx[i]);
	for (int i = 0; i < 3; i++) {
			write(fd, default_tx, sizeof(default_tx));
			read(fd, default_rx, sizeof(default_rx));
			offset = sizeof(default_tx);
			ret = lseek(fd, offset, SEEK_CUR);
			printf("current addr:%d\n", ret);

			for (int i = 0; i < ARRAY_SIZE(default_rx); i++)
				printf("receive data:%x\t\n", default_rx[i]);
		}
	
	lseek(fd, 0x8000, SEEK_SET);
	ioctl(fd, W25Q64_IOC_64KB_BLOCK_ERASE);
	read(fd, default_rx, sizeof(default_rx));
		for (int i = 0; i < ARRAY_SIZE(default_rx); i++)
			printf("revice data should be 0XFF:%x\t\n", default_rx[i]);
	for (int i = 0; i < 3; i++) {
			write(fd, default_tx, sizeof(default_tx));
			read(fd, default_rx, sizeof(default_rx));
			offset = sizeof(default_tx);
			ret = lseek(fd, offset, SEEK_CUR);
			printf("current addr:%d\n", ret);

			for (int i = 0; i < ARRAY_SIZE(default_rx); i++)
				printf("receive data:%x\t\n", default_rx[i]);
		}

	lseek(fd, 0, SEEK_SET);
	ioctl(fd, W25Q64_IOC_CHIP_ERASE);
	read(fd, default_rx, sizeof(default_rx));
		for (int i = 0; i < ARRAY_SIZE(default_rx); i++)
			printf("revice data should be 0XFF:%x\t\n", default_rx[i]);
	for (int i = 0; i < 3; i++) {
			write(fd, default_tx, sizeof(default_tx));
			read(fd, default_rx, sizeof(default_rx));
			offset = sizeof(default_tx);
			ret = lseek(fd, offset, SEEK_CUR);
			printf("current addr:%d\n", ret);

			for (int i = 0; i < ARRAY_SIZE(default_rx); i++)
				printf("receive data:%x\t\n", default_rx[i]);
		}
}
