#include <stdint.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <linux/types.h>
#include <time.h>
#include <pthread.h>
#include <openssl/md5.h>
#include "w25q64.h"
#include "rs_spiflash.h"

#define ARRAY_SIZE(x) (sizeof(x)/sizeof(x[0]))
static const char *device = "/dev/w25q64";
static FLASH_INFO flashinfo = {
		.flashtype = {'w', '2', '5', '\0'},
		.config_start = 8192,
		.data_start = 12288,
};
static pthread_mutex_t mutex;
static get_md5(PFLASH_INFO info);

static int rs_get_flash_info(PFLASH_INFO info)
{
	int status = 0;

	if (!info)
		goto exit;

	pthread_mutex_lock(&mutex);
	status = memcpy(info, &flashinfo, sizeof(flashinfo));
	pthread_mutex_unlock(&mutex);

exit:
	return status;
}

static int rs_set_flash_info(PFLASH_INFO info)
{
	int status = 0;

	if (!info)
		goto exit;

	pthread_mutex_lock(&mutex);
	status = memcpy( &flashinfo, info, sizeof(flashinfo));
	pthread_mutex_unlock(&mutex);

exit:
	return status;
}

int rs_read_flash_info()
{
	int fd, i, status = 0;
	unsigned char *buf = NULL;
	FLASH_INFO info;
	unsigned int size = sizeof(info);

	fd = open(device, O_RDWR);
	if (fd < 0) {
		printf("error can't open %s file\n", device);
		goto exit;
	}

	buf = malloc(sizeof(info));
	if (!buf) {
		printf("out of memory\n");
		goto exit;;
	}

	i = 0;
	while (size > 0) {
		lseek(fd, i, SEEK_SET);
		if (size >= W25Q64_PAGE_LENGTH) {
			status = read(fd, &buf[i], W25Q64_PAGE_LENGTH);
			i += W25Q64_PAGE_LENGTH;
			size -= W25Q64_PAGE_LENGTH;
		} else {
			status = read(fd, &buf[i], size);
			size = 0;
		}
	}

	memcpy((unsigned char *)&info, buf, sizeof(info));

	rs_set_flash_info(&info);

	get_md5(&info);

	close(fd);
	free(buf);

exit:
	return status;
}

static int get_time(unsigned char date[6])
{
	struct timespec time;
	struct tm now;

	if (!date)
		goto exit;

	clock_gettime(CLOCK_REALTIME, &time);
	localtime_r(&time.tv_sec, &now);
	date[0] = (unsigned char)(now.tm_year >> 8);
	date[1] = (unsigned char)now.tm_mon;
	date[2] = (unsigned char)now.tm_mday;
	date[3] = (unsigned char)now.tm_hour;
	date[4] = (unsigned char)now.tm_min;
	date[5] = (unsigned char)now.tm_sec;

exit:
	return 0;
}

static int get_md5(PFLASH_INFO info)
{
	unsigned int size = sizeof(*info) - 16;
	unsigned char buf[size];
	unsigned char md[16];
	unsigned int i;
	unsigned char tmp[3] = {'\0'};
	unsigned char outbuf[33] = {'\0'};
	
	MD5_CTX ctx;
	
	memcpy(buf, (unsigned char*)info, size);
	MD5_Init(&ctx);
	MD5_Update(&ctx, buf, size);
	MD5_Final(info->md5, &ctx);
	for (i = 0; i < 16; i++) {
		sprintf(tmp, "%02x", info->md5[i]);
		strcat(outbuf, tmp);
	}
	printf("%s\n", outbuf);

	return 0;
}

int rs_write_flash_info()
{
	int fd, i, status = 0;
	FLASH_INFO info;
	unsigned char *buf = NULL;
	unsigned int size = sizeof(info);

	fd = open(device, O_RDWR);
	if (fd < 0) {
		printf("error can't open %s file\n", device);
		goto exit;
	}

	buf = malloc(sizeof(info));
	if (!buf) {
		printf("out of memory\n");
		goto exit;
	}
	
	lseek(fd, 0, SEEK_SET);
	ioctl(fd, W25Q64_IOC_SECTOR_ERASE, sizeof(info));

	rs_get_flash_info(&info);
	get_time(info.date);
	get_md5(&info);
	rs_set_flash_info(&info);

	memcpy(buf, (unsigned char *)&info, sizeof(info));

	i = 0;
	while(size > 0) {
		lseek(fd, i, SEEK_SET);
		if (size >= W25Q64_PAGE_LENGTH) {
			status = write(fd, &buf[i], W25Q64_PAGE_LENGTH);
			i += W25Q64_PAGE_LENGTH;
			size -= W25Q64_PAGE_LENGTH;
		} else {
			status = write(fd, &buf[i], size);
			size = 0;
		}
	}

	close(fd);
	free(buf);
exit:
	return status;
}

int rs_dev_id_ops(unsigned char id[4], unsigned int write)
{
	int status = 0;
	FLASH_INFO info;
	
	if (!id)
		goto exit;

	memset(&info, 0, sizeof(FLASH_INFO));
	rs_get_flash_info(&info);

	if (write) {
		memcpy(info.device_id, id, sizeof(info.device_id));
		status = rs_set_flash_info(&info);
	} else
		status = memcpy(id, info.device_id, sizeof(info.device_id));

exit:
	return status;
}

int rs_version_ops(unsigned char version[4], unsigned int write)
{
	int status = 0;
	FLASH_INFO info;

	if (!version)
		goto exit;

	memset(&info, 0, sizeof(FLASH_INFO));
	rs_get_flash_info(&info);

	if (write) {
		memcpy(info.version, version, sizeof(info.version));
		status = rs_set_flash_info(&info);
	} else
		status = memcpy(version, info.version, sizeof(info.version));

exit:
	return status;
}

int rs_read_common_config(void *outbuf)
{
	int fd, status = 0, i, j;
	FLASH_INFO info;
	unsigned char *buf = NULL;
	unsigned int size;

	if (!outbuf)
		goto exit;

	fd = open(device, O_RDWR);
	if (fd < 0) {
		printf("error can't open %s file\n", device);
		goto exit;
	}

	if (!rs_get_flash_info(&info)) {
		printf("get flash info failed\n");
		goto exit;
	}

	size = info.config_len;
	printf("read %d common config\n", size);
	buf = malloc(size);
	if (!buf) {
		printf("out of memory\n");
		goto exit;
	}

	printf("%s set config start addr:%02x\n", __func__, info.config_start);
	
	i = info.config_start;
	j = 0;
	while (size > 0) {
		lseek(fd, i, SEEK_SET);
		if (size >= W25Q64_PAGE_LENGTH) {
			status = read(fd, &buf[j], W25Q64_PAGE_LENGTH);
			i += W25Q64_PAGE_LENGTH;
			j += W25Q64_PAGE_LENGTH;
			size -= W25Q64_PAGE_LENGTH;
		} else {
			status = read(fd, &buf[j], size);
			size = 0;
		}
	}

	memcpy((unsigned char *)outbuf, buf, info.config_len);

	close(fd);
	free(buf);
	status = info.config_len;
exit:
	return status;
}

int rs_write_common_config(void *data, unsigned int size)
{
	int fd, status = 0, i, j;
	FLASH_INFO info;
	unsigned char *buf = NULL;

	if (!data)
		goto exit;

	if (!rs_get_flash_info(&info)) {
		printf("get flash info failed\n");
		goto exit;
	}

	/*update flash info: config len*/
	info.config_len = size;
	if (!rs_set_flash_info(&info)) {
		printf("write flash info failed\n");
		goto exit;
	}
	printf("write %d common config\n", size);

	fd = open(device, O_RDWR);
	if (fd < 0) {
		printf("error can't open %s file\n", device);
		goto exit;
	}

	buf = malloc(size);
	if (!buf) {
		printf("out of memory\n");
		goto exit;
	}

	printf("%s set config start addr:%02x\n", __func__, info.config_start);
	lseek(fd, info.config_start, SEEK_SET);
	ioctl(fd, W25Q64_IOC_SECTOR_ERASE, size);

	memcpy(buf, (unsigned char *)data, size);

	i = info.config_start;
	j = 0;
	while(size > 0) {
		lseek(fd, i, SEEK_SET);
		if (size >= W25Q64_PAGE_LENGTH) {
			status = write(fd, &buf[j], W25Q64_PAGE_LENGTH);
			i += W25Q64_PAGE_LENGTH;
			j += W25Q64_PAGE_LENGTH;
			size -= W25Q64_PAGE_LENGTH;
		} else {
			status = write(fd, &buf[j], size);
			size = 0;
		}
	}
	close(fd);
	free(buf);

exit:
	return status;
}

int rs_write_data_to_flash(void *data, unsigned int data_size)
{
	int fd, status = 0, i, j;
	FLASH_INFO info;
	unsigned char *buf = NULL;

	if (!data)
		goto exit;

	if (!rs_get_flash_info(&info)) {
		printf("get flash info failed\n");
		goto exit;
	}

	/*update flash info: data len*/
	info.data_len = data_size;
	if (!rs_set_flash_info(&info)) {
		printf("write flash info failed\n");
		goto exit;
	}
	printf("write %d data to flash\n", data_size);

	fd = open(device, O_RDWR);
	if (fd < 0) {
		printf("error can't open %s file\n", device);
		goto exit;
	}

	buf = malloc(data_size);
	if (!buf) {
		printf("out of memory\n");
		goto exit;
	}

	lseek(fd, info.data_start, SEEK_SET);
	printf("%s set data start addr:%02x\n", __func__, info.data_start);
	ioctl(fd, W25Q64_IOC_SECTOR_ERASE, data_size);

	memcpy(buf, (unsigned char *)data, data_size);

	i = info.data_start;
	j = 0;
	while(data_size > 0) {
		lseek(fd, i, SEEK_SET);
		if (data_size >= W25Q64_PAGE_LENGTH) {
			status = write(fd, &buf[j], W25Q64_PAGE_LENGTH);
			i += W25Q64_PAGE_LENGTH;
			data_size -= W25Q64_PAGE_LENGTH;
			j += W25Q64_PAGE_LENGTH;
		} else {
			status = write(fd, &buf[j], data_size);
			data_size = 0;
		}
	}

	close(fd);
	free(buf);

exit:
	return status;
}

int rs_read_data_from_flash(void *data)
{
	int fd,status = 0, i, j;
	FLASH_INFO info;
	unsigned char *buf = NULL;
	unsigned int size, data_size;

	if (!data)
		goto exit;

	if (!rs_get_flash_info(&info)) {
		printf("get flash info failed\n");
		goto exit;
	}

	size = info.data_len;
	data_size = size;
	printf("read %d data from flash\n", size);

	fd = open(device, O_RDWR);
	if (fd < 0) {
		printf("error can't open %s file\n", device);
		goto exit;
	}

	buf = malloc(data_size);
	if (!buf) {
		printf("out of memory\n");
		goto exit;
	}

	lseek(fd, info.data_start, SEEK_SET);
	printf("%s set data start addr:%02x\n", __func__, info.data_start);

	i = info.data_start;
	j = 0;
	while(data_size > 0) {
		lseek(fd, i, SEEK_SET);
		if (data_size >= W25Q64_PAGE_LENGTH) {
			status = read(fd, &buf[j], W25Q64_PAGE_LENGTH);
			i += W25Q64_PAGE_LENGTH;
			j += W25Q64_PAGE_LENGTH;
			data_size -= W25Q64_PAGE_LENGTH;
		} else {
			status = read(fd, &buf[j], data_size);
			data_size = 0;
		}
	}

	memcpy((unsigned char *)data, buf, size);

	close(fd);
	free(buf);
	status = info.data_len;
exit:
	return status;
}

int rs_get_config_len()
{
	int status = 0;
	FLASH_INFO info;

	if(!rs_read_flash_info())
		goto exit;

	if(!rs_get_flash_info(&info))
		goto exit;

	status = info.config_len;

exit:
	return status;
}

int rs_get_data_len()
{
	int status = 0;
	FLASH_INFO info;

	if(!rs_read_flash_info())
		goto exit;

	if(!rs_get_flash_info(&info))
		goto exit;

	status = info.data_len;

exit:
	return status;
}

