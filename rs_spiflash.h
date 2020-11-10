#ifndef RS_SPIFLASH_H
#define RS_SPIFLASH_H

typedef struct {
	unsigned char device_id[4];
	unsigned char version[4];
	unsigned char flashtype[4];
	unsigned char date[6];
	unsigned int config_star;
	unsigned int config_len;
	unsigned int data_start;
	unsigned int data_len;
	unsigned char md5[16];
}FLASH_INFO, *PFLASH_INFO;

typedef struct {
	unsigned char reserved[4096];
}COMMOM_CONFIG, *PCOMMOM_CONFIG;

int rs_dev_id_ops(unsigned char id[4], unsigned int write);
int rs_version_ops(unsigned char version[4], unsigned int write);
int rs_get_commom_config(PCOMMOM_CONFIG cfg);
int rs_write_commom_config(PCOMMOM_CONFIG cfg);
/*returns a value greater than 0 on success, zero on failure*/
int rs_write_data_to_flash(void *data, unsigned int data_size);
/*returns data size on success, zero on failure*/
unsigned int rs_read_data_from_flash(void *data);

#endif