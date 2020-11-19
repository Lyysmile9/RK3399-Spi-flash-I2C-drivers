#ifndef RS_SPIFLASH_H
#define RS_SPIFLASH_H

typedef struct {
	unsigned char device_id[4];
	unsigned char version[4];
	unsigned char flashtype[4];
	unsigned char date[6];
	unsigned int config_start;
	unsigned int config_len;
	unsigned int data_start;
	unsigned int data_len;
	unsigned char md5[16];
}FLASH_INFO, *PFLASH_INFO;

/*returns a value greater than 0 on success, zero on failure*/
int rs_dev_id_ops(unsigned char id[4], unsigned int write);
int rs_version_ops(unsigned char version[4], unsigned int write);
int rs_read_common_config(void *buf);
int rs_write_common_config(void *data, unsigned int size);
int rs_read_data_from_flash(void *buf);
int rs_write_data_to_flash(void *data, unsigned int size);
int rs_write_flash_info();
int rs_read_flash_info();
int rs_get_data_len();
int rs_get_config_len();
#endif
