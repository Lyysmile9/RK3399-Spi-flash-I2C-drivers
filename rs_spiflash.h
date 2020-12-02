#ifndef RS_SPIFLASH_H
#define RS_SPIFLASH_H

/*returns a value greater than 0 on success, zero on failure*/
int rs_dev_id_ops(unsigned char id[4], unsigned int write);
int rs_version_ops(unsigned char version[4], unsigned int write);
int rs_read_common_config(void *buf);
int rs_write_common_config(void *data, unsigned int size);
int rs_read_data_from_flash(void *buf);
int rs_write_data_to_flash(void *data, unsigned int size);
int rs_get_data_len();
int rs_get_config_len();
#endif
