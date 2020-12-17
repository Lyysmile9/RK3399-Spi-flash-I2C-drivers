#ifndef W25Q64_H
#define W25Q64_H

#include <linux/types.h>
#include <linux/ioctl.h>

#define W25Q64_SIZE 0x800000
#define W25Q64_PAGE_LENGTH	256
#define W25Q64_SECTOR	4096
#define W25Q64_32KB_BLOCK 32768
#define W25Q64_64KB_BLOCK 65536

/* IOCTL commands */
#define W25Q64_MAGIC			'k'

/*Erase SPI Flash*/
#define W25Q64_IOC_SECTOR_ERASE			_IOW(W25Q64_MAGIC, 6, __u32)
#define W25Q64_IOC_32KB_BLOCK_ERASE		_IOW(W25Q64_MAGIC, 7, __u32)
#define W25Q64_IOC_64KB_BLOCK_ERASE		_IOW(W25Q64_MAGIC, 8, __u32)
#define W25Q64_IOC_CHIP_ERASE			_IOW(W25Q64_MAGIC, 9, __u32)

#endif /* W25Q64_H */
