#ifndef W25Q64_H
#define W25Q64_H

#include <linux/types.h>
#include <linux/ioctl.h>

#define W25Q64_SIZE 0x800000

/* IOCTL commands */
#define W25Q64_MAGIC			'k'

/*Erase SPI Flash*/
#define W25Q64_IOC_SECTOR_ERASE			_IOW(W25Q64_MAGIC, 6, __u32)
#define W25Q64_IOC_32KB_BLOCK_ERASE		_IOW(W25Q64_MAGIC, 7, __u32)
#define W25Q64_IOC_64KB_BLOCK_ERASE		_IOW(W25Q64_MAGIC, 8, __u32)
#define W25Q64_IOC_CHIP_ERASE			_IOW(W25Q64_MAGIC, 9, __u32)

#endif /* W25Q64_H */
