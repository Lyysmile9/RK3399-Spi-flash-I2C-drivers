#define DEBUG
#include <linux/init.h>
#include <linux/module.h>
#include <linux/ioctl.h>
#include <linux/fs.h>
#include <linux/device.h>
#include <linux/err.h>
#include <linux/list.h>
#include <linux/errno.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include <linux/compat.h>
#include <linux/of.h>
#include <linux/of_device.h>
#include <linux/kernel.h>
#include <linux/i2c.h>
#include <linux/uaccess.h>
#include "w25q64.h"

#define M031_MAJOR			154
#define N_M031_MINORS			32
static DECLARE_BITMAP(minors, N_M031_MINORS);

static unsigned int bufsiz = 4096;

typedef enum {
		get_status = 0x20,
        erase_flash = 0x40,
        write_flash = 0x80,
        read_flash = 0xff,
}SPI_OPS;

struct m031_data {
	dev_t			devt;
	spinlock_t		m031_lock;
	struct i2c_client	*m031_client;
	struct list_head	device_entry;

	/* TX/RX buffers are NULL unless this device is open (users > 0) */
	struct mutex		buf_lock;
	unsigned		users;
	u8			*tx_buffer;
	u8			*rx_buffer;
	unsigned int cur_addr;
};

static LIST_HEAD(device_list);
static DEFINE_MUTEX(device_list_lock);

static int m031_open(struct inode *inode, struct file *filp)
{
	struct m031_data	*m031dev;
	int			status = -ENXIO;

	mutex_lock(&device_list_lock);

	list_for_each_entry(m031dev, &device_list, device_entry) {
		if (m031dev->devt == inode->i_rdev) {
			status = 0;
			break;
		}
	}

	if (status) {
		pr_debug("m031dev: nothing for minor %d\n", iminor(inode));
		goto err_find_dev;
	}

	if (!m031dev->tx_buffer) {
		m031dev->tx_buffer = kmalloc(bufsiz, GFP_KERNEL);
		if (!m031dev->tx_buffer) {
			dev_dbg(&m031dev->m031_client->dev, "open/ENOMEM\n");
			status = -ENOMEM;
			goto err_find_dev;
		}
	}

	if (!m031dev->rx_buffer) {
		m031dev->rx_buffer = kmalloc(bufsiz, GFP_KERNEL);
		if (!m031dev->rx_buffer) {
			dev_dbg(&m031dev->m031_client->dev, "open/ENOMEM\n");
			status = -ENOMEM;
			goto err_alloc_rx_buf;
		}
	}

	m031dev->users++;
	filp->private_data = m031dev;

	mutex_unlock(&device_list_lock);
	return 0;

err_alloc_rx_buf:
	kfree(m031dev->tx_buffer);
	m031dev->tx_buffer = NULL;
err_find_dev:
	mutex_unlock(&device_list_lock);
	return status;
}

static int m031_release(struct inode *inode, struct file *filp)
{
	struct m031_data	*m031dev;

	mutex_lock(&device_list_lock);
	m031dev = filp->private_data;
	filp->private_data = NULL;

	/* last close? */
	m031dev->users--;
	if (!m031dev->users) {
		int		dofree;

		kfree(m031dev->tx_buffer);
		m031dev->tx_buffer = NULL;

		kfree(m031dev->rx_buffer);
		m031dev->rx_buffer = NULL;

		spin_lock_irq(&m031dev->m031_lock);
		/* ... after we unbound from the underlying device? */
		dofree = (m031dev->m031_client == NULL);
		spin_unlock_irq(&m031dev->m031_lock);

		if (dofree)
			kfree(m031dev);
	}
	mutex_unlock(&device_list_lock);

	return 0;
}

static unsigned char firefly_i2c_get_flash_status(struct m031_data *m031dev)
{
	int ret;
	struct i2c_client *client = m031dev->m031_client;
	struct i2c_adapter *adap = client->adapter;
	struct i2c_msg msg[2];
	unsigned char buf[7] = {0};
	unsigned char status;

	buf[0] = get_status;
	msg[0].addr = client->addr;
	msg[0].flags = client->flags & I2C_M_TEN;
	msg[0].len = ARRAY_SIZE(buf);
	msg[0].buf = buf;
	ret = i2c_transfer(adap, &msg[0], 1);
	if (ret == 1)
		dev_dbg(&client->dev, "get flash status\n");

	msg[1].addr = client->addr;
	msg[1].flags = client->flags | I2C_M_RD;
	msg[1].len = 1;
	msg[1].buf = &status;
	ret = i2c_transfer(adap, &msg[1], 1);
	if (ret == 1)
		dev_dbg(&client->dev, "read flash status\n");
	
	return status;
}

static int firefly_wait_flash_ready(struct m031_data *m031dev)
{
	unsigned char ret = 1;
	do {
		ret = firefly_i2c_get_flash_status(m031dev);
	}while (ret != 0);

	return ret;
}
static int firefly_i2c_master_send(struct m031_data *m031dev, size_t len)
{
	int ret;
	struct i2c_client *client = m031dev->m031_client;
	struct i2c_adapter *adap = client->adapter;
	struct i2c_msg msg;
	size_t size = len;
	unsigned char *buffer;
	unsigned int count = 0;
	unsigned int flash_addr = m031dev->cur_addr;

	while (len > 0) {
		printk("send len:%ld\n", len);
		firefly_wait_flash_ready(m031dev);
		if (len > W25Q64_PAGE_LENGTH) {
			buffer = kzalloc(W25Q64_PAGE_LENGTH + 7, GFP_KERNEL);
			if (!buffer)
				return-ENOMEM;
			/*assign flag & flash addr & data size*/
			buffer[0] = write_flash;
			buffer[1] = (unsigned char)((flash_addr & 0xff0000) >> 16);
			buffer[2] = (unsigned char)((flash_addr & 0xff00) >> 8);
			buffer[3] = (unsigned char)(flash_addr & 0xff);
			buffer[4] = (unsigned char)((W25Q64_PAGE_LENGTH & 0xff0000) >> 16);
			buffer[5] = (unsigned char)((W25Q64_PAGE_LENGTH & 0xff00) >> 8);
			buffer[6] = (unsigned char)(W25Q64_PAGE_LENGTH & 0xff);
			/*copy data to buffer*/
			memcpy(&buffer[7], &m031dev->tx_buffer[count], W25Q64_PAGE_LENGTH);

			msg.addr = client->addr;
			msg.flags = client->flags & I2C_M_TEN;
			msg.len = W25Q64_PAGE_LENGTH + 7;
			msg.buf = buffer;
			ret = i2c_transfer(adap, &msg, 1);
			if (ret == 1)
				dev_dbg(&client->dev, "transmit: 256 byte\n");
			else
				goto exit;

			count += W25Q64_PAGE_LENGTH;
			len -= W25Q64_PAGE_LENGTH;
			flash_addr += W25Q64_PAGE_LENGTH;
		}else {
			buffer = kzalloc(len + 7, GFP_KERNEL);
			if (!buffer)
				return-ENOMEM;

			buffer[0] = write_flash;
			buffer[1] = (unsigned char)((flash_addr & 0xff0000) >> 16);
			buffer[2] = (unsigned char)((flash_addr & 0xff00) >> 8);
			buffer[3] = (unsigned char)(flash_addr & 0xff);

			buffer[4] = (unsigned char)((len & 0xff0000) >> 16);
			buffer[5] = (unsigned char)((len & 0xff00) >> 8);
			buffer[6] = (unsigned char)(len & 0xff);

			memcpy(&buffer[7], &m031dev->tx_buffer[count], len);
			
			msg.addr = client->addr;
			msg.flags = client->flags & I2C_M_TEN;
			msg.len = len + 7;
			msg.buf = buffer;
			ret = i2c_transfer(adap, &msg, 1);
			if (ret == 1)
				dev_dbg(&client->dev, "transmit: %d byte\n", msg.len - 7);
			else
				goto exit;

			count += len;
			len = 0;
			flash_addr += len;
		}
		kfree(buffer);
		buffer = NULL;
	}
	/*
	 * If everything went ok (i.e. 1 msg transmitted), return #bytes
	 * transmitted, else error code.
	 */
exit:
	if (buffer)
		kfree(buffer);
	return (ret == 1) ? size : ret;
}

static ssize_t m031_write(struct file *filp, const char __user *buf,
		size_t count, loff_t *f_pos)
{
	struct m031_data	*m031dev;
	ssize_t			status = 0;
	unsigned long		missing;

	if (count > bufsiz)
		return -EMSGSIZE;

	m031dev = filp->private_data;

	mutex_lock(&m031dev->buf_lock);
	missing = copy_from_user(m031dev->tx_buffer, buf, count);
	if (missing == 0)
		status = firefly_i2c_master_send(m031dev, count);
	else
		status = -EFAULT;
	mutex_unlock(&m031dev->buf_lock);

	return status; 
}
	
static int firefly_i2c_master_recv(struct m031_data *m031dev, size_t len)
{
	int ret;
	struct i2c_client *client = m031dev->m031_client;
	struct i2c_adapter *adap = client->adapter;
	struct i2c_msg msg[2];
	size_t size = len;
	unsigned int count = 0;
	unsigned char *buffer;
	unsigned int flash_addr = m031dev->cur_addr;

	while(len > 0) {
		unsigned char head_info[7];
		firefly_wait_flash_ready(m031dev);
		if (len > W25Q64_PAGE_LENGTH) {
			head_info[0] = read_flash;
			head_info[1] = (unsigned char)((flash_addr & 0xff0000) >> 16);
			head_info[2] = (unsigned char)((flash_addr & 0xff00) >> 8);
			head_info[3] = (unsigned char)(flash_addr & 0xff);

			head_info[4] = (unsigned char)((W25Q64_PAGE_LENGTH & 0xff0000) >> 16);
			head_info[5] = (unsigned char)((W25Q64_PAGE_LENGTH & 0xff00) >> 8);
			head_info[6] = (unsigned char)(W25Q64_PAGE_LENGTH & 0xff);

			msg[0].addr = client->addr;
			msg[0].flags = client->flags;
			msg[0].len = sizeof(head_info);
			msg[0].buf = head_info;
			ret = i2c_transfer(adap, &msg[0], 1);
			if (ret == 1)
				dev_dbg(&client->dev, "transmit: %d byte\n", msg[0].len);
			else
				goto exit;
			
			buffer = kzalloc(W25Q64_PAGE_LENGTH, GFP_KERNEL);
			if (!buffer)
				return-ENOMEM;

			msg[1].addr = client->addr;
			msg[1].flags = client->flags | I2C_M_RD;
			msg[1].len = W25Q64_PAGE_LENGTH;
			msg[1].buf = buffer;
			ret = i2c_transfer(adap, &msg[1], 1);
			if (ret == 1)
				dev_dbg(&client->dev, "transmit: 256 byte\n");
			else
				goto exit;

			memcpy(&m031dev->rx_buffer[count], &buffer[count], W25Q64_PAGE_LENGTH);

			count += W25Q64_PAGE_LENGTH;
			len -= W25Q64_PAGE_LENGTH;
			flash_addr += W25Q64_PAGE_LENGTH;
		}else {
			head_info[0] = read_flash;
			head_info[1] = (unsigned char)((flash_addr & 0xff0000) >> 16);
			head_info[2] = (unsigned char)((flash_addr & 0xff00) >> 8);
			head_info[3] = (unsigned char)(flash_addr & 0xff);

			head_info[4] = (unsigned char)((len & 0xff0000) >> 16);
			head_info[5] = (unsigned char)((len & 0xff00) >> 8);
			head_info[6] = (unsigned char)(len & 0xff);

			msg[0].addr = client->addr;
			msg[0].flags = client->flags;
			msg[0].len = sizeof(head_info);
			msg[0].buf = head_info;
			ret = i2c_transfer(adap, &msg[0], 1);
			if (ret == 1)
				dev_dbg(&client->dev, "transmit: %d byte\n", msg[0].len);
			else
				goto exit;
			
			buffer = kzalloc(len, GFP_KERNEL);
			if (!buffer)
				return-ENOMEM;

			msg[1].addr = client->addr;
			msg[1].flags = client->flags | I2C_M_RD;
			msg[1].len = len;
			msg[1].buf = buffer;
			ret = i2c_transfer(adap, &msg[1], 1);
			if (ret == 1)
				dev_dbg(&client->dev, "transmit: %ld byte\n", len);
			else
				goto exit;

			memcpy(&m031dev->rx_buffer[count], buffer, len);

			count += len;
			len = 0;
			flash_addr += len;
		}
		kfree(buffer);
		buffer = NULL;
	}
exit:
	if(buffer)
		kfree(buffer);
	return (ret == 1) ? size : ret;
}

static ssize_t m031_read(struct file *filp, char __user *buf,
		size_t count, loff_t *f_pos)
{
	struct m031_data	*m031dev;
	ssize_t			status = 0;
	unsigned long		missing;

	if (count > bufsiz)
		return -EMSGSIZE;

	m031dev = filp->private_data;

	mutex_lock(&m031dev->buf_lock);
	status = firefly_i2c_master_recv(m031dev, count);
	if (status > 0) {
		missing = copy_to_user(buf, m031dev->rx_buffer, status);
		if (missing == status)
			status = -EFAULT;
		else
			status = status - missing;
	}
	mutex_unlock(&m031dev->buf_lock);

	return status; 
}

static loff_t m031_llseek(struct file *filp, loff_t offset, int orig)
{
	loff_t ret = 0;
	struct m031_data	*m031dev;

	m031dev = filp->private_data;
	switch (orig) {
	case SEEK_SET:
		if (offset < 0) {
			ret = -EINVAL;
			break;
		}
		if ((unsigned int)offset > W25Q64_SIZE) {
			ret = -EINVAL;
			break;
		}
		m031dev->cur_addr = (unsigned int)offset;
		ret = m031dev->cur_addr;
		break;
	case SEEK_CUR:
		if ((m031dev->cur_addr + offset) > W25Q64_SIZE) {
			ret = -EINVAL;
			break;
		}
		if ((m031dev->cur_addr + offset) < 0) {
			ret = -EINVAL;
			break;
		}
		m031dev->cur_addr += offset;
		ret = m031dev->cur_addr;
		break;
	default:
		ret =  - EINVAL;
		break;
	}
	dev_dbg(&m031dev->m031_client->dev, "set curr addr:%02X\n", (unsigned int)ret);
	return ret;
}

static int firefly_i2c_w25x_sector_erase(struct m031_data *m031dev, unsigned long size)
{
	int ret;
	struct i2c_client *client = m031dev->m031_client;
	struct i2c_adapter *adap = client->adapter;
	struct i2c_msg msg;
	unsigned int flash_addr = m031dev->cur_addr;
	unsigned char buf[7];
	int count = (int)size;

	for ( ; count > 0; count -= W25Q64_SECTOR) {
		buf[0] = erase_flash;
		buf[1] = (unsigned char)((flash_addr & 0xff0000) >> 16);
		buf[2] = (unsigned char)((flash_addr & 0xff00) >> 8);
		buf[3] = (unsigned char)(flash_addr & 0xff);
		buf[4] = (unsigned char)((W25Q64_SECTOR & 0xff0000) >> 16);
		buf[5] = (unsigned char)((W25Q64_SECTOR & 0xff00) >> 8);
		buf[6] = (unsigned char)(W25Q64_SECTOR & 0xff);

		msg.addr = client->addr;
		msg.flags = client->flags & I2C_M_TEN;
		msg.len = sizeof(buf);
		msg.buf = buf;
		ret = i2c_transfer(adap, &msg, 1);
		if (ret == 1)
			dev_dbg(&client->dev, "4 KB block erase...");
		flash_addr += W25Q64_SECTOR;
		if (!firefly_wait_flash_ready(m031dev))
			dev_dbg(&client->dev, "OK\n");
	}

	return ret;
}

static int firefly_i2c_w25x_32kb_block_erase(struct m031_data *m031dev)
{
	int ret;
	struct i2c_client *client = m031dev->m031_client;
	struct i2c_adapter *adap = client->adapter;
	struct i2c_msg msg;
	unsigned int flash_addr = m031dev->cur_addr;
	unsigned char buf[7];

	firefly_wait_flash_ready(m031dev);
	buf[0] = erase_flash;
	buf[1] = (unsigned char)((flash_addr & 0xff0000) >> 16);
	buf[2] = (unsigned char)((flash_addr & 0xff00) >> 8);
	buf[3] = (unsigned char)(flash_addr & 0xff);
	buf[4] = (unsigned char)((W25Q64_32KB_BLOCK & 0xff0000) >> 16);
	buf[5] = (unsigned char)((W25Q64_32KB_BLOCK & 0xff00) >> 8);
	buf[6] = (unsigned char)(W25Q64_32KB_BLOCK & 0xff);

	msg.addr = client->addr;
	msg.flags = client->flags & I2C_M_TEN;
	msg.len = sizeof(buf);
	msg.buf = buf;
	ret = i2c_transfer(adap, &msg, 1);
	if (ret == 1)
		dev_dbg(&client->dev, "32 KB block erase\n");

	return ret;
}

static int firefly_i2c_w25x_64kb_block_erase(struct m031_data *m031dev)
{
	int ret;
	struct i2c_client *client = m031dev->m031_client;
	struct i2c_adapter *adap = client->adapter;
	struct i2c_msg msg;
	unsigned int flash_addr = m031dev->cur_addr;
	unsigned char buf[7];

	firefly_wait_flash_ready(m031dev);
	buf[0] = erase_flash;
	buf[1] = (unsigned char)((flash_addr & 0xff0000) >> 16);
	buf[2] = (unsigned char)((flash_addr & 0xff00) >> 8);
	buf[3] = (unsigned char)(flash_addr & 0xff);
	buf[4] = (unsigned char)((W25Q64_64KB_BLOCK & 0xff0000) >> 16);
	buf[5] = (unsigned char)((W25Q64_64KB_BLOCK & 0xff00) >> 8);
	buf[6] = (unsigned char)(W25Q64_64KB_BLOCK & 0xff);

	msg.addr = client->addr;
	msg.flags = client->flags & I2C_M_TEN;
	msg.len = sizeof(buf);
	msg.buf = buf;
	ret = i2c_transfer(adap, &msg, 1);
	if (ret == 1)
		dev_dbg(&client->dev, "64 KB block erase\n");

	return ret;
}

static int firefly_i2c_w25x_chip_erase(struct m031_data *m031dev)
{
	int ret;
	struct i2c_client *client = m031dev->m031_client;
	struct i2c_adapter *adap = client->adapter;
	struct i2c_msg msg;
	unsigned int flash_addr = m031dev->cur_addr;
	unsigned char buf[7];

	firefly_wait_flash_ready(m031dev);
	buf[0] = erase_flash;
	buf[1] = (unsigned char)((flash_addr & 0xff0000) >> 16);
	buf[2] = (unsigned char)((flash_addr & 0xff00) >> 8);
	buf[3] = (unsigned char)(flash_addr & 0xff);
	buf[4] = (unsigned char)((W25Q64_SIZE & 0xff0000) >> 16);
	buf[5] = (unsigned char)((W25Q64_SIZE & 0xff00) >> 8);
	buf[6] = (unsigned char)(W25Q64_SIZE & 0xff);

	msg.addr = client->addr;
	msg.flags = client->flags & I2C_M_TEN;
	msg.len = sizeof(buf);
	msg.buf = buf;
	ret = i2c_transfer(adap, &msg, 1);
	if (ret == 1)
		dev_dbg(&client->dev, "chip erase\n");

	return ret;
}

static long m031_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	int	err = 0;
	int	retval = 0;
	struct m031_data *m031dev;

	/* Check type and command number */
	if (_IOC_TYPE(cmd) != W25Q64_MAGIC)
		return -ENOTTY;

	/* Check access direction once here; don't repeat below.
	 * IOC_DIR is from the user perspective, while access_ok is
	 * from the kernel perspective; so they look reversed.
	 */
	if (_IOC_DIR(cmd) & _IOC_READ)
		err = !access_ok(VERIFY_WRITE,
				(void __user *)arg, _IOC_SIZE(cmd));
	if (err == 0 && _IOC_DIR(cmd) & _IOC_WRITE)
		err = !access_ok(VERIFY_READ,
				(void __user *)arg, _IOC_SIZE(cmd));
	if (err)
		return -EFAULT;

	m031dev = filp->private_data;
	switch (cmd) {
	/* read requests */
	case W25Q64_IOC_SECTOR_ERASE:
		retval = firefly_i2c_w25x_sector_erase(m031dev, arg);
		break;
	case W25Q64_IOC_32KB_BLOCK_ERASE:
		retval = firefly_i2c_w25x_32kb_block_erase(m031dev);
		break;
	case W25Q64_IOC_64KB_BLOCK_ERASE:
		retval = firefly_i2c_w25x_64kb_block_erase(m031dev);
		break;
	case W25Q64_IOC_CHIP_ERASE:
		retval = firefly_i2c_w25x_chip_erase(m031dev);
		break;
		}
	return retval;
}

#ifdef CONFIG_COMPAT
static long
m031_compat_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	return m031_ioctl(filp, cmd, (unsigned long)compat_ptr(arg));
}
#else
#define m031_compat_ioctl NULL
#endif /* CONFIG_COMPAT */

static const struct file_operations m031_fops = {
	.owner =	THIS_MODULE,
	.write =	m031_write,
	.read =		m031_read,
	.unlocked_ioctl = m031_ioctl,
	.compat_ioctl = m031_compat_ioctl,
	.open =		m031_open,
	.release =	m031_release,
	.llseek =	m031_llseek,
};

static struct class *m031_class;
static struct of_device_id m031_ids[] = {
	{.compatible = "Nuvoton,m031fb0ae"},
	{}
};

static struct i2c_device_id m031_id[] = {
	{"m031fb0ae", 0},
	{}
};
MODULE_DEVICE_TABLE(i2c, m031_id);
		
static int m031_probe(struct i2c_client *client, const struct i2c_device_id *id)
{
	struct m031_data *m031dev;
	int			status;
	unsigned long		minor;

	dev_dbg(&client->dev, "probe\n");
	if (client->dev.of_node && !of_match_device(m031_ids, &client->dev)) {
		dev_err(&client->dev, "buggy DT: m031 listed directly in DT\n");
		WARN_ON(client->dev.of_node &&
			!of_match_device(m031_ids, &client->dev));
	}

	client->adapter->timeout = msecs_to_jiffies(50);

	/* Allocate driver data */
	m031dev = kzalloc(sizeof(*m031dev), GFP_KERNEL);
	if (!m031dev)
		return -ENOMEM;

	/* Initialize the driver data */
	m031dev->m031_client = client;
	spin_lock_init(&m031dev->m031_lock);
	mutex_init(&m031dev->buf_lock);

	INIT_LIST_HEAD(&m031dev->device_entry);
	
	mutex_lock(&device_list_lock);
		minor = find_first_zero_bit(minors, N_M031_MINORS);
		if (minor < N_M031_MINORS) {
			struct device *dev;
	
			m031dev->devt = MKDEV(M031_MAJOR, minor);
			dev = device_create(m031_class, &client->dev, m031dev->devt,
						m031dev, "w25q64");
			status = PTR_ERR_OR_ZERO(dev);
		} else {
			dev_dbg(&client->dev, "no minor number available!\n");
			status = -ENODEV;
		}
		if (status == 0) {
			set_bit(minor, minors);
			list_add(&m031dev->device_entry, &device_list);
		}
	mutex_unlock(&device_list_lock);
		
	if (status == 0)
		dev_set_drvdata(&client->dev, m031dev);
	else
		kfree(m031dev);

	return status;
}

static int m031_remove(struct i2c_client *client)
{
	struct m031_data *m031dev = dev_get_drvdata(&client->dev);

	/* make sure ops on existing fds can abort cleanly */
	spin_lock_irq(&m031dev->m031_lock);
	m031dev->m031_client = NULL;
	spin_unlock_irq(&m031dev->m031_lock);

	/* prevent new opens */
	mutex_lock(&device_list_lock);
	list_del(&m031dev->device_entry);
	device_destroy(m031_class, m031dev->devt);
	clear_bit(MINOR(m031dev->devt), minors);
	if (m031dev->users == 0)
		kfree(m031dev);
	mutex_unlock(&device_list_lock);

	return 0;
}

static struct i2c_driver m031_driver = {
	.driver = {
		.name = "m031",
		.owner = THIS_MODULE,
		.of_match_table = of_match_ptr(m031_ids),
		},
	.probe = m031_probe,
	.remove = m031_remove,
	.id_table = m031_id,
};

static int __init m031_init(void)
{
	int status;

	status = register_chrdev(M031_MAJOR, "m031", &m031_fops);
	if (status < 0)
		return status;

	m031_class = class_create(THIS_MODULE, "m031");
	if (IS_ERR(m031_class)) {
		unregister_chrdev(M031_MAJOR, m031_driver.driver.name);
		return PTR_ERR(m031_class);
	}

	status = i2c_add_driver(&m031_driver);
	if (status < 0) {
		class_destroy(m031_class);
		unregister_chrdev(M031_MAJOR, m031_driver.driver.name);
	}
	return status;
}
module_init(m031_init);

static void __exit m031_exit(void)
{
	i2c_del_driver(&m031_driver);
	class_destroy(m031_class);
	unregister_chrdev(M031_MAJOR, m031_driver.driver.name);
}
module_exit(m031_exit);

MODULE_AUTHOR("jfhuang@raysees.com");
MODULE_LICENSE("GPL");

