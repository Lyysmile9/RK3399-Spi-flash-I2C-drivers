#define DEBUG
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/err.h>
#include <linux/io.h>
#include <linux/of.h>
#include <linux/interrupt.h>
#include <linux/platform_device.h>
#include <linux/spi/spi.h>
#include <linux/spi/spidev.h>
#include <linux/cdev.h>
#include <linux/uaccess.h>

static LIST_HEAD(device_list);
static DEFINE_MUTEX(device_list_lock);
static unsigned bufsize = 4096;
//static struct class *spiflash;

struct spiflash_dev {
	dev_t			devt;
	struct cdev	cdev;
	spinlock_t		spi_lock;
	struct spi_device	*spi;
	struct list_head	device_entry;

	/* TX/RX buffers are NULL unless this device is open (users > 0) */
	struct mutex		buf_lock;
	unsigned		users;
	u8			*tx_buffer;
	u8			*rx_buffer;
	u32			speed_hz;
};

static struct spiflash_dev *spiflash_devp;

#define FIREFLY_SPI_READ_ID_CMD 0x9F
#define W25Q64_FLASH_READ_DATA_CMD 0x03

#define FIREFLY_SPI_PRINT_ID(rbuf) \
	do { \
		if (status == 0) \
		dev_dbg(&spi->dev, "%s: ID = %02x %02x %02x %02x %02x\n", __FUNCTION__, \
				rbuf[0], rbuf[1], rbuf[2], rbuf[3], rbuf[4]); \
		else \
		dev_err(&spi->dev, "%s: read ID error\n", __FUNCTION__); \
	}while(0)


static inline ssize_t spiflash_sync_write(struct spiflash_dev *dev, size_t len)
{
	struct spi_transfer	t = {
		.tx_buf		= dev->tx_buffer,
		.len		= len,
		.speed_hz	= dev->speed_hz,
	};
	struct spi_message	m;

	spi_message_init(&m);
	spi_message_add_tail(&t, &m);
	return spi_sync(dev->spi, &m);
}

static ssize_t spiflash_write(struct file *filp, const char __user *buf,
		size_t count, loff_t *f_pos)
{
	ssize_t status;
	struct spiflash_dev *dev;
	unsigned long missing;

	dev = filp->private_data;

	mutex_lock(&dev->buf_lock);
	missing = copy_from_user(dev->tx_buffer, buf, count);
	if (missing == 0)
		status = spiflash_sync_write(dev, count);
	else
		status = -EFAULT;
	mutex_unlock(&dev->buf_lock);

	return status;
}

static inline ssize_t spiflash_sync_read(struct spiflash_dev *dev, size_t len)
{
	char tbuf[4] = {W25Q64_FLASH_READ_DATA_CMD, 0, 0, 0};

	struct spi_transfer	t = {
		.tx_buf		= tbuf,
		.len		= sizeof(tbuf),
		.speed_hz	= dev->speed_hz,
	};
	struct spi_transfer	r = {
		.rx_buf		= dev->rx_buffer,
		.len		= len,
		.speed_hz	= dev->speed_hz,
	};
	struct spi_message	m;

	spi_message_init(&m);
	spi_message_add_tail(&t, &m);
	spi_message_add_tail(&r, &m);
	return spi_sync(dev->spi, &m);
}

static ssize_t spiflash_read(struct file *filp, char __user *buf,
		size_t count, loff_t *f_pos)
{
	struct spiflash_dev	*spidev;
	ssize_t 		status = 0;

	spidev = filp->private_data;

	mutex_lock(&spidev->buf_lock);
	status = spiflash_sync_read(spidev, count);
	if (status > 0) {
		unsigned long	missing;

		missing = copy_to_user(buf, spidev->rx_buffer, status);
		if (missing == status)
			status = -EFAULT;
		else
			status = status - missing;
	}

	mutex_unlock(&spidev->buf_lock);
	return status;
}

static int spiflash_open(struct inode *inode, struct file *filp)
{
	struct spiflash_dev	*spidev;
	int			status = -ENXIO;

	mutex_lock(&device_list_lock);

	list_for_each_entry(spidev, &device_list, device_entry) {
		if (spidev->devt == inode->i_rdev) {
			status = 0;
			break;
		}
	}

	if (status) {
		pr_debug("spiflash: nothing for minor %d\n", iminor(inode));
		goto err_find_dev;
	}

	if (!spidev->tx_buffer) {
		spidev->tx_buffer = kmalloc(bufsize, GFP_KERNEL);
		if (!spidev->tx_buffer) {
			dev_dbg(&spidev->spi->dev, "open/ENOMEM\n");
			status = -ENOMEM;
			goto err_find_dev;
		}
	}

	if (!spidev->rx_buffer) {
		spidev->rx_buffer = kmalloc(bufsize, GFP_KERNEL);
		if (!spidev->rx_buffer) {
			dev_dbg(&spidev->spi->dev, "open/ENOMEM\n");
			status = -ENOMEM;
			goto err_alloc_rx_buf;
		}
	}

	spidev->users++;
	filp->private_data = spidev;
	nonseekable_open(inode, filp);

	mutex_unlock(&device_list_lock);
	return 0;

err_alloc_rx_buf:
	kfree(spidev->tx_buffer);
	spidev->tx_buffer = NULL;
err_find_dev:
	mutex_unlock(&device_list_lock);
	return status;
}

static int spiflash_release(struct inode *inode, struct file *filp)
{
	struct spiflash_dev	*spidev;

	mutex_lock(&device_list_lock);
	spidev = filp->private_data;
	filp->private_data = NULL;

	/* last close? */
	spidev->users--;
	if (!spidev->users) {
		int		dofree;

		kfree(spidev->tx_buffer);
		spidev->tx_buffer = NULL;

		kfree(spidev->rx_buffer);
		spidev->rx_buffer = NULL;

		spin_lock_irq(&spidev->spi_lock);
		if (spidev->spi)
			spidev->speed_hz = spidev->spi->max_speed_hz;

		/* ... after we unbound from the underlying device? */
		dofree = (spidev->spi == NULL);
		spin_unlock_irq(&spidev->spi_lock);

		if (dofree)
			kfree(spidev);
	}
	mutex_unlock(&device_list_lock);

	return 0;
}

static const struct file_operations spiflash_fops = {
	.owner = THIS_MODULE,
	.write = spiflash_write,
	.read = spiflash_read,
	.unlocked_ioctl = NULL,
	.compat_ioctl = NULL,
	.open = spiflash_open,
	.release = spiflash_release,
	.llseek = NULL,
};

static int firefly_spi_read_w25x_id_0(struct spi_device *spi)
{       
	int     status;
	char tbuf[]={FIREFLY_SPI_READ_ID_CMD};
	char rbuf[5];

	struct spi_transfer     t = {
		.tx_buf         = tbuf,
		.len            = sizeof(tbuf),
	};

	struct spi_transfer     r = {
		.rx_buf         = rbuf,
		.len            = sizeof(rbuf),
	};
	struct spi_message      m;

	spi_message_init(&m);
	spi_message_add_tail(&t, &m);
	spi_message_add_tail(&r, &m);
	status = spi_sync(spi, &m);

	printk("%s ID = %02x %02x %02x %02x %02x\n", __FUNCTION__, rbuf[0], rbuf[1], rbuf[2], rbuf[3], rbuf[4]);
	return status;
}


static int firefly_spi_read_w25x_id_1(struct spi_device *spi)
{
	int     status;
	char tbuf[] = {FIREFLY_SPI_READ_ID_CMD};
	char rbuf[5];

	status = spi_write_then_read(spi, tbuf, sizeof(tbuf), rbuf, sizeof(rbuf));
	printk("%s ID = %02x %02x %02x %02x %02x\n", __FUNCTION__, rbuf[0], rbuf[1], rbuf[2], rbuf[3], rbuf[4]);
	return status;
}

static int firefly_spi_probe(struct spi_device *spi)
{
	int ret = 0;
//	int status;
	struct device_node __maybe_unused *np = spi->dev.of_node;
	struct spiflash_dev *dev = spiflash_devp;

	dev_dbg(&spi->dev, "Firefly SPI demo program\n");
	printk("firefly spi demo\r\n");

	dev = kzalloc(sizeof(struct spiflash_dev), GFP_KERNEL);
	if (!dev)
		return -ENOMEM;

	ret = alloc_chrdev_region(&dev->devt, 0, 1, "spiflash");
	printk(KERN_ALERT "alloc device number:%d, return v = %d\n", dev->devt, ret);

	cdev_init(&dev->cdev, &spiflash_fops);
	dev->cdev.owner = THIS_MODULE;
	ret = cdev_add(&dev->cdev, dev->devt, 1);
	if (ret < 0)
		printk(KERN_ALERT "Error code:%d adding spiflash\n", ret);
#if 0
	spiflash = class_create(THIS_MODULE, "firefly-spi");
	if (!spiflash){
		printk("create class spiflash failed\n");
		return -1;
	}

#endif
	if(!spi)        
		return -ENOMEM;

	/* Initialize the driver data */
	dev->spi = spi;
	spin_lock_init(&dev->spi_lock);
	mutex_init(&dev->buf_lock);

	INIT_LIST_HEAD(&dev->device_entry);
#if 0
	{
		struct device *dev;
		dev = device_create(spiflash, &spi->dev, dev->devt, dev, "spiflash");
		status = PTR_ERR_OR_ZERO(dev);
	}
	if (status == 0)
		list_add(&dev->device_entry, &device_list);
	else
		printk(KERN_ALERT "device create error\n");
#endif
	dev->speed_hz = spi->max_speed_hz;

	spi_set_drvdata(spi, dev);

	dev_dbg(&spi->dev, "firefly_spi_probe: setup mode %d, %s%s%s%s%u bits/w, %u Hz max\n",
			(int) (spi->mode & (SPI_CPOL | SPI_CPHA)),
			(spi->mode & SPI_CS_HIGH) ? "cs_high, " : "",
			(spi->mode & SPI_LSB_FIRST) ? "lsb, " : "",
			(spi->mode & SPI_3WIRE) ? "3wire, " : "",
			(spi->mode & SPI_LOOP) ? "loopback, " : "",
			spi->bits_per_word, spi->max_speed_hz);

	firefly_spi_read_w25x_id_0(spi);
	firefly_spi_read_w25x_id_1(spi);

	return ret;
}

static int firefly_spi_remove(struct spi_device *spi)
{
	struct spiflash_dev *spidev = spi_get_drvdata(spi);

	spin_lock_irq(&spidev->spi_lock);
	spidev->spi = NULL;
	spin_unlock_irq(&spidev->spi_lock);

	mutex_lock(&device_list_lock);
	list_del(&spidev->device_entry);
//	device_destroy(spiflash, spidev->devt);
	cdev_del(&spidev->cdev);
	unregister_chrdev_region(spidev->devt, 1);
	if (spidev->users == 0)
		kfree(spidev);
	mutex_unlock(&device_list_lock);
	return 0;
}

static struct of_device_id firefly_match_table[] = {
	{ .compatible = "firefly,rk3399-spi",},
	{},
};

static struct spi_driver firefly_spi_driver = {
	.driver = {
		.name = "firefly-spi",
		.of_match_table = of_match_ptr(firefly_match_table),
	},
	.probe = firefly_spi_probe,
	.remove = firefly_spi_remove,
};

static int firefly_spi_init(void)
{
	int retval;

	retval = spi_register_driver(&firefly_spi_driver);
	printk(KERN_ALERT "register firefly_spi_init spi return v = :%d\n",retval);
	return retval;
}

module_init(firefly_spi_init);

static void firefly_spi_exit(void)
{
	spi_unregister_driver(&firefly_spi_driver);
}
module_exit(firefly_spi_exit);

MODULE_AUTHOR("zhansb <service@t-firefly.com>");
MODULE_DESCRIPTION("Firefly SPI demo driver");
MODULE_ALIAS("platform:firefly-spi");
MODULE_LICENSE("GPL");
