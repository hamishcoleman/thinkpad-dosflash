/*
 * Provide the infrastructure needed to talk to the Thinkpad SMI
 * interface used to flash the BIOS.
 *
 * Intended to eventually allow building a replacement for dosflash.exe
 *
 * Based on the generic_nvram.c driver
 *
 */

#include <linux/module.h>

#include <linux/types.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/miscdevice.h>
#include <linux/fcntl.h>
#include <linux/init.h>
#include <linux/mutex.h>
#include <linux/pagemap.h>
#include <asm/uaccess.h>
#ifdef CONFIG_PPC_PMAC
#include <asm/machdep.h>
#endif

/* some quick hacks to make this compile */
/* they will be removed as I actually write code */
#define nvram_read_byte(i)      i
#define nvram_write_byte(c, i)  0
#define nvram_sync()            0
#define IOC_NVRAM_SYNC          0

static DEFINE_MUTEX(dosflash_mutex);    /* protect ioctl */
static ssize_t dummy_len;               /* size of the fake read/write area */

static loff_t dosflash_llseek(struct file *file, loff_t offset, int origin)
{
	return generic_file_llseek_size(file, offset, origin,
					MAX_LFS_FILESIZE, dummy_len);
}

static ssize_t read_dosflash(struct file *file, char __user *buf,
			  size_t count, loff_t *ppos)
{
	unsigned int i;
	char __user *p = buf;

	if (!access_ok(VERIFY_WRITE, buf, count))
		return -EFAULT;
	if (*ppos >= dummy_len)
		return 0;
	for (i = *ppos; count > 0 && i < dummy_len; ++i, ++p, --count)
		if (__put_user(nvram_read_byte(i), p))
			return -EFAULT;
	*ppos = i;
	return p - buf;
}

static ssize_t write_dosflash(struct file *file, const char __user *buf,
			   size_t count, loff_t *ppos)
{
	unsigned int i;
	const char __user *p = buf;
	char c;

	if (!access_ok(VERIFY_READ, buf, count))
		return -EFAULT;
	if (*ppos >= dummy_len)
		return 0;
	for (i = *ppos; count > 0 && i < dummy_len; ++i, ++p, --count) {
		if (__get_user(c, p))
			return -EFAULT;
		nvram_write_byte(c, i);
	}
	*ppos = i;
	return p - buf;
}

static int dosflash_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	switch(cmd) {
#ifdef CONFIG_PPC_PMAC
	case OBSOLETE_PMAC_NVRAM_GET_OFFSET:
		printk(KERN_WARNING "nvram: Using obsolete PMAC_NVRAM_GET_OFFSET ioctl\n");
	case IOC_NVRAM_GET_OFFSET: {
		int part, offset;

		if (!machine_is(powermac))
			return -EINVAL;
		if (copy_from_user(&part, (void __user*)arg, sizeof(part)) != 0)
			return -EFAULT;
		if (part < pmac_nvram_OF || part > pmac_nvram_NR)
			return -EINVAL;
		offset = pmac_get_partition(part);
		if (copy_to_user((void __user*)arg, &offset, sizeof(offset)) != 0)
			return -EFAULT;
		break;
	}
#endif /* CONFIG_PPC_PMAC */
	case IOC_NVRAM_SYNC:
		nvram_sync();
		break;
	default:
		return -EINVAL;
	}

	return 0;
}

static long dosflash_unlocked_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	int ret;

	mutex_lock(&dosflash_mutex);
	ret = dosflash_ioctl(file, cmd, arg);
	mutex_unlock(&dosflash_mutex);

	return ret;
}

const struct file_operations dosflash_fops = {
	.owner		= THIS_MODULE,
	.llseek		= dosflash_llseek,
	.read		= read_dosflash,
	.write		= write_dosflash,
	.unlocked_ioctl	= dosflash_unlocked_ioctl,
};

static struct miscdevice dosflash_dev = {
	MISC_DYNAMIC_MINOR,
	"dosflash",
	&dosflash_fops
};

int __init dosflash_init(void)
{
	int ret = 0;

	printk(KERN_INFO "Thinkpad SMI interface driver\n");
	ret = misc_register(&dosflash_dev);
	if (ret != 0)
		goto out;

        dummy_len = 256;

out:
	return ret;
}

void __exit dosflash_cleanup(void)
{
        misc_deregister( &dosflash_dev );
}

module_init(dosflash_init);
module_exit(dosflash_cleanup);
MODULE_LICENSE("GPL");
