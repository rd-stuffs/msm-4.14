#include <linux/input/tp_common.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/uaccess.h>

bool capacitive_keys_enabled;
struct kobject *touchpanel_kobj;

static struct tp_common_ops *double_tap_ops;
static struct proc_dir_entry *tp_gesture_proc;

#define TS_ENABLE_FOPS(type)                                                   \
	int tp_common_set_##type##_ops(struct tp_common_ops *ops)              \
	{                                                                      \
		static struct kobj_attribute kattr =                           \
			__ATTR(type, (S_IWUSR | S_IRUGO), NULL, NULL);         \
		kattr.show = ops->show;                                        \
		kattr.store = ops->store;                                      \
		return sysfs_create_file(touchpanel_kobj, &kattr.attr);        \
	}

TS_ENABLE_FOPS(capacitive_keys)
TS_ENABLE_FOPS(reversed_keys)

static int tp_gesture_proc_show(struct seq_file *m, void *v)
{
	char buf[32];
	int len;

	if (!double_tap_ops || !double_tap_ops->show)
		return -EINVAL;

	len = double_tap_ops->show(NULL, NULL, buf);
	if (len > 0)
		seq_write(m, buf, len);

	return 0;
}

static int tp_gesture_proc_open(struct inode *inode, struct file *file)
{
	return single_open(file, tp_gesture_proc_show, NULL);
}

static ssize_t tp_gesture_proc_write(struct file *file,
				    const char __user *buffer,
				    size_t count, loff_t *pos)
{
	char buf[32];

	if (!double_tap_ops || !double_tap_ops->store)
		return -EINVAL;

	if (count >= sizeof(buf))
		return -EINVAL;

	if (copy_from_user(buf, buffer, count))
		return -EFAULT;

	buf[count] = '\0';
	return double_tap_ops->store(NULL, NULL, buf, count);
}

static const struct file_operations tp_gesture_proc_ops = {
	.open    = tp_gesture_proc_open,
	.read    = seq_read,
	.llseek  = seq_lseek,
	.release = single_release,
	.write   = tp_gesture_proc_write,
};

int tp_common_set_double_tap_ops(struct tp_common_ops *ops)
{
	static struct kobj_attribute kattr =
		__ATTR(double_tap, (S_IWUSR | S_IRUGO), NULL, NULL);

	kattr.show  = ops->show;
	kattr.store = ops->store;

	double_tap_ops = ops;

	if (!tp_gesture_proc) {
		tp_gesture_proc = proc_create(
			"tp_gesture",
			0664,
			NULL,
			&tp_gesture_proc_ops
		);
		if (!tp_gesture_proc)
			return -ENOMEM;
	}

	return sysfs_create_file(touchpanel_kobj, &kattr.attr);
}

static int __init tp_common_init(void)
{
	touchpanel_kobj = kobject_create_and_add("touchpanel", NULL);
	if (!touchpanel_kobj)
		return -ENOMEM;

	return 0;
}

core_initcall(tp_common_init);
