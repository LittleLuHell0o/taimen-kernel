/* ksu_krw.h -- KernelSU compatibility shim for kernel_read()/kernel_write()
 *
 * Linux < 4.14 declares:
 *     int kernel_read (struct file *file, loff_t offset, char *addr, unsigned long count);
 *     int kernel_write(struct file *file, const char *addr, unsigned long count, loff_t pos);
 * Linux >= 4.14 declares:
 *     ssize_t kernel_read (struct file *file, void *buf, size_t count, loff_t *pos);
 *     ssize_t kernel_write(struct file *file, const void *buf, size_t count, loff_t *pos);
 *
 * KernelSU is written against the >= 4.14 prototype. Compiling that call style
 * against the old prototype silently misplaces every argument (buf is used as the
 * file offset, count is used as the destination pointer, ...), so every file read
 * fails and APK signature / allowlist / packages.list parsing never works.
 * Provide the new semantics on top of the old kernel primitives.
 */
#ifndef __KSU_COMPAT_KRW_H
#define __KSU_COMPAT_KRW_H

#include <linux/version.h>
#include <linux/fs.h>
#include <linux/uaccess.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 14, 0)

static inline ssize_t ksu_kernel_read(struct file *file, void *buf,
				      size_t count, loff_t *pos)
{
	mm_segment_t old_fs;
	ssize_t ret;

	old_fs = get_fs();
	set_fs(KERNEL_DS);
	ret = vfs_read(file, (char __user *)buf, count, pos);
	set_fs(old_fs);

	return ret;
}

static inline ssize_t ksu_kernel_write(struct file *file, const void *buf,
				       size_t count, loff_t *pos)
{
	mm_segment_t old_fs;
	ssize_t ret;

	old_fs = get_fs();
	set_fs(KERNEL_DS);
	ret = vfs_write(file, (const char __user *)buf, count, pos);
	set_fs(old_fs);

	return ret;
}

#else /* >= 4.14: kernel already provides the new semantics */

static inline ssize_t ksu_kernel_read(struct file *file, void *buf,
				      size_t count, loff_t *pos)
{
	return kernel_read(file, buf, count, pos);
}

static inline ssize_t ksu_kernel_write(struct file *file, const void *buf,
				       size_t count, loff_t *pos)
{
	return kernel_write(file, buf, count, pos);
}

#endif /* LINUX_VERSION_CODE < 4.14.0 */

#endif /* __KSU_COMPAT_KRW_H */
