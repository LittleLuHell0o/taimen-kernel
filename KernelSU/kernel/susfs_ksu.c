// susfs_ksu.c -- SukiSU-native KernelSU glue for susfs4ksu (Linux 4.4).
//
// SukiSU's KernelSU routes manager/supercall traffic through an ioctl channel
// (supercalls.c), so it has NO prctl(0xDEADBEEF) handler. The user-space
// ksu_susfs tool, however, issues susfs commands via
//   prctl(KERNEL_SU_OPTION = 0xDEADBEEF, CMD_SUSFS_*, &info, NULL, &error)
// This file provides that entry point and the few symbols fs/susfs.c expects
// from the KernelSU tree.

#include <linux/err.h>
#include <linux/uaccess.h>
#include <linux/cred.h>
#include <linux/string.h>
#include <linux/fs.h>
#include <linux/namei.h>
#include <linux/path.h>
#include <linux/sched.h>
#include <linux/types.h>
#include <linux/version.h>
#include <linux/prctl.h>
#include <linux/susfs.h>
#include <linux/susfs_def.h>
#include "ksu.h"
#include "allowlist.h"
#include "selinux/selinux.h"

/* ---- try_umount entry (defined in fs/namespace.c under CONFIG_KSU_SUSFS_TRY_UMOUNT) ---- */
#if defined(CONFIG_KSU_SUSFS_TRY_UMOUNT)
extern void susfs_run_try_umount_for_current_mnt_ns(void);
#endif

/* ---- symbols required by fs/susfs.c ---- */
bool susfs_is_current_ksu_domain(void)
{
    return is_ksu_domain();
}

bool susfs_is_current_zygote_domain(void)
{
    return is_zygote(current->cred);
}

/* ---- post-fs-data auto-add flag setup (triggered from on_post_fs_data) ---- */
#if defined(CONFIG_KSU_SUSFS_SUS_MOUNT) || defined(CONFIG_KSU_SUSFS_AUTO_ADD_SUS_BIND_MOUNT) || \
    defined(CONFIG_KSU_SUSFS_AUTO_ADD_SUS_KSU_DEFAULT_MOUNT) || defined(CONFIG_KSU_SUSFS_AUTO_ADD_TRY_UMOUNT_FOR_BIND_MOUNT)
#ifdef CONFIG_KSU_SUSFS_SUS_MOUNT
static bool susfs_is_umount_for_zygote_system_process_enabled = false;
#endif
#ifdef CONFIG_KSU_SUSFS_AUTO_ADD_SUS_BIND_MOUNT
static bool susfs_is_auto_add_sus_bind_mount_enabled = true;
#endif
#ifdef CONFIG_KSU_SUSFS_AUTO_ADD_SUS_KSU_DEFAULT_MOUNT
static bool susfs_is_auto_add_sus_ksu_default_mount_enabled = true;
#endif
#ifdef CONFIG_KSU_SUSFS_AUTO_ADD_TRY_UMOUNT_FOR_BIND_MOUNT
static bool susfs_is_auto_add_try_umount_for_bind_mount_enabled = true;
#endif

void susfs_on_post_fs_data(void)
{
    struct path path;
#ifdef CONFIG_KSU_SUSFS_SUS_MOUNT
    if (!kern_path(DATA_ADB_UMOUNT_FOR_ZYGOTE_SYSTEM_PROCESS, 0, &path)) {
        susfs_is_umount_for_zygote_system_process_enabled = true;
        path_put(&path);
    }
    pr_info("susfs_is_umount_for_zygote_system_process_enabled: %d\n",
        susfs_is_umount_for_zygote_system_process_enabled);
#endif
#ifdef CONFIG_KSU_SUSFS_AUTO_ADD_SUS_BIND_MOUNT
    if (!kern_path(DATA_ADB_NO_AUTO_ADD_SUS_BIND_MOUNT, 0, &path)) {
        susfs_is_auto_add_sus_bind_mount_enabled = false;
        path_put(&path);
    }
    pr_info("susfs_is_auto_add_sus_bind_mount_enabled: %d\n",
        susfs_is_auto_add_sus_bind_mount_enabled);
#endif
#ifdef CONFIG_KSU_SUSFS_AUTO_ADD_SUS_KSU_DEFAULT_MOUNT
    if (!kern_path(DATA_ADB_NO_AUTO_ADD_SUS_KSU_DEFAULT_MOUNT, 0, &path)) {
        susfs_is_auto_add_sus_ksu_default_mount_enabled = false;
        path_put(&path);
    }
    pr_info("susfs_is_auto_add_sus_ksu_default_mount_enabled: %d\n",
        susfs_is_auto_add_sus_ksu_default_mount_enabled);
#endif
#ifdef CONFIG_KSU_SUSFS_AUTO_ADD_TRY_UMOUNT_FOR_BIND_MOUNT
    if (!kern_path(DATA_ADB_NO_AUTO_ADD_TRY_UMOUNT_FOR_BIND_MOUNT, 0, &path)) {
        susfs_is_auto_add_try_umount_for_bind_mount_enabled = false;
        path_put(&path);
    }
    pr_info("susfs_is_auto_add_try_umount_for_bind_mount_enabled: %d\n",
        susfs_is_auto_add_try_umount_for_bind_mount_enabled);
#endif
}
#else
void susfs_on_post_fs_data(void) {}
#endif

/* prctl dispatcher: only handles KERNEL_SU_OPTION susfs commands.
   Returns 0 if handled (caller should stop processing prctl),
   returns 1 if not ours (caller continues normal prctl path). */
int ksu_handle_prctl(int option, unsigned long arg2, unsigned long arg3,
                     unsigned long arg4, unsigned long arg5)
{
    if (option != KERNEL_SU_OPTION)
        return 1;
    /* only root may configure susfs */
    if (current_uid().val != 0)
        return 1;

#ifdef CONFIG_KSU_SUSFS
#if defined(CONFIG_KSU_SUSFS_SUS_PATH)
    if (arg2 == CMD_SUSFS_ADD_SUS_PATH) {
        int error = 0;
        if (!access_ok(VERIFY_READ, (void __user *)arg3, sizeof(struct st_susfs_sus_path))) return 0;
        if (!access_ok(VERIFY_WRITE, (void __user *)arg5, sizeof(error))) return 0;
        error = susfs_add_sus_path((struct st_susfs_sus_path __user *)arg3);
        pr_info("susfs: CMD_SUSFS_ADD_SUS_PATH -> ret: %d\n", error);
        if (copy_to_user((void __user *)arg5, &error, sizeof(error)))
            pr_info("susfs: copy_to_user() failed\n");
        return 0;
    }
#endif
#if defined(CONFIG_KSU_SUSFS_SUS_MOUNT)
    if (arg2 == CMD_SUSFS_ADD_SUS_MOUNT) {
        int error = 0;
        if (!access_ok(VERIFY_READ, (void __user *)arg3, sizeof(struct st_susfs_sus_mount))) return 0;
        if (!access_ok(VERIFY_WRITE, (void __user *)arg5, sizeof(error))) return 0;
        error = susfs_add_sus_mount((struct st_susfs_sus_mount __user *)arg3);
        pr_info("susfs: CMD_SUSFS_ADD_SUS_MOUNT -> ret: %d\n", error);
        if (copy_to_user((void __user *)arg5, &error, sizeof(error)))
            pr_info("susfs: copy_to_user() failed\n");
        return 0;
    }
#endif
#if defined(CONFIG_KSU_SUSFS_SUS_KSTAT)
    if (arg2 == CMD_SUSFS_ADD_SUS_KSTAT) {
        int error = 0;
        if (!access_ok(VERIFY_READ, (void __user *)arg3, sizeof(struct st_susfs_sus_kstat))) return 0;
        if (!access_ok(VERIFY_WRITE, (void __user *)arg5, sizeof(error))) return 0;
        error = susfs_add_sus_kstat((struct st_susfs_sus_kstat __user *)arg3);
        pr_info("susfs: CMD_SUSFS_ADD_SUS_KSTAT -> ret: %d\n", error);
        if (copy_to_user((void __user *)arg5, &error, sizeof(error)))
            pr_info("susfs: copy_to_user() failed\n");
        return 0;
    }
    if (arg2 == CMD_SUSFS_UPDATE_SUS_KSTAT) {
        int error = 0;
        if (!access_ok(VERIFY_READ, (void __user *)arg3, sizeof(struct st_susfs_sus_kstat))) return 0;
        if (!access_ok(VERIFY_WRITE, (void __user *)arg5, sizeof(error))) return 0;
        error = susfs_update_sus_kstat((struct st_susfs_sus_kstat __user *)arg3);
        pr_info("susfs: CMD_SUSFS_UPDATE_SUS_KSTAT -> ret: %d\n", error);
        if (copy_to_user((void __user *)arg5, &error, sizeof(error)))
            pr_info("susfs: copy_to_user() failed\n");
        return 0;
    }
    if (arg2 == CMD_SUSFS_ADD_SUS_KSTAT_STATICALLY) {
        int error = 0;
        if (!access_ok(VERIFY_READ, (void __user *)arg3, sizeof(struct st_susfs_sus_kstat))) return 0;
        if (!access_ok(VERIFY_WRITE, (void __user *)arg5, sizeof(error))) return 0;
        error = susfs_add_sus_kstat((struct st_susfs_sus_kstat __user *)arg3);
        pr_info("susfs: CMD_SUSFS_ADD_SUS_KSTAT_STATICALLY -> ret: %d\n", error);
        if (copy_to_user((void __user *)arg5, &error, sizeof(error)))
            pr_info("susfs: copy_to_user() failed\n");
        return 0;
    }
#endif
#if defined(CONFIG_KSU_SUSFS_TRY_UMOUNT)
    if (arg2 == CMD_SUSFS_ADD_TRY_UMOUNT) {
        int error = 0;
        if (!access_ok(VERIFY_READ, (void __user *)arg3, sizeof(struct st_susfs_try_umount))) return 0;
        if (!access_ok(VERIFY_WRITE, (void __user *)arg5, sizeof(error))) return 0;
        error = susfs_add_try_umount((struct st_susfs_try_umount __user *)arg3);
        pr_info("susfs: CMD_SUSFS_ADD_TRY_UMOUNT -> ret: %d\n", error);
        if (copy_to_user((void __user *)arg5, &error, sizeof(error)))
            pr_info("susfs: copy_to_user() failed\n");
        return 0;
    }
#endif
#if defined(CONFIG_KSU_SUSFS_SPOOF_UNAME)
    if (arg2 == CMD_SUSFS_SET_UNAME) {
        int error = 0;
        if (!access_ok(VERIFY_READ, (void __user *)arg3, sizeof(struct st_susfs_uname))) return 0;
        if (!access_ok(VERIFY_WRITE, (void __user *)arg5, sizeof(error))) return 0;
        error = susfs_set_uname((struct st_susfs_uname __user *)arg3);
        pr_info("susfs: CMD_SUSFS_SET_UNAME -> ret: %d\n", error);
        if (copy_to_user((void __user *)arg5, &error, sizeof(error)))
            pr_info("susfs: copy_to_user() failed\n");
        return 0;
    }
#endif
#if defined(CONFIG_KSU_SUSFS_ENABLE_LOG)
    if (arg2 == CMD_SUSFS_ENABLE_LOG) {
        int error = 0;
        if (arg3 != 0 && arg3 != 1) return 0;
        susfs_set_log(arg3);
        if (copy_to_user((void __user *)arg5, &error, sizeof(error)))
            pr_info("susfs: copy_to_user() failed\n");
        return 0;
    }
#endif
#if defined(CONFIG_KSU_SUSFS_SPOOF_CMDLINE_OR_BOOTCONFIG)
    if (arg2 == CMD_SUSFS_SET_CMDLINE_OR_BOOTCONFIG) {
        int error = 0;
        if (!access_ok(VERIFY_READ, (void __user *)arg3, SUSFS_FAKE_CMDLINE_OR_BOOTCONFIG_SIZE)) return 0;
        if (!access_ok(VERIFY_WRITE, (void __user *)arg5, sizeof(error))) return 0;
        error = susfs_set_cmdline_or_bootconfig((char __user *)arg3);
        pr_info("susfs: CMD_SUSFS_SET_CMDLINE_OR_BOOTCONFIG -> ret: %d\n", error);
        if (copy_to_user((void __user *)arg5, &error, sizeof(error)))
            pr_info("susfs: copy_to_user() failed\n");
        return 0;
    }
#endif
#if defined(CONFIG_KSU_SUSFS_OPEN_REDIRECT)
    if (arg2 == CMD_SUSFS_ADD_OPEN_REDIRECT) {
        int error = 0;
        if (!access_ok(VERIFY_READ, (void __user *)arg3, sizeof(struct st_susfs_open_redirect))) return 0;
        if (!access_ok(VERIFY_WRITE, (void __user *)arg5, sizeof(error))) return 0;
        error = susfs_add_open_redirect((struct st_susfs_open_redirect __user *)arg3);
        pr_info("susfs: CMD_SUSFS_ADD_OPEN_REDIRECT -> ret: %d\n", error);
        if (copy_to_user((void __user *)arg5, &error, sizeof(error)))
            pr_info("susfs: copy_to_user() failed\n");
        return 0;
    }
#endif
#if defined(CONFIG_KSU_SUSFS_TRY_UMOUNT)
    if (arg2 == CMD_SUSFS_RUN_UMOUNT_FOR_CURRENT_MNT_NS) {
        int error = 0;
        susfs_run_try_umount_for_current_mnt_ns();
        pr_info("susfs: CMD_SUSFS_RUN_UMOUNT_FOR_CURRENT_MNT_NS -> done\n");
        if (copy_to_user((void __user *)arg5, &error, sizeof(error)))
            pr_info("susfs: copy_to_user() failed\n");
        return 0;
    }
#endif
    if (arg2 == CMD_SUSFS_SHOW_VERSION) {
        int error = 0;
        int len_of_susfs_version = strlen(SUSFS_VERSION);
        char *susfs_version = SUSFS_VERSION;
        if (!access_ok(VERIFY_WRITE, (void __user *)arg3, len_of_susfs_version + 1)) return 0;
        if (!access_ok(VERIFY_WRITE, (void __user *)arg5, sizeof(error))) return 0;
        error = copy_to_user((void __user *)arg3, (void *)susfs_version, len_of_susfs_version + 1);
        pr_info("susfs: CMD_SUSFS_SHOW_VERSION -> ret: %d\n", error);
        if (copy_to_user((void __user *)arg5, &error, sizeof(error)))
            pr_info("susfs: copy_to_user() failed\n");
        return 0;
    }
    if (arg2 == CMD_SUSFS_SHOW_ENABLED_FEATURES) {
        int error = 0;
        u64 enabled_features = 0;
        if (!access_ok(VERIFY_WRITE, (void __user *)arg3, sizeof(u64))) return 0;
        if (!access_ok(VERIFY_WRITE, (void __user *)arg5, sizeof(error))) return 0;
#ifdef CONFIG_KSU_SUSFS_SUS_PATH
        enabled_features |= (1 << 0);
#endif
#ifdef CONFIG_KSU_SUSFS_SUS_MOUNT
        enabled_features |= (1 << 1);
#endif
#ifdef CONFIG_KSU_SUSFS_AUTO_ADD_SUS_KSU_DEFAULT_MOUNT
        enabled_features |= (1 << 2);
#endif
#ifdef CONFIG_KSU_SUSFS_AUTO_ADD_SUS_BIND_MOUNT
        enabled_features |= (1 << 3);
#endif
#ifdef CONFIG_KSU_SUSFS_SUS_KSTAT
        enabled_features |= (1 << 4);
#endif
#ifdef CONFIG_KSU_SUSFS_SUS_OVERLAYFS
        enabled_features |= (1 << 5);
#endif
#ifdef CONFIG_KSU_SUSFS_TRY_UMOUNT
        enabled_features |= (1 << 6);
#endif
#ifdef CONFIG_KSU_SUSFS_AUTO_ADD_TRY_UMOUNT_FOR_BIND_MOUNT
        enabled_features |= (1 << 7);
#endif
#ifdef CONFIG_KSU_SUSFS_SPOOF_UNAME
        enabled_features |= (1 << 8);
#endif
#ifdef CONFIG_KSU_SUSFS_ENABLE_LOG
        enabled_features |= (1 << 9);
#endif
#ifdef CONFIG_KSU_SUSFS_SPOOF_CMDLINE_OR_BOOTCONFIG
        enabled_features |= (1 << 11);
#endif
#ifdef CONFIG_KSU_SUSFS_OPEN_REDIRECT
        enabled_features |= (1 << 12);
#endif
#ifdef CONFIG_KSU_SUSFS_HAS_MAGIC_MOUNT
        enabled_features |= (1 << 14);
#endif
        error = copy_to_user((void __user *)arg3, (void *)&enabled_features, sizeof(enabled_features));
        pr_info("susfs: CMD_SUSFS_SHOW_ENABLED_FEATURES -> ret: %d\n", error);
        if (copy_to_user((void __user *)arg5, &error, sizeof(error)))
            pr_info("susfs: copy_to_user() failed\n");
        return 0;
    }
    if (arg2 == CMD_SUSFS_SHOW_VARIANT) {
        int error = 0;
        int len_of_variant = strlen(SUSFS_VARIANT);
        char *susfs_variant = SUSFS_VARIANT;
        if (!access_ok(VERIFY_WRITE, (void __user *)arg3, len_of_variant + 1)) return 0;
        if (!access_ok(VERIFY_WRITE, (void __user *)arg5, sizeof(error))) return 0;
        error = copy_to_user((void __user *)arg3, (void *)susfs_variant, len_of_variant + 1);
        pr_info("susfs: CMD_SUSFS_SHOW_VARIANT -> ret: %d\n", error);
        if (copy_to_user((void __user *)arg5, &error, sizeof(error)))
            pr_info("susfs: copy_to_user() failed\n");
        return 0;
    }
#endif /* CONFIG_KSU_SUSFS */

    return 0;
}
