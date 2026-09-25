#include "selinux.h"
#include "linux/cred.h"
#include "linux/sched.h"
#include "objsec.h"
#include "security.h"
#include "avc.h"
extern int selinux_enforcing;
#include "linux/version.h"
#include "../klog.h" // IWYU pragma: keep
#include "../ksu.h"

static int transive_to_domain(const char *domain, struct cred *cred)
{
    u32 sid;
    int error;
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 18, 0)
    struct task_security_struct *tsec;
#else 
    struct cred_security_struct *tsec;
#endif
    tsec = cred->security;
    if (!tsec) {
        pr_err("tsec == NULL!\n");
        return -1;
    }
    error = security_context_to_sid(domain, strlen(domain), &sid, GFP_ATOMIC);
    if (error) {
        pr_info("security_secctx_to_secid %s -> sid: %d, error: %d\n",
            domain, sid, error);
    }
    if (!error) {
        tsec->sid = sid;
        tsec->create_sid = 0;
        tsec->keycreate_sid = 0;
        tsec->sockcreate_sid = 0;
    }
    return error;
}

void setup_selinux(const char *domain)
{
    if (transive_to_domain(domain, (struct cred *)__task_cred(current))) {
        pr_err("transive domain failed.\n");
        return;
    }
}

void setup_ksu_cred()
{
    if (ksu_cred && transive_to_domain(KERNEL_SU_CONTEXT, ksu_cred)) {
        pr_err("setup ksu cred failed.\n");
    }
}

void setenforce(bool enforce)
{
#ifdef CONFIG_SECURITY_SELINUX_DEVELOP
    selinux_enforcing = enforce;
#endif
}

bool getenforce()
{
#ifdef CONFIG_SECURITY_SELINUX_DISABLE
    if (selinux_state.disabled) {
        return false;
    }
#endif

#ifdef CONFIG_SECURITY_SELINUX_DEVELOP
    return selinux_enforcing;
#else
    return true;
#endif
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 14, 0)
struct lsm_context {
    char *context;
    u32 len;
};

static int __security_secid_to_secctx(u32 secid, struct lsm_context *cp)
{
    return security_sid_to_context(secid, &cp->context, &cp->len);
}
static void __security_release_secctx(struct lsm_context *cp)
{
    kfree(cp->context);
}
#else
#define __security_secid_to_secctx security_secid_to_secctx
#define __security_release_secctx security_release_secctx
#endif

bool is_task_ksu_domain(const struct cred* cred)
{
    struct lsm_context ctx;
    bool result;
    if (!cred) {
        return false;
    }
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 18, 0)
    const struct task_security_struct * tsec = (struct task_security_struct *)cred->security;
#else 
    const struct cred_security_struct *tsec = (struct task_security_struct *)cred->security;
#endif
    if (!tsec) {
        return false;
    }
    int err = __security_secid_to_secctx(tsec->sid, &ctx);
    if (err) {
        return false;
    }
    result = strncmp(KERNEL_SU_CONTEXT, ctx.context, ctx.len) == 0;
    __security_release_secctx(&ctx);
    return result;
}

bool is_ksu_domain()
{
    return is_task_ksu_domain(current_cred());
}

bool is_context(const struct cred* cred, const char* context)
{
    struct lsm_context ctx;
    bool result;
    if (!cred) {
        return false;
    }
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 18, 0)
    const struct task_security_struct * tsec = (struct task_security_struct *)cred->security;
#else 
    const struct cred_security_struct *tsec = (struct task_security_struct *)cred->security;
#endif
    if (!tsec) {
        return false;
    }
    int err = __security_secid_to_secctx(tsec->sid, &ctx);
    if (err) {
        return false;
    }
    result = strncmp(context, ctx.context, ctx.len) == 0;
    __security_release_secctx(&ctx);
    return result;
}

bool is_zygote(const struct cred* cred)
{
    return is_context(cred, "u:r:zygote:s0");
}

bool is_init(const struct cred* cred) {
    return is_context(cred, "u:r:init:s0");
}

u32 ksu_get_ksu_file_sid()
{
    u32 ksu_file_sid = 0;
    int err = security_context_to_sid(KSU_FILE_CONTEXT, strlen(KSU_FILE_CONTEXT),
                       &ksu_file_sid, GFP_ATOMIC);
    if (err) {
        pr_info("get ksufile sid err %d\n", err);
    }
    return ksu_file_sid;
}
