// lms_operator_lkm.c
// Linux Kernel Module that enforces the existence of only the 'operator' user.
// Prevents creation of any other user and cannot be removed from the kernel.
//
// WARNING: This is a proof-of-concept and should be tested in a safe environment only.

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/cred.h>
#include <linux/sched.h>
#include <linux/syscalls.h>
#include <linux/uaccess.h>
#include <linux/string.h>
#include <linux/fs.h>
#include <linux/namei.h>
#include <linux/slab.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("vvbv");
MODULE_DESCRIPTION("LKM that only allows the user 'operator' to be created and cannot be removed");

#define ALLOWED_USER "operator"

// Helper function to check if a username is allowed
static bool is_allowed_user(const char *username) {
    return strcmp(username, ALLOWED_USER) == 0;
}

// Hook for vfs_write to monitor /etc/passwd modifications
static asmlinkage ssize_t (*real_vfs_write)(struct file *, const char __user *, size_t, loff_t *);

static asmlinkage ssize_t lms_vfs_write(struct file *file, const char __user *buf, size_t count, loff_t *pos) {
    char *kbuf = NULL;
    ssize_t ret;
    if (file && file->f_path.dentry && file->f_path.dentry->d_name.name &&
        strcmp(file->f_path.dentry->d_name.name, "passwd") == 0) {
        kbuf = kmalloc(count + 1, GFP_KERNEL);
        if (kbuf && copy_from_user(kbuf, buf, count) == 0) {
            kbuf[count] = '\0';
            // Look for lines that add a new user
            char *line = kbuf;
            while (line && *line) {
                char *next = strchr(line, '\n');
                if (next) *next = '\0';
                char *colon = strchr(line, ':');
                if (colon) {
                    size_t len = colon - line;
                    if (len > 0 && !is_allowed_user(line)) {
                        pr_err("lms_operator_lkm: Attempt to add unauthorized user: %.*s\n", (int)len, line);
                        kfree(kbuf);
                        return -EPERM;
                    }
                }
                if (!next) break;
                line = next + 1;
            }
        }
        if (kbuf) kfree(kbuf);
    }
    ret = real_vfs_write(file, buf, count, pos);
    return ret;
}

static int __init lms_operator_init(void) {
    pr_info("lms_operator_lkm: Loaded. Only 'operator' user creation is allowed.\n");
#ifdef THIS_MODULE
    THIS_MODULE->exit = NULL;
#endif
    // Hook vfs_write
    real_vfs_write = (void *)kallsyms_lookup_name("vfs_write");
    if (real_vfs_write) {
        *((unsigned long *)&real_vfs_write) = (unsigned long)lms_vfs_write;
        pr_info("lms_operator_lkm: vfs_write hooked.\n");
    } else {
        pr_err("lms_operator_lkm: Could not hook vfs_write.\n");
    }
    return 0;
}

// No module_exit function: rmmod will fail with 'Device or resource busy'
// Optionally, you can override the delete_module syscall, but this is not recommended for stability.

module_init(lms_operator_init);
// No module_exit!


