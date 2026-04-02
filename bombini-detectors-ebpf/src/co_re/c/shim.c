#include "types.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

// this just a simple C macro to make easier shim definition
// the macro prefix the function name by "shim_" so that doing we can
// easily filter the shim functions to bindgen.
#define _SHIM_GETTER(ret, proto, accessed_member)                \
	__attribute__((always_inline)) ret proto                     \
	{                                                            \
		return __builtin_preserve_access_index(accessed_member); \
	}

#define _SHIM_GETTER_BPF_CORE_READ(ret, proto, struc, memb) \
	__attribute__((always_inline)) ret proto                \
	{                                                       \
		return BPF_CORE_READ(struc, memb);                  \
	}

#define _SHIM_GETTER_BPF_CORE_READ_BITFIELD(ret, proto, struc, memb) \
	__attribute__((always_inline)) ret proto                         \
	{                                                                \
		return BPF_CORE_READ_BITFIELD_PROBED(struc, memb);           \
	}

#define _SHIM_GETTER_BPF_CORE_READ_USER(ret, proto, struc, memb) \
	__attribute__((always_inline)) ret proto                     \
	{                                                            \
		return BPF_CORE_READ_USER(struc, memb);                  \
	}

#define _SHIM_GETTER_BPF_CORE_READ_RECAST(ret, proto, old_struct, new_struct, memb) \
	__attribute__((always_inline)) ret proto                                        \
	{                                                                               \
		struct old_struct *old = (void *)new_struct;                                \
		return BPF_CORE_READ(old, memb);                                            \
	}

// macro used to define a function to check if a field exists
#define _FIELD_EXISTS_DEF(_struct, memb, memb_name)                                                       \
	__attribute__((always_inline)) _Bool shim_##_struct##_##memb_name##_##exists(struct _struct *_struct) \
	{                                                                                                     \
		return bpf_core_field_exists(_struct->memb);                                                      \
	}

#define SHIM_BITFIELD(struc, memb)                                                                                                  \
	_SHIM_GETTER_BPF_CORE_READ_BITFIELD(typeof(((struct struc *)0)->memb), shim_##struc##_##memb(struct struc *struc), struc, memb) \
	_FIELD_EXISTS_DEF(struc, memb, memb)

#define SHIM(struc, memb)                                                                                                              \
	_SHIM_GETTER_BPF_CORE_READ(typeof(((struct struc *)0)->memb), shim_##struc##_##memb(struct struc *struc), struc, memb)             \
	_SHIM_GETTER_BPF_CORE_READ_USER(typeof(((struct struc *)0)->memb), shim_##struc##_##memb##_user(struct struc *struc), struc, memb) \
	_FIELD_EXISTS_DEF(struc, memb, memb)

#define SHIM_WITH_NAME(struc, memb, memb_name)                                                                                              \
	_SHIM_GETTER_BPF_CORE_READ(typeof(((struct struc *)0)->memb), shim_##struc##_##memb_name(struct struc *struc), struc, memb)             \
	_SHIM_GETTER_BPF_CORE_READ_USER(typeof(((struct struc *)0)->memb), shim_##struc##_##memb_name##_user(struct struc *struc), struc, memb) \
	_FIELD_EXISTS_DEF(struc, memb, memb_name)

#define SHIM_REF(struc, memb)                                                                                             \
	_SHIM_GETTER(typeof(&(((struct struc *)0)->memb)), shim_##struc##_##memb(struct struc *struc), &(struc->memb))        \
	_SHIM_GETTER(typeof(&(((struct struc *)0)->memb)), shim_##struc##_##memb##_user(struct struc *struc), &(struc->memb)) \
	_FIELD_EXISTS_DEF(struc, memb, memb)

#define ARRAY_SHIM(struc, memb)                                                                                                 \
	_SHIM_GETTER(typeof(&(((struct struc *)0)->memb[0])), shim_##struc##_##memb(struct struc *struc), &(struc->memb[0]))        \
	_SHIM_GETTER(typeof(&(((struct struc *)0)->memb[0])), shim_##struc##_##memb##_user(struct struc *struc), &(struc->memb[0])) \
	_FIELD_EXISTS_DEF(struc, memb, memb)

#define ARRAY_SHIM_WITH_NAME(struc, memb, memb_name)                                                                                 \
	_SHIM_GETTER(typeof(&(((struct struc *)0)->memb[0])), shim_##struc##_##memb_name(struct struc *struc), &(struc->memb[0]))        \
	_SHIM_GETTER(typeof(&(((struct struc *)0)->memb[0])), shim_##struc##_##memb_name##_user(struct struc *struc), &(struc->memb[0])) \
	_FIELD_EXISTS_DEF(struc, memb, memb_name)

#define SHIM_ENUM_VALUE(enum_type, enum_value)                                      \
	__attribute__((always_inline)) unsigned int shim_##enum_type##_##enum_value()   \
	{                                                                               \
		return bpf_core_enum_value(enum enum_type, enum_value);                     \
	}                                                                               \
	__attribute__((always_inline)) _Bool shim_##enum_type##_##enum_value##_exists() \
	{                                                                               \
		return bpf_core_enum_value_exists(enum enum_type, enum_value);              \
	}

#define SHIM_TRUSTED(struc, memb)                                            \
    _SHIM_GETTER(                                                            \
        typeof(((struct struc *)0)->memb),                                   \
        shim_##struc##_##memb##_trusted(struct struc *struc),                \
        struc->memb)                                                         \
    _FIELD_EXISTS_DEF(struc, memb, memb##_trusted)

struct kgid_t
{
	gid_t val;
} __attribute__((preserve_access_index));

struct kuid_t
{
	uid_t val;
} __attribute__((preserve_access_index));

typedef struct {
    __u64 val;
} kernel_cap_t;

///

static __attribute__((always_inline)) pid_t shim_pid_type_helper(pid_t p) { return p; }

struct cgroup
{
    struct kernfs_node *kn;
} __attribute__((preserve_access_index));

SHIM(cgroup, kn);

struct cred
{
    struct kuid_t uid;
    struct kgid_t gid;
    struct kuid_t euid;
    struct kgid_t egid;
    kernel_cap_t cap_inheritable;
    kernel_cap_t cap_permitted;
    kernel_cap_t cap_effective;
} __attribute__((preserve_access_index));

_SHIM_GETTER_BPF_CORE_READ(uid_t, shim_cred_uid(struct cred *cred), cred, uid.val);
_SHIM_GETTER_BPF_CORE_READ(gid_t, shim_cred_gid(struct cred *cred), cred, gid.val);
_SHIM_GETTER_BPF_CORE_READ(uid_t, shim_cred_euid(struct cred *cred), cred, euid.val);
_SHIM_GETTER_BPF_CORE_READ(gid_t, shim_cred_egid(struct cred *cred), cred, egid.val);

_SHIM_GETTER_BPF_CORE_READ(__u64, shim_cred_cap_effective(struct cred *cred), cred, cap_effective.val);
_SHIM_GETTER_BPF_CORE_READ(__u64, shim_cred_cap_inheritable(struct cred *cred), cred, cap_inheritable.val);
_SHIM_GETTER_BPF_CORE_READ(__u64, shim_cred_cap_permitted(struct cred *cred), cred, cap_permitted.val);

struct css_set
{
    struct cgroup *dfl_cgrp;
} __attribute__((preserve_access_index));

SHIM(css_set, dfl_cgrp);

struct qstr
{
    const unsigned char *name;
} __attribute__((preserve_access_index));

SHIM(qstr, name);

struct dentry
{
    struct qstr d_name;
} __attribute__((preserve_access_index));

SHIM_REF(dentry, d_name);

struct path
{
    struct vfsmount *mnt;
    struct dentry *dentry;
} __attribute__((preserve_access_index));

SHIM(path, dentry);
SHIM_TRUSTED(path, dentry);

struct mm_struct
{
    unsigned long arg_start;
    unsigned long arg_end;
    struct file *exe_file;
} __attribute__((preserve_access_index));

SHIM(mm_struct, arg_start);
SHIM(mm_struct, arg_end);
SHIM(mm_struct, exe_file);

struct kernfs_node
{
    struct kernfs_node *parent;
    const char *name;
} __attribute__((preserve_access_index));

SHIM(kernfs_node, parent);
SHIM(kernfs_node, name);

struct inode
{
    umode_t i_mode;
    unsigned long i_ino;
    struct kuid_t i_uid;
    struct kgid_t i_gid;
    unsigned int __i_nlink;
} __attribute__((preserve_access_index));

SHIM(inode, i_mode);
SHIM(inode, i_ino);
SHIM(inode, __i_nlink);
_SHIM_GETTER_BPF_CORE_READ(uid_t, shim_inode_i_uid(struct inode *inode), inode, i_uid.val);
_SHIM_GETTER_BPF_CORE_READ(gid_t, shim_inode_i_gid(struct inode *inode), inode, i_gid.val);

struct file
{
    struct inode *f_inode;
    struct path f_path;
    unsigned int f_flags;
} __attribute__((preserve_access_index));

SHIM_REF(file, f_path);   // inline struct → SHIM_REF
SHIM(file, f_inode);       // pointer → SHIM
SHIM(file, f_flags);       // value → SHIM
SHIM_TRUSTED(file, f_inode);

struct filename
{
    const char *name;
} __attribute__((preserve_access_index));

SHIM(filename, name);

#define COMM_LEN 16

struct task_struct
{
    pid_t pid;
    pid_t tgid;
    struct cred *cred;
    struct task_struct *parent;
    struct task_struct *real_parent;
    struct mm_struct *mm;
    struct css_set *cgroups;
    struct kuid_t loginuid;
    unsigned char comm[COMM_LEN];
} __attribute__((preserve_access_index));

SHIM(task_struct, pid);
SHIM(task_struct, tgid);
SHIM(task_struct, cred);
SHIM(task_struct, parent);
SHIM(task_struct, real_parent);
SHIM(task_struct, mm);
SHIM(task_struct, cgroups);
ARRAY_SHIM(task_struct, comm);

_SHIM_GETTER_BPF_CORE_READ(uid_t, shim_task_struct_loginuid(struct task_struct *task), task, loginuid.val);
_FIELD_EXISTS_DEF(task_struct, loginuid, loginuid);

struct linux_binprm
{
    struct file *file;
    struct cred *cred;
    unsigned int per_clear;
} __attribute__((preserve_access_index));

SHIM(linux_binprm, file);
SHIM(linux_binprm, cred);
SHIM(linux_binprm, per_clear);
SHIM_TRUSTED(linux_binprm, file);

struct in6_addr
{
    union {
        __u8 u6_addr8[16];
    } in6_u;
} __attribute__((preserve_access_index));

ARRAY_SHIM_WITH_NAME(in6_addr, in6_u.u6_addr8, u6_addr8);

typedef __u64 __addrpair;
typedef __u32 __portpair;

struct sock_common
{
    union {
        __addrpair skc_addrpair;
    };

    union {
        __portpair skc_portpair;
    };

    unsigned short skc_family;

    struct in6_addr skc_v6_daddr;
    struct in6_addr skc_v6_rcv_saddr;
} __attribute__((preserve_access_index));

SHIM(sock_common, skc_family);
SHIM(sock_common, skc_addrpair);
SHIM(sock_common, skc_portpair);
SHIM_REF(sock_common, skc_v6_daddr);
SHIM_REF(sock_common, skc_v6_rcv_saddr);

struct sock
{
    struct sock_common __sk_common;
} __attribute__((preserve_access_index));

SHIM_REF(sock, __sk_common);

struct io_kiocb
{
    u8 opcode;
} __attribute__((preserve_access_index));

SHIM(io_kiocb, opcode);

struct open_how
{
    __u64 flags;
} __attribute__((preserve_access_index));

SHIM(open_how, flags);
