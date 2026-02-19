#pragma once

#define MAX_PATH_LEN 4096
// kernel's max dentry name length that is 255
// (https://elixir.bootlin.com/linux/v5.10/source/include/uapi/linux/limits.h#L12) + 1 for the `/`
#define MAX_COMPONENT_LEN 256
// Max iterations when looping paths, we can reach at least 1024 but the verification time
// increases, so for now we keep it conservative, and moreover 512 should be more than enough.
#define FALLBACK_PATH_ITERATIONS 512
// With numeric code iterators we have no limits.
#define PATH_ITERATIONS 2048

#define DELETED_STRING " (deleted)"

#define SAFE_PATH_LEN(x) ((x) & (MAX_PATH_LEN - 1))
// we need `MAX_PATH_LEN * 2 -1` because we need to tell the verifier that
// our offset will never cross the second `MAX_PATH_LEN` segment.
#define SAFE_PATH_ACCESS(x) ((x) & (MAX_PATH_LEN * 2 - 1))
#define SAFE_COMPONENT_ACCESS(x) ((x) & (MAX_COMPONENT_LEN - 1))

struct path_read_data {
	struct dentry *root_dentry;
	struct vfsmount *root_mnt;
	struct dentry *dentry;
	struct vfsmount *vfsmnt;
	struct mount *mnt;
	char *bptr;
	u32 curr_off;
	bool resolved;
};

static __always_inline bool IS_ROOT(struct dentry *dentry) {
	struct dentry *d_parent;
	bpf_core_read(&d_parent, sizeof(d_parent), &dentry->d_parent);
	return (dentry == d_parent);
}

static __always_inline bool hlist_bl_unhashed(const struct hlist_bl_node *h) {
	struct hlist_bl_node **pprev;
	bpf_core_read(&pprev, sizeof(pprev), &h->pprev);
	return !pprev;
}

static __always_inline bool d_unhashed(struct dentry *dentry) {
	return hlist_bl_unhashed(&dentry->d_hash);
}

static __always_inline bool d_unlinked(struct dentry *dentry) {
	return d_unhashed(dentry) && !IS_ROOT(dentry);
}

static __always_inline void copy_name(char *buf, u32 *buflen, struct dentry *dentry) {
	struct qstr d_name = {};
	bpf_core_read(&d_name, bpf_core_type_size(struct qstr), &dentry->d_name);
	// d_name.len doesn't contain the terminator. we do +1 to reserve space for the initial '/'
	*buflen -= (d_name.len + 1);
	// before the new path component, we need to add a '/'
	buf[SAFE_PATH_ACCESS(*buflen)] = '/';
	bpf_probe_read_kernel(&buf[SAFE_PATH_ACCESS(*buflen + 1)],
	                      SAFE_COMPONENT_ACCESS(d_name.len * sizeof(char)),
	                      d_name.name);
}

static __always_inline long path_read(struct path_read_data *data) {
	struct dentry *dentry = data->dentry;
	struct vfsmount *vfsmnt = data->vfsmnt;
	struct mount *mnt = data->mnt;

	if((dentry == data->root_dentry && vfsmnt == data->root_mnt)) {
		// resolved all path components successfully
		data->resolved = true;
		return 1;
	}

	struct dentry *vfsmnt_mnt_root = NULL;
	bpf_core_read(&vfsmnt_mnt_root, sizeof(vfsmnt_mnt_root), &vfsmnt->mnt_root);
	if(dentry == vfsmnt_mnt_root || IS_ROOT(dentry)) {
		struct mount *m_parent = NULL;
		bpf_core_read(&m_parent, sizeof(m_parent), &mnt->mnt_parent);
		/* Global root? */
		if(data->mnt == m_parent) {
			// resolved all path components successfully
			data->resolved = true;
			return 1;
		}
		bpf_core_read(&data->dentry, sizeof(data->dentry), &mnt->mnt_mountpoint);
		data->mnt = m_parent;
		data->vfsmnt = &m_parent->mnt;
		return 0;
	}
	copy_name(data->bptr, &data->curr_off, dentry);

	struct dentry *d_parent = NULL;
	bpf_core_read(&d_parent, sizeof(d_parent), &dentry->d_parent);
	data->dentry = d_parent;
	return 0;
}

// this method is inspired by Tetragon https://github.com/cilium/tetragon/pull/90
// but simplified and reworked in light of our specific use case.
//
// Our `buf` is composed of 3 segments of size `MAX_PATH_LEN`
// - the first segment is not used in this method. it is left empty. it will be used to copy the
//   final path in following methods.
// - the second segment is used to store the progressive path reconstruction.
// - the third segment has a double role:
//   - it is used to please the verifier with some free space.
//   - it is used as padding for the final comparison.
//
// | MAX_PATH_LEN | MAX_PATH_LEN | MAX_PATH_LEN |
//                               |
//                               | <- `off` we start here
//                            /cat
//                        /bin/cat
//                    /usr/bin/cat
//  path reconstruction goes in this direction (<-). We don't copy the terminator of each string
//  since we don't need it among `/`. For the final terminator, we use the first empty byte of
//  the third `MAX_PATH_LEN` segment.
//
// `bpf_d_path_approx` returns the offset of the last written byte in the buffer.
static __always_inline u32 bpf_d_path_approx(const struct path *path, char *buf) {
	int off = MAX_PATH_LEN * 2;
	struct dentry *dentry = NULL;
	if(bpf_core_read(&dentry, sizeof(dentry), &path->dentry) != 0) {
		return -1;
	}

	if(d_unlinked(dentry)) {
		// we don't need the terminator since the next `MAX_PATH_LEN` segment
		off -= (sizeof(DELETED_STRING) - 1);
		memcpy(&buf[SAFE_PATH_ACCESS(off)], DELETED_STRING, sizeof(DELETED_STRING) - 1);
	}

	struct path_read_data data = {
	        .bptr = buf,      // initial pointer to the beginning of the buffer
	        .curr_off = off,  // remaining length of the buffer
	};

	struct fs_struct *fs = NULL;
	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	bpf_core_read(&fs, sizeof(fs), &task->fs);
	struct path *root = NULL;
	bpf_core_read(&root, sizeof(root), &fs->root);

	// final mount and dentry
	bpf_core_read(&data.root_dentry, sizeof(data.root_dentry), &root->dentry);
	bpf_core_read(&data.root_mnt, sizeof(data.root_mnt), &root->mnt);
	// current mount and dentry
	bpf_core_read(&data.dentry, sizeof(data.dentry), &path->dentry);
	bpf_core_read(&data.vfsmnt, sizeof(data.vfsmnt), &path->mnt);
	data.mnt = container_of(
	        data.vfsmnt,
	        struct mount,
	        mnt);  // container_of comes from bpf_helpers.h and it is already adapted for CO-RE

	if(bpf_ksym_exists(bpf_iter_num_new)) {
		// Numeric code iterators are available from kernel 6.4
		// (https://docs.ebpf.io/linux/kfuncs/bpf_iter_num_new/) so we check if the kfunc is
		// available.
		// `bpf_repeat` is a macro defined by libbpf that uses `bpf_iter_num_new` under
		// the hood.
		// The initial implementation used `bpf_loop`, but this is not so handy to use with CO-RE,
		// you can find more info here
		// https://lore.kernel.org/bpf/CAGQdkDt9zyQwr5JyftXqL=OLKscNcqUtEteY4hvOkx2S4GdEkQ@mail.gmail.com/T/#u
		// and here https://github.com/falcosecurity/libs/pull/2027#issuecomment-2568997393
		// TL;DR; we need 2 ebpf programs, one with `bpf_loop` on kernels >= 5.13 and another
		// without it on older kernels.
		bpf_repeat(PATH_ITERATIONS) {
			if(path_read(&data)) {
				break;
			}
		}
	} else {
		for(int i = 0; i < FALLBACK_PATH_ITERATIONS; ++i) {
			if(path_read(&data)) {
				break;
			}
		}
	}

	// memfd files have no path in the filesystem so we never decremented the `curr_off`.
	// As our last resort we try to read the current dentry.
	if(data.curr_off == MAX_PATH_LEN * 2) {
		// if we arrive here `data.resolved` could be:
		// - `true` if there is no path like in case of memfd files.
		// - `false` if we never found the final path root. In this case we will just return -1.
		copy_name(data.bptr, &data.curr_off, data.dentry);
	}

	if(data.resolved) {
		// if it is a successful resolution, we return the last byte we wrote
		return data.curr_off;
	}

	// Otherwise we return -1
	return -1;
}
