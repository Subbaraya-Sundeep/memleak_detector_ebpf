/* Copyright (C) 2025 Subbaraya Sundeep <sundeep.lkml@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of version 2 of the GNU General Public License
 * as published by the Free Software Foundation.
 */

#include <uapi/linux/bpf.h>
#include <bpf/bpf_helpers.h>

#define MAX_ENTRIES		1024

#define MAP_DO_KMALLOC		(1ULL << 0)
#define MAP_DO_LEAK		(1ULL << 63)

#define PERF_MAX_STACK_DEPTH	127

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u64));
	__uint(max_entries, 1);
} map_config SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_STACK_TRACE);
	__uint(key_size, sizeof(u32));
	__uint(value_size, PERF_MAX_STACK_DEPTH * sizeof(u64));
	__uint(max_entries, MAX_ENTRIES);
} smap_kmalloc SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(key_size, sizeof(u64));
	__uint(value_size, sizeof(u32));
	__uint(max_entries, MAX_ENTRIES);
} map_kmalloc SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u32));
	__uint(max_entries, MAX_ENTRIES);
} smap_count SEC(".maps");

struct kmalloc_tp {
	u64 pad;
	unsigned long call_site;
	u64 ptr;
	size_t bytes_req;
	size_t bytes_alloc;
	gfp_t gfp_flags;
};

SEC("tracepoint/kmem/kmalloc")
int on_kmalloc(struct kmalloc_tp *ctx)
{
	char err_fmt[] = "Configuration map not found\n";
	char err_fmt1[] = "Updating kmalloc map failed:%d ptr:0x%llx\n";
	char err_fmt2[] = "Getting stack map failed\n";
	char fmt[] = "ptr:0x%llx stack_id:0x%llx\n";
	u32 key = 0, init_val = 1;
	u64 ptr = ctx->ptr;
	u32 kstack, *count;
	u64 *cfg;
	int ret;

	cfg = bpf_map_lookup_elem(&map_config, &key);
	if (!cfg) {
		bpf_trace_printk(err_fmt, sizeof(err_fmt));
		return 0;
	}

	if (*cfg & MAP_DO_KMALLOC) {
		kstack = bpf_get_stackid(ctx, &smap_kmalloc, BPF_F_FAST_STACK_CMP);
		if ((int)kstack < 0) {
			bpf_trace_printk(err_fmt2, sizeof(err_fmt2));
			return 0;
		}

		bpf_trace_printk(fmt, sizeof(fmt), ptr, kstack);

		ret = bpf_map_update_elem(&map_kmalloc, &ptr,
					  &kstack, BPF_ANY);
		if (ret)
			bpf_trace_printk(err_fmt1, sizeof(err_fmt1), ret, ptr);

		count  = bpf_map_lookup_elem(&smap_count, &kstack);
		if (count)
			__sync_fetch_and_add(count, 1);
		else
			bpf_map_update_elem(&smap_count, &kstack, &init_val, BPF_ANY);
	}

	return 0;
}

struct kfree_tp {
	u64 pad;
	unsigned long call_site;
	u64 ptr;
};

SEC("tracepoint/kmem/kfree")
int on_kfree(struct kfree_tp *ctx)
{
	char err_fmt[] = "Configuration map not found\n";
	char info_fmt[] = "deleted ptr:0x%llx\n";
	u64 ptr = ctx->ptr;
	u32 key = 0;
	u32 kstack;
	u32 *val;
	u64 *cfg;
	int ret;

	cfg = bpf_map_lookup_elem(&map_config, &key);
	if (!cfg) {
		bpf_trace_printk(err_fmt, sizeof(err_fmt));
		return 0;
	}

	/* Delete pointers which are in alloc map */
	if (*cfg & MAP_DO_LEAK) {
		val = bpf_map_lookup_elem(&map_kmalloc, &ptr);
		if (val) {
			bpf_map_delete_elem(&map_kmalloc, &ptr);
			bpf_trace_printk(info_fmt, sizeof(info_fmt), ptr);
		}
	}

	return 0;
}

char _license[] SEC("license") = "GPL";
