/* Copyright (C) 2025 Subbaraya Sundeep <sundeep.lkml@gmail.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 */

#include <linux/bpf.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <limits.h>

#include <sys/resource.h>
#include <getopt.h>
#include <net/if.h>

#include <bpf/bpf.h>
#include "bpf_util.h"
#include <bpf/libbpf.h>
#include <uapi/linux/bpf_perf_event.h>
#include "trace_helpers.h"

#define MAP_DO_KMALLOC		(1ULL << 0)
#define MAP_DO_LEAK		(1ULL << 63)

#define MAP_DO_SYMS		(1ULL << 62)

#define MAX_ENTRIES		1024

#define PERF_MAX_STACK_DEPTH	127

static struct {
	int verbosity;
	char alloc_cmd[256];
	char free_cmd[256];
	char sym_file[256];
	__u64 input_flags;
	int map_config_fd;
	int map_kmalloc_fd;
	int smap_kmalloc_fd;
	int smap_count_fd;
	__u64 alloc_ptrs[MAX_ENTRIES];
	int alloc_count;
	__u64 *symbols;
	int sym_count;
} state;

static struct bpf_object *obj;

static void dump_exit(int sig)
{
	bpf_object__close(obj);
	exit(0);
}

static const struct option long_options[] = {
	{"alloc",     required_argument, NULL, 'a'},
	{"free",      required_argument, NULL, 'f'},
	{"help",      no_argument,       NULL, 'h'},
	{"kmalloc",   no_argument,       NULL, 'k'},
	{"leak",      no_argument,       NULL, 'l'},
	{"verbose",   no_argument,       NULL, 'v'},
	{"symbols",   required_argument, NULL, 's'},
	{ },
};

static void usage(char *cmd)
{
	printf("eBPF program to detect memory leaks\n"
		"Usage: %s <options>\n"
		"       --alloc,    -a  <command for which allocations are tracked> \n"
		"       --free,     -f  <command for which free are tracked> \n"
		"       --help,     -h  this menu\n"
		"       --kmalloc,  -k  <trace kmallocs >\n"
		"       --leak,     -l  <find leaks, use along with -k option>\n"
		"       --symbols,  -s  <search only symbols in the file>\n"
		, cmd
		);
}

static int cmp_ptrs(const void *p1, const void *p2)
{
	__u64 addr1 = *((__u64 *)p1);
	__u64 addr2 = *((__u64 *)p2);

	if (addr1 < addr2)
		return -1;

	if (addr1 > addr2)
		return 1;

	return 0;
}

static __u8 search_in_syms(__u64 addr)
{
	__u64 *found;

	found = bsearch(&addr, state.symbols, state.sym_count,
			sizeof(__u64), cmp_ptrs);

	return found ? 1 : 0;
}

static bool calltrace_has_symbols(__u64 *calltrace)
{
	struct ksym *sym;
	__u8 ret = 0;
	int i;

	for (i = PERF_MAX_STACK_DEPTH - 1; i >= 0; i--) {
		if (!calltrace[i])
			continue;

		sym = ksym_search(calltrace[i]);
		if (!sym) {
			printf("ksym not found. Is kallsyms loaded?\n");
			return false;
		}

		ret |= search_in_syms((__u64)sym->addr);
	}

	return ret == 1;
}

static bool print_stack(int fd, int stack_count_fd, __u32 stackid)
{
	__u64 calltrace[PERF_MAX_STACK_DEPTH] = {};
	bool printed = false;
	struct ksym *sym;
	char buf[80];
	__u32 count;
	int i, err;

	err = bpf_map_lookup_elem(fd, &stackid, calltrace);
	if (err)
		return false;

	if (state.input_flags & MAP_DO_SYMS) {
		if (!calltrace_has_symbols(calltrace))
			return false;
	}

	err = bpf_map_lookup_elem(stack_count_fd, &stackid, &count);
	if (err)
		return false;

	for (i = PERF_MAX_STACK_DEPTH - 1; i >= 0; i--) {
		if (!calltrace[i])
			continue;

		sym = ksym_search(calltrace[i]);
		if (!sym) {
			printf("ksym not found. Is kallsyms loaded?\n");
			break;
		}

		if (i > 0) {
			sprintf(buf, "%s+%d", sym->name, (int)(calltrace[i] - sym->addr));
			printf("\t%-40s\n", buf);
		} else {
			sprintf(buf, "%s+%d", sym->name, (int)(calltrace[0] - sym->addr));
			printf("\t%-40s%-10d\n", buf, count);
		}

		printed = true;
	}

	return printed;
}

static int parse_args(int argc, char **argv)
{
	int longindex = 0;
	int opt;

	while ((opt = getopt_long(argc, argv, "klha:f:s:v",
				  long_options, &longindex)) != -1) {
		switch (opt) {
		case 'k':
			state.input_flags |= MAP_DO_KMALLOC;
			break;
		case 'a':
			memcpy(state.alloc_cmd, optarg, strlen(optarg));
			break;
		case 'f':
			memcpy(state.free_cmd, optarg, strlen(optarg));
			break;
		case 's':
			memcpy(state.sym_file, optarg, strlen(optarg));
			state.input_flags |= MAP_DO_SYMS;
			break;
		case 'l':
			state.input_flags |= MAP_DO_LEAK;
			break;
		case 'v':
			state.verbosity++;
			break;
		default:
		case 'h':
			usage(argv[0]);
			return 1;
		}
	}

	if (state.alloc_cmd[0] == '\0' || state.free_cmd[0] == '\0') {
		printf("Please provide alloc and free commands\n");
		usage(argv[0]);
		return 1;
	}

	return 0;
}

static int get_map_fd(int *fd, const char *name)
{
	*fd = bpf_object__find_map_fd_by_name(obj, name);
	if (*fd < 0) {
		fprintf(stderr, "ERROR: finding %s map in obj file failed\n",
			name);
		return -1;
	}

	return 0;
}

static int get_all_map_fds(void)
{
	if (get_map_fd(&state.map_config_fd, "map_config"))
		return -1;

	if (get_map_fd(&state.map_kmalloc_fd, "map_kmalloc"))
		return -1;

	if (get_map_fd(&state.smap_kmalloc_fd, "smap_kmalloc"))
		return -1;

	if (get_map_fd(&state.smap_count_fd, "smap_count"))
		return -1;

	return 0;
}

static void collect_info(void)
{
	__u64 cfg = state.input_flags;
	__u32 key = 0;

	bpf_map_update_elem(state.map_config_fd, &key, &cfg, 0);
	(void)system(state.alloc_cmd);
	cfg = 0;
	bpf_map_update_elem(state.map_config_fd, &key, &cfg, 0);

	if (state.input_flags & MAP_DO_LEAK)
		cfg |= MAP_DO_LEAK;

	bpf_map_update_elem(state.map_config_fd, &key, &cfg, 0);
	(void)system(state.free_cmd);
	cfg = 0;
	bpf_map_update_elem(state.map_config_fd, &key, &cfg, 0);
}

static int get_all_keys_from_map(int fd, __u64 *store_ptrs, int max)
{
	__u64 key = UINT64_MAX;
	__u64 next_key;
	int count = 0;

	while (bpf_map_get_next_key(fd, &key, &next_key) == 0) {
		if (count >= max)
			break;
		store_ptrs[count] = next_key;
		key = next_key;
		count++;
	}

	if (count)
		qsort(store_ptrs, count, sizeof(__u64), cmp_ptrs);

	return count;
}

static void analyse_info(void)
{
	state.alloc_count = get_all_keys_from_map(state.map_kmalloc_fd,
						  state.alloc_ptrs, MAX_ENTRIES);
}

static void print_info(void)
{
	__u64 *store_ptrs = state.alloc_ptrs;
	__u32 stackid = 0, prev = UINT32_MAX;
	int fd = state.map_kmalloc_fd;
	int count = state.alloc_count;
	int i, err;
	bool printed;

	if (state.verbosity)
		printf("Alloc map count:%d\n", count);

	printf("\n\t%-40s%-10s\n\n", "Callsite", "Count");

	for (i = 0; i < count; i++) {
		err = bpf_map_lookup_elem(fd, &store_ptrs[i], &stackid);
		if (err) {
			printf("T ");
			continue;
		}

		if (prev == stackid)
			continue;

		if (state.verbosity)
			printf("Printing stack id:%d\n", stackid);

		printed = print_stack(state.smap_kmalloc_fd, state.smap_count_fd, stackid);
		if (printed)
			printf("\n");

		prev = stackid;
	}
}

static int get_symbols_from_file(char *symbol_file)
{
	unsigned long long addr;
	int nr_syms = 0;
	char line[512];
	FILE *f_sym;
	int i;

	f_sym = fopen(symbol_file, "r");
	if (!f_sym) {
		printf("Failed to open given symbols file %s\n", symbol_file);
		return -EINVAL;
	}

	while (fscanf(f_sym, "%499s%*[^\n]\n", line) > 0)
		nr_syms++;

	if (nr_syms == 0) {
		printf("Given symbols file %s is empty\n", symbol_file);
		return -ENOENT;
	}

	state.symbols = calloc(nr_syms, sizeof(__u64));
	if (!state.symbols) {
		printf("mem alloc failed for given symbols\n");
		return -ENOMEM;
	}

	rewind(f_sym);
	nr_syms = 0;

	while (fscanf(f_sym, "%499s%*[^\n]\n", line) > 0) {
/*
		if (kallsyms_find(line, &addr))
			continue;
*/
		addr = ksym_get_addr(line);
		if (!addr)
			continue;
		state.symbols[nr_syms] = (__u64)addr;
		nr_syms++;
	}

	state.sym_count = nr_syms;

	qsort(state.symbols, nr_syms, sizeof(__u64), cmp_ptrs);

	if (state.verbosity) {
		printf("Read %d symbols from given file:\n", nr_syms);

		if (state.verbosity > 1) {
			for (i = 0; i < nr_syms; i++)
				printf("0x%llx\n", state.symbols[i]);
		}
	}

	fclose(f_sym);

	return 0;
}

int main(int argc, char **argv)
{
	struct bpf_program *prog;
	struct bpf_link *link;
	char filename[256];
	int err = -1;

	if (parse_args(argc, argv))
		exit(1);

	if (load_kallsyms()) {
		printf("failed to process /proc/kallsyms\n");
		exit(1);
	}

	/* Do one final dump when exiting */
	signal(SIGINT, dump_exit);
	signal(SIGTERM, dump_exit);

	snprintf(filename, sizeof(filename), "%s.bpf.o", argv[0]);
	obj = bpf_object__open_file(filename, NULL);
	if (libbpf_get_error(obj)) {
		fprintf(stderr, "ERROR: opening BPF object file failed\n");
		return err;
	}

	/* load BPF program */
	if (bpf_object__load(obj)) {
		fprintf(stderr, "ERROR: loading BPF object file failed\n");
		goto cleanup;
	}


	bpf_object__for_each_program(prog, obj) {
		link = bpf_program__attach(prog);
		if (libbpf_get_error(link)) {
			fprintf(stderr, "ERROR: bpf_program__attach failed\n");
			goto cleanup;
		}
	}

	if (get_all_map_fds())
		goto cleanup;

	if (state.input_flags & MAP_DO_SYMS) {
		if (get_symbols_from_file(state.sym_file))
			/* if something is wrong then disable the feature */
			state.input_flags &= ~MAP_DO_SYMS;
	}

	collect_info();
	analyse_info();
	print_info();

cleanup:
	bpf_link__destroy(link);
	bpf_object__close(obj);
	return err;
}
