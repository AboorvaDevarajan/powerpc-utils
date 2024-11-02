/**
 * @file cpu_info_helpers.c
 * @brief Common routines to capture cpu information
 *
 * Copyright (c) 2007, 2020 International Business Machines
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 *
 * @author Anton Blanchard <anton@au.ibm.com>
 * @author Kamalesh Babulal <kamalesh@linux.vnet.ibm.com>
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sched.h>
#include <errno.h>
#include <stdbool.h>
#include <dirent.h>
#include <limits.h>
#include <sys/stat.h>
#include <sys/types.h>
#include "cpu_info_helpers.h"

int get_attribute(char *path, const char *fmt, int *value)
{
	FILE *fp;
	int rc;

	rc = access(path, F_OK);
	if (rc)
		return -1;

	fp = fopen(path, "r");
	if (!fp)
		return -1;

	rc = fscanf(fp, fmt, value);
	fclose(fp);

	if (rc == EOF)
		return -1;

	return 0;
}

static int test_sysattr(char *attribute, int perms, int threads_in_system)
{
	char path[SYSFS_PATH_MAX];
	int i;

	for (i = 0; i < threads_in_system; i++) {
		sprintf(path, SYSFS_CPUDIR"/%s", i, attribute);
		if (access(path, F_OK))
			continue;

		if (access(path, perms))
			return 0;
	}

	return 1;
}

int __sysattr_is_readable(char *attribute, int threads_in_system)
{
	return test_sysattr(attribute, R_OK, threads_in_system);
}

int __sysattr_is_writeable(char *attribute, int threads_in_system)
{
	return test_sysattr(attribute, W_OK, threads_in_system);
}

int cpu_physical_id(int thread)
{
	char path[SYSFS_PATH_MAX];
	int rc, physical_id;

	sprintf(path, SYSFS_CPUDIR"/physical_id", thread);
	rc = get_attribute(path, "%d", &physical_id);

	/* This attribute does not exist in kernels without hotplug enabled */
	if (rc && errno == ENOENT)
		return -1;
	return physical_id;
}

int cpu_online(int thread)
{
	char path[SYSFS_PATH_MAX];
	int rc, online;

	sprintf(path, SYSFS_CPUDIR"/online", thread);
	rc = get_attribute(path, "%d", &online);

	/* This attribute does not exist in kernels without hotplug enabled */
	if (rc && errno == ENOENT)
		return 1;

	if (rc || !online)
		return 0;

	return 1;
}

int is_subcore_capable(void)
{
	return access(SYSFS_SUBCORES, F_OK) == 0;
}

int num_subcores(void)
{
	int rc, subcores;

	rc = get_attribute(SYSFS_SUBCORES, "%d", &subcores);
	if (rc)
		return -1;
	return subcores;
}

int get_cpu_info(int *_threads_per_cpu, int *_cpus_in_system,
		 int *_threads_in_system)
{
	DIR *d;
	struct dirent *de;
	int first_cpu = 1;
	int rc;
	int subcores;
	int threads_in_system;
	int threads_per_cpu = 0;
	int cpus_in_system = 0;

	d = opendir("/proc/device-tree/cpus");
	if (!d)
		return -1;

	while ((de = readdir(d)) != NULL) {
		if (!strncmp(de->d_name, "PowerPC", 7)) {
			if (first_cpu) {
				struct stat sbuf;
				char path[PATH_MAX];

				snprintf(path, sizeof(path), INTSERV_PATH, de->d_name);
				rc = stat(path, &sbuf);
				if (!rc)
					threads_per_cpu = sbuf.st_size / 4;

				first_cpu = 0;
			}

			cpus_in_system++;
		}
	}

	closedir(d);
	threads_in_system = cpus_in_system * threads_per_cpu;

	subcores = num_subcores();
	if (is_subcore_capable() && subcores > 0) {
		threads_per_cpu /= subcores;
		cpus_in_system *= subcores;
	}

	*_threads_per_cpu = threads_per_cpu;
	*_threads_in_system = threads_in_system;
	*_cpus_in_system = cpus_in_system;

	return 0;
}

int __is_smt_capable(int threads_per_cpu)
{
	return threads_per_cpu > 1;
}

int __get_one_smt_state(int core, int threads_per_cpu)
{
	int primary_thread = core * threads_per_cpu;
	int smt_state = 0;
	int i;

	if (!__sysattr_is_readable("online", threads_per_cpu)) {
		perror("Cannot retrieve smt state");
		return -2;
	}

	for (i = 0; i < threads_per_cpu; i++) {
		smt_state += cpu_online(primary_thread + i);
	}

	return smt_state;
}

static void print_cpu_list(const cpu_set_t *cpuset, int cpuset_size,
		           int cpus_in_system)
{
	int core;
	const char *comma = "";

    int *present_cores = NULL;
    int num_present_cores;


    present_cores = get_present_core_list(threads_per_cpu, &num_present_cores);

    
    
	for (core = 0; core < present_cores[num_present_cores-1]; core++) {
		int begin = core;
		if (CPU_ISSET_S(core, cpuset_size, cpuset)) {
			while (CPU_ISSET_S(core+1, cpuset_size, cpuset))
				core++;

			if (core > begin)
				printf("%s%d-%d", comma, begin, core);
			else
				printf("%s%d", comma, core);
			comma = ",";
		}
	}
}

int *get_present_cpu_list(int *num_cpus) {
    FILE *fp = fopen(CPU_PRESENT_PATH, "r");
    if (!fp) {
        perror("Failed to open the file");
        exit(EXIT_FAILURE);
    }

    char line[MAX_NR_CPUS];
    if (fgets(line, sizeof(line), fp) == NULL) {
        perror("Failed to read the file");
        fclose(fp);
        exit(EXIT_FAILURE);
    }
    fclose(fp);

    int *cpu_list = malloc(MAX_NR_CPUS * sizeof(int));
    int count = 0;
    char *token = strtok(line, ",");

    while (token) {
        int start, end;
        if (sscanf(token, "%d-%d", &start, &end) == 2) { 
            for (int i = start; i <= end; i++) {
                cpu_list[count++] = i;
            }
        } else if (sscanf(token, "%d", &start) == 1) {
            cpu_list[count++] = start;
        }
        token = strtok(NULL, ",");
    }

    *num_cpus = count;
    return cpu_list;
}


int *get_present_core_list(int threads_per_cpu, int *num_cores) {
    FILE *fp;
    char cpu_ranges[64];

    fp = fopen(CPU_PRESENT_PATH, "r");
    if (fp == NULL) {
        perror("Failed to open /sys/devices/system/cpu/present");
        exit(EXIT_FAILURE);
    }

    if (fgets(cpu_ranges, sizeof(cpu_ranges), fp) == NULL) {
        perror("Failed to read CPU ranges");
        fclose(fp);
        exit(EXIT_FAILURE);
    }
    fclose(fp);

    bool core_seen[MAX_NR_CORES] = {0};
    int *core_list = malloc(MAX_NR_CORES * sizeof(int));
    int core_count = 0;

    char *range = strtok(cpu_ranges, ",");
    while (range) {
        int start, end;

        if (sscanf(range, "%d-%d", &start, &end) == 2) {
            for (int cpu = start; cpu <= end; cpu++) {
                int core_id = cpu / threads_per_cpu;
                if (!core_seen[core_id]) {
                    core_seen[core_id] = true;
                    core_list[core_count++] = core_id;

                }
            }
        } else if (sscanf(range, "%d", &start) == 1) {
            int core_id = start / threads_per_cpu;
            if (!core_seen[core_id]) {
                core_seen[core_id] = true;
                core_list[core_count++] = core_id;
            }
        }

        range = strtok(NULL, ",");
    }

    *num_cores = core_count;
    return core_list;
}


int __do_smt(bool numeric, int cpus_in_system, int threads_per_cpu, bool print_smt_state) {
    int thread, smt_state = -1;
    cpu_set_t **cpu_states = NULL;
    int *present_cores = NULL;
    int num_present_cores, c, rc = 0;


    present_cores = get_present_core_list(threads_per_cpu, &num_present_cores);
    // Use parse_cpu_present_list to get the list of present CPUs

    if (!present_cores) {
        rc = -ENOMEM;
        goto cleanup_get_smt;
    }


    int cpu_state_size = CPU_ALLOC_SIZE(num_present_cores);


    // Allocate cpu_states array
    cpu_states = (cpu_set_t **)calloc(threads_per_cpu, sizeof(cpu_set_t *));
    if (!cpu_states)
        return -ENOMEM;

    for (thread = 0; thread < threads_per_cpu; thread++) {
        cpu_states[thread] = CPU_ALLOC(cpus_in_system);
        CPU_ZERO_S(cpu_state_size, cpu_states[thread]);
    }


    // Loop over each present CPU
    printf("num present cores : %d\n", num_present_cores);
    for (int i = 0; i < num_present_cores; i++) {
        c = present_cores[i];
        int threads_online = __get_one_smt_state(c, threads_per_cpu);
        printf("core: %d threads online : %d\n", c , threads_online);
        if (threads_online < 0) {
            rc = threads_online;
            goto cleanup_get_smt;
        }
        if (threads_online) {
            CPU_SET_S(c, cpu_state_size, cpu_states[threads_online - 1]);
        }
    }


    /* TODO: this should be anyway fixed even standalone */
    // Determine the SMT state by counting CPUs in each thread's set
    for (thread = 0; thread < threads_per_cpu; thread++) {
        if (CPU_COUNT_S(cpu_state_size, cpu_states[thread])) {
            printf("hit : threads per cpu : %d\n", thread);
            if (smt_state == -1)
                smt_state = thread + 1;
            else if (smt_state > 0)
                smt_state = 0; // mixed SMT modes
        }
    }

    printf("smt state : %d\n", smt_state);
    // Print SMT state if requested
    if (!print_smt_state)
        return smt_state;

    if (smt_state == 1) {
        printf("SMT=%s\n", numeric ? "1" : "SMT is off");
    } else if (smt_state == 0) {
        for (thread = 0; thread < threads_per_cpu; thread++) {
            if (CPU_COUNT_S(cpu_state_size, cpu_states[thread])) {
                printf("SMT=%d: ", thread + 1);
                print_cpu_list(cpu_states[thread], cpu_state_size, cpus_in_system);
                printf("\n");
            }
        }
    } else {
        printf("SMT=%d\n", smt_state);
    }

cleanup_get_smt:
    // Free allocated resources
    for (thread = 0; thread < threads_per_cpu; thread++)
        CPU_FREE(cpu_states[thread]);
    free(cpu_states);
    free(present_cores);

    return rc;
}

