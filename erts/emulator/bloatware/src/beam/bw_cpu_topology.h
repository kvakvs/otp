#pragma once

#include <stdint.h>
#include <sched.h>

#include "erl_process.h"

#ifdef __linux__
#  define BW_ERTS_SYS_NODE_PATH	"/sys/devices/system/node"
#  define BW_ERTS_SYS_CPU_PATH	"/sys/devices/system/cpu"
#endif

namespace cpu {

void pre_early_init_cpu_topology(int32_t *max_rg_p, int32_t *conf_p,
                                 int32_t *onln_p, int32_t *avail_p);

typedef struct {
  int logical;
  int cpu_group;
} groups_map_array_t;

typedef void (*groups_callback_t)(int32_t, ErtsSchedulerData *, int32_t, void *);

typedef struct groups_callback_list_t {
  groups_callback_list_t *next;
  groups_callback_t callback;
  void *arg;
} groups_callback_list_t;

typedef struct groups_map_t {
  groups_map_t *next;
  int32_t groups;
  groups_map_array_t *array;
  int32_t size;
  int32_t logical_processors;
  groups_callback_list_t *callback_list;
} groups_map_t;

typedef struct {
  int32_t node;
  int32_t processor;
  int32_t processor_node;
  int32_t core;
  int32_t thread;
  int32_t logical;
} cpu_topology_t;

#define BW_HAVE_MISC_UTIL_AFFINITY_MASK 1
#define BW_HAVE_SCHED_xETAFFINITY       1

typedef struct cpu_info_t {
  int32_t         configured;
  int32_t         online;
  int32_t         available;
  int32_t         topology_size;
  cpu_topology_t *topology;

#if BW_HAVE_MISC_UTIL_AFFINITY_MASK
  char *affinity_str;
  char affinity_str_buf[CPU_SETSIZE/4+2];
  cpu_set_t cpuset;
#if BW_HAVE_SCHED_xETAFFINITY
  pid_t pid;
#endif
#endif

public:
  cpu_info_t();

  int32_t get_cpu_configured() const;
  int32_t get_cpu_online() const;
  int32_t get_cpu_available() const;
  int32_t update();
  int32_t get_proc_affinity();

protected:
  int32_t read_topology();
  void adjust_processor_nodes(int32_t no_nodes);
} cpu_info_t;

bool cpu_sets_equal(cpu_set_t *a, cpu_set_t *b);

} // ns cpu

class Cpu {
public:
    static cpu::groups_map_t *groups_maps;
    static cpu::cpu_info_t *cpuinfo;
    static bool no_groups_callbacks;
};
