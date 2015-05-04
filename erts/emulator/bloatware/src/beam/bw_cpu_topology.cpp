#include "bw_cpu_topology.h"
#include "bw_misc_utils.h"

#include <algorithm>

cpu::groups_map_t *Cpu::groups_maps = nullptr;
bool Cpu::no_groups_callbacks = false;
cpu::cpu_info_t *Cpu::cpuinfo = nullptr;

static const int32_t ERTS_MAX_READER_GROUPS = 64;

namespace cpu {

int32_t cpu_info_t::get_cpu_configured() const
{
    if (configured <= 0) {
        return -ENOTSUP;
    }
    return configured;
}

int32_t cpu_info_t::get_cpu_online() const
{
    if (online <= 0) {
        return -ENOTSUP;
    }
    return online;
}

int32_t cpu_info_t::get_cpu_available() const
{
    if (available <= 0) {
        return -ENOTSUP;
    }
    return available;
}


static void get_logical_processors(int32_t *conf, int32_t *onln, int32_t *avail)
{
  if (conf) {
    *conf = Cpu::cpuinfo->get_cpu_configured();
  }

  if (onln) {
    *onln = Cpu::cpuinfo->get_cpu_online();
  }

  if (avail) {
    *avail = Cpu::cpuinfo->get_cpu_available();
  }
}

void pre_early_init_cpu_topology(int32_t *max_rg_p, int32_t *conf_p,
                                 int32_t *onln_p, int32_t *avail_p)
{
  *max_rg_p = ERTS_MAX_READER_GROUPS;
  Cpu::cpuinfo = new cpu_info_t;
  get_logical_processors(conf_p, onln_p, avail_p);
}

cpu_info_t::cpu_info_t() {
#if BW_HAVE_MISC_UTIL_AFFINITY_MASK
  affinity_str = nullptr;
#if BW_SCHED_xETAFFINITY
  pid = getpid();
#endif
#endif
  topology_size = 0;
  topology = nullptr;
  configured = -1;
  online = -1;
  available = -1;
  Cpu::cpuinfo->update();
}

int32_t cpu_info_t::update()
{
  int32_t changed = 0;
  int32_t configured = 0;
  int32_t online = 0;
  int32_t available = 0;
  cpu_topology_t *old_topology;
  int32_t old_topology_size;

#if BW_HAVE_MISC_UTIL_AFFINITY_MASK
  cpu_set_t cpuset;
#endif

#ifdef _SC_NPROCESSORS_CONF
  configured = std::max(0, (int32_t)::sysconf(_SC_NPROCESSORS_CONF));
#endif
#ifdef _SC_NPROCESSORS_ONLN
  online = std::max(0, (int32_t)::sysconf(_SC_NPROCESSORS_ONLN));
#endif

  if (this->online > configured) {
    online = configured;
  }
  if (this->configured != configured) {
    changed = 1;
  }
  if (this->online != online) {
    changed = 1;
  }

#if BW_HAVE_MISC_UTIL_AFFINITY_MASK
  if (this->get_proc_affinity() == 0) {
      if (!changed && !cpu::cpu_sets_equal(&cpuset, &this->cpuset)) {
          changed = 1;
      }
      if (!changed) {
          available = this->available;
      } else {
          int i, c, cn, si;

          memcpy((void *) &this->cpuset,
                 (void *) &cpuset,
                 sizeof(cpu_set_t));

          c = cn = 0;
          si = sizeof(this->affinity_str_buf) - 1;
          this->affinity_str_buf[si] = '\0';
          for (i = 0; i < CPU_SETSIZE; i++) {
              if (CPU_ISSET(i, &this->cpuset)) {
                  c |= 1 << cn;
                  available++;
              }
              cn++;
              if (cn == 4) {
                  this->affinity_str_buf[--si] = (c < 10
                                                 ? '0' + c
                                                 : 'A' + c - 10);
                  c = cn = 0;
              }
          }
          if (c)
              this->affinity_str_buf[--si] = (c < 10
                                             ? '0' + c
                                             : 'A' + c - 10);
          while (this->affinity_str_buf[si] == '0') {
            si++;
          }
          this->affinity_str = &this->affinity_str_buf[si];
      }
  }
#endif

  if (this->available > online) {
    available = online;
  }
  if (this->available != available) {
    changed = 1;
  }

  this->configured = configured;
  this->online = online;
  this->available = available;

  old_topology = this->topology;
  old_topology_size = this->topology_size;
  this->topology = nullptr;

  read_topology();

  if (this->topology_size != old_topology_size
      || (old_topology_size != 0
          && memcmp((void *) this->topology,
                    (void *) old_topology,
                    (sizeof(cpu_topology_t)
                     * old_topology_size)) != 0)) {
      changed = 1;
      if (old_topology) {
        delete old_topology;
      }
  }
  else {
      if (this->topology) {
          delete this->topology;
      }
      this->topology = old_topology;
  }

  return changed;
}

int32_t cpu_info_t::get_proc_affinity() {
  return sched_getaffinity(pid, sizeof(cpu_set_t), &cpuset) != 0 ? -errno : 0;
}

static int
pn_cmp(const void *vx, const void *vy)
{
    cpu_topology_t *x = (cpu_topology_t *) vx;
    cpu_topology_t *y = (cpu_topology_t *) vy;

    if (x->processor != y->processor)
        return x->processor - y->processor;
    if (x->node != y->node)
        return x->node - y->node;
    if (x->processor_node != y->processor_node)
        return x->processor_node - y->processor_node;
    if (x->core != y->core)
        return x->core - y->core;
    if (x->thread != y->thread)
        return x->thread - y->thread;
    if (x->logical != y->logical)
        return x->logical - y->logical;
    return 0;
}

static int cpu_cmp(const void *vx, const void *vy)
{
    cpu_topology_t *x = (cpu_topology_t *) vx;
    cpu_topology_t *y = (cpu_topology_t *) vy;

    if (x->node != y->node)
        return x->node - y->node;
    if (x->processor != y->processor)
        return x->processor - y->processor;
    if (x->processor_node != y->processor_node)
        return x->processor_node - y->processor_node;
    if (x->core != y->core)
        return x->core - y->core;
    if (x->thread != y->thread)
        return x->thread - y->thread;
    if (x->logical != y->logical)
        return x->logical - y->logical;
    return 0;
}

int32_t cpu_info_t::read_topology()
{
  char npath[MAXPATHLEN];
  char cpath[MAXPATHLEN];
  char tpath[MAXPATHLEN];
  char fpath[MAXPATHLEN];
  DIR *ndir = nullptr;
  DIR *cdir = nullptr;
  struct dirent *nde;
  int ix;
  int res = 0;
  int got_nodes = 0;
  int no_nodes = 0;

  errno = 0;

  if (configured < 1) {
      goto error;
  }

  topology = new cpu_topology_t[configured];
  if (!topology) {
    goto error;
  }

  for (ix = 0; ix < configured; ix++) {
      topology[ix].node = -1;
      topology[ix].processor = -1;
      topology[ix].processor_node = -1;
      topology[ix].core = -1;
      topology[ix].thread = -1;
      topology[ix].logical = -1;
  }

  ix = -1;

  if (::realpath(BW_ERTS_SYS_NODE_PATH, npath)) {
      ndir = ::opendir(npath);
      got_nodes = (ndir != nullptr);
  }

  do {
      int node_id = -1;

      if (!got_nodes) {
          if (!realpath(BW_ERTS_SYS_CPU_PATH, cpath))
              goto error;
      }
      else {

          nde = readdir(ndir);

          if (!nde)
              break;

          if (sscanf(nde->d_name, "node%d", &node_id) != 1)
              continue;

          no_nodes++;

          sprintf(tpath, "%s/node%d", npath, node_id);

          if (!realpath(tpath, cpath))
              goto error;
      }

      cdir = opendir(cpath);
      if (!cdir)
          goto error;

      while (1) {
          int cpu_id;
          struct dirent *cde = readdir(cdir);
          if (!cde) {
              closedir(cdir);
              cdir = nullptr;
              break;
          }
          if (sscanf(cde->d_name, "cpu%d", &cpu_id) == 1) {
              char buf[50]; /* Much more than enough for an integer */
              int processor_id, core_id;
              sprintf(tpath, "%s/cpu%d/topology/physical_package_id",
                      cpath, cpu_id);
              if (!realpath(tpath, fpath))
                  continue;
              if (util::read_file(fpath, buf, sizeof(buf)) <= 0)
                  continue;
              if (sscanf(buf, "%d", &processor_id) != 1)
                  continue;
              sprintf(tpath, "%s/cpu%d/topology/core_id",
                      cpath, cpu_id);
              if (!realpath(tpath, fpath))
                  continue;
              if (util::read_file(fpath, buf, sizeof(buf)) <= 0)
                  continue;
              if (sscanf(buf, "%d", &core_id) != 1)
                  continue;

              /*
               * We now know node id, processor id, and
               * core id of the logical processor with
               * the cpu id 'cpu_id'.
               */
              ix++;
              topology[ix].node	= node_id;
              topology[ix].processor	= processor_id;
              topology[ix].processor_node = -1; /* Fixed later */
              topology[ix].core	= core_id;
              topology[ix].thread	= 0; /* we'll numerate later */
              topology[ix].logical	= cpu_id;
          }
      }
  } while (got_nodes);

  res = ix+1;

  if (!res || res < online)
      res = 0;
  else {
      cpu_topology_t *prev, *this_, *last;

      topology_size = res;

      if (topology_size != configured) {
          void *t = realloc(topology, (sizeof(cpu_topology_t) * topology_size));
          if (t)
              topology = (cpu_topology_t*)t;
      }

      adjust_processor_nodes(no_nodes);

      qsort(topology,
            topology_size,
            sizeof(cpu_topology_t),
            cpu_cmp);

      this_ = &topology[0];
      this_->thread = 0;

      if (res > 1) {
          prev = this_++;
          last = &topology[topology_size-1];

          while (1) {
              this_->thread = ((this_->node == prev->node
                               && this_->processor == prev->processor
                               && this_->processor_node == prev->processor_node
                               && this_->core == prev->core)
                              ? prev->thread + 1
                              : 0);
              if (this_ == last)
                  break;
              prev = this_++;
          }
      }
  }

error:

  if (res == 0) {
      topology_size = 0;
      if (topology) {
          free(topology);
          topology = nullptr;
      }
      if (errno)
          res = -errno;
      else
          res = -EINVAL;
  }

  if (ndir)
      closedir(ndir);
  if (cdir)
      closedir(cdir);

  return res;
}

bool cpu_sets_equal(cpu_set_t *a, cpu_set_t *b)
{
  int i;
  for (i = 0; i < CPU_SETSIZE; i++) {
    if (CPU_ISSET(i, a)) {
      if (!CPU_ISSET(i, b)) {
        return false;
      }
    }
    else {
      if (CPU_ISSET(i, b)) {
        return false;
      }
    }
  }
  return true;
}

void cpu_info_t::adjust_processor_nodes(int32_t no_nodes)
{
  cpu_topology_t *prev, *this_, *last;
  if (no_nodes > 1) {
    int processor = -1;
    int processor_node = 0;
    int node = -1;

    qsort(topology,
          topology_size,
          sizeof(cpu_topology_t),
          pn_cmp);

    prev = nullptr;
    this_ = &topology[0];
    last = &topology[topology_size-1];
    while (1) {
      if (processor == this_->processor) {
          if (node != this_->node)
              processor_node = 1;
      }
      else {
          if (processor_node) {
          make_processor_node:
              while (prev->processor == processor) {
                  prev->processor_node = prev->node;
                  prev->node = -1;
                  if (prev == &topology[0])
                      break;
                  prev--;
              }
              processor_node = 0;
          }
          processor = this_->processor;
          node = this_->node;
      }
      if (this_ == last) {
          if (processor_node) {
              prev = this_;
              goto make_processor_node;
          }
          break;
      }
      prev = this_++;
    }
  }
}

} // ns cpu
