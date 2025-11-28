# WASP: Workload-Aware Self-Replicating Page-Tables for NUMA Servers

An implementation of **WASP** (Workload-Aware Self-Replicating Page-Tables) based on the ASPLOS '24 paper by Hongliang Qu and Zhibin Yu.

## Overview

WASP automatically enables and disables page-table self-replication (PTSR) to reduce the **page-table caused NUMA effect** on multi-socket NUMA servers. Unlike manual approaches like Mitosis, WASP monitors workload characteristics at runtime and makes intelligent decisions about when replication helps or hurts performance.

### The Problem

On NUMA systems, page-table walks triggered by TLB misses may access remote memory, causing significant performance degradation. While page-table replication (creating local copies on each NUMA node) can help, it can also *hurt* performance when:

- Co-located applications contend for the local memory controller
- The workload doesn't have significant TLB miss rates
- Memory access patterns don't benefit from local page tables

### The Solution

WASP uses three key indicators to automatically decide when to enable/disable PTSR:

| Indicator | Description | Threshold |
|-----------|-------------|-----------|
| **MAR** (Memory Access Rate) | Number of memory accesses per microsecond | > 10M accesses/sec |
| **DTLB Miss Rate** | Ratio of page-table walks to TLB accesses | > 0.01 (1%) |
| **PTL** (Page-Table access Latency) | Measured latency to each NUMA node's memory | Dynamic |

When conditions are met, WASP enables replication and steers each thread to use the replica with the **lowest latency** (which may be local or remote, depending on memory controller contention).

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        User Space                               │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │                    waspd (daemon)                       │    │
│  │  ┌──────────┐  ┌──────────┐  ┌──────────────────────┐   │    │
│  │  │ Perf     │  │ PTL      │  │ Decision Engine      │   │    │
│  │  │ Counters │  │ Measure  │  │ (MAR/DTLB/PTL)       │   │    │
│  │  └────┬─────┘  └────┬─────┘  └──────────┬───────────┘   │    │
│  │       │             │                   │               │    │
│  │       └─────────────┴───────────────────┘               │    │
│  │                         │                               │    │
│  │                    prctl() syscalls                     │    │
│  └─────────────────────────┼───────────────────────────────┘    │
└────────────────────────────┼────────────────────────────────────┘
                             │
┌────────────────────────────┼────────────────────────────────────┐
│                        Kernel                                   │
│  ┌─────────────────────────┴───────────────────────────────┐    │
│  │              Page Table Replication (Mitosis)           │    │
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐   │    │
│  │  │ PGD Replicas │  │ P4D/PUD/PMD  │  │ PTE Replicas │   │    │
│  │  │ per NUMA node│  │ Replicas     │  │              │   │    │
│  │  └──────────────┘  └──────────────┘  └──────────────┘   │    │
│  │                                                         │    │
│  │  ┌──────────────────────────────────────────────────┐   │    │
│  │  │ CR3 Switching (switch_mm_irqs_off)               │   │    │
│  │  │ - Select local or forced replica                 │   │    │
│  │  │ - RCU-protected for safe disable                 │   │    │
│  │  └──────────────────────────────────────────────────┘   │    │
│  └─────────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────────┘
```

## Components

### 1. Kernel Module (`arch/x86/mm/pgtable_repl.c`)

The kernel-side implementation provides:

- **Page table replication**: Creates and maintains replicas of the entire page table hierarchy (PGD → P4D → PUD → PMD → PTE) on each specified NUMA node
- **Circular linked lists**: Replicas are linked via `page->replica` pointers for efficient traversal
- **Synchronized updates**: All `set_pte/pmd/pud/p4d/pgd` operations propagate to all replicas
- **A/D bit aggregation**: `get_*` operations OR together flags from all replicas
- **CR3 switching**: On context switch, selects the appropriate replica based on thread's NUMA node or forced assignment
- **Fork/exec handling**: Properly inherits or re-enables replication across process boundaries

#### Key Kernel APIs

```c
// Enable replication on specified nodes
int pgtable_repl_enable(struct mm_struct *mm, nodemask_t nodes);

// Disable replication (frees all replicas)
void pgtable_repl_disable(struct mm_struct *mm);

// Page table operations (automatically replicate)
void pgtable_repl_set_pte(pte_t *ptep, pte_t pteval);
void pgtable_repl_set_pmd(pmd_t *pmdp, pmd_t pmdval);
// ... etc for all levels
```

#### prctl Interface

```c
// Enable/disable replication
prctl(PR_SET_PGTABLE_REPL, mode, pid, 0, 0);
// mode: 0 = disable, 1 = all nodes, bitmask = specific nodes

// Get replication status (returns node bitmask)
prctl(PR_GET_PGTABLE_REPL);

// Force thread to use specific replica node
prctl(PR_SET_PGTABLE_REPL_NODE, node, tid, 0, 0);
// node: -1 = auto (local), 0..N = force specific node

// Get current forced node
prctl(PR_GET_PGTABLE_REPL_NODE, tid, 0, 0, 0);
```

### 2. Userspace Daemon (`waspd.c`)

The daemon monitors all processes and makes automatic decisions:

```
┌─────────────────────────────────────────────────────────────┐
│                     WASP Decision Flow                      │
│                                                             │
│   ┌─────────┐     ┌─────────┐     ┌─────────┐     ┌───────┐ │
│   │ Step 1  │ Yes │ Step 2  │ Yes │ Step 3  │     │Step 4 │ │
│   │ MAR >   ├────►│ DTLB MR ├────►│ Enable  ├────►│ PTL   │ │
│   │ 10M/s?  │     │ > 1%?   │     │ PTSR    │     │Measure│ │
│   └────┬────┘     └────┬────┘     └─────────┘     └───┬───┘ │
│        │ No            │ No                           │     │
│        ▼               ▼                              ▼     │
│   ┌─────────┐     ┌─────────┐                   ┌─────────┐ │
│   │ Disable │     │ Disable │                   │ Steer   │ │
│   │ PTSR    │     │ PTSR    │                   │ Threads │ │
│   └─────────┘     └─────────┘                   └─────────┘ │
└─────────────────────────────────────────────────────────────┘
```

#### Performance Counters Used

| Counter | Purpose |
|---------|---------|
| `L1D-loads` | Memory load operations |
| `L1D-stores` | Memory store operations |
| `DTLB-loads` | TLB load accesses |
| `DTLB-stores` | TLB store accesses |
| `DTLB-load-walks` | Page walks from load misses |
| `DTLB-store-walks` | Page walks from store misses |

#### PTL Measurement

The daemon periodically measures memory access latency between all NUMA node pairs using pointer-chasing:

```
         ┌─ PTL Matrix ──────────┐
         │     N0      N1        │
      N0 │   120ns   180ns       │  (green = fastest)
      N1 │   175ns   115ns       │
         └───────────────────────┘
```

## Installation

### Prerequisites

- Ubuntu 24.04 (or compatible Linux distribution)
- Root access
- Multi-socket NUMA system (2+ nodes recommended)

### Quick Start

```bash
# 1. Prepare the environment and kernel config
./prepare.sh

# 2. Build and install the kernel + daemon
./install.sh

# 3. Reboot into the new kernel
sudo reboot

# 4. Run the WASP daemon
sudo ./waspd 1    # Full mode with PTL measurement
# or
sudo ./waspd 0    # Naive mode (perf counters only)
```

### Manual Installation

#### Building the Kernel

```bash
# Configure (ensure CONFIG_PGTABLE_REPLICATION=y)
make menuconfig
# Navigate to: Processor type and features → Page table replication support

# Build
make -j$(nproc)
sudo make modules_install
sudo make install
```

#### Building the Daemon

```bash
gcc -O2 -o waspd waspd.c -lm
```

## Usage

### Daemon Modes

```bash
# Full WASP mode (recommended)
# - Monitors perf counters
# - Measures PTL between nodes
# - Steers threads to optimal replicas
sudo ./waspd 1

# Full mode with custom PTL interval
sudo ./waspd 1 -i 5    # Measure PTL every 5 seconds

# Naive mode (no PTL measurement)
# - Only uses perf counters for enable/disable decisions
# - Threads always use local replica
sudo ./waspd 0

# Exclude specific programs
sudo ./waspd 1 -x stream -x benchmark
```

### Manual Control via prctl

```c
#include <sys/prctl.h>

#define PR_SET_PGTABLE_REPL      100
#define PR_GET_PGTABLE_REPL      101
#define PR_SET_PGTABLE_REPL_NODE 102
#define PR_GET_PGTABLE_REPL_NODE 103

// Enable replication on all online nodes
prctl(PR_SET_PGTABLE_REPL, 1, 0, 0, 0);

// Enable on specific nodes (e.g., nodes 0 and 2)
prctl(PR_SET_PGTABLE_REPL, (1 << 0) | (1 << 2), 0, 0, 0);

// Disable replication
prctl(PR_SET_PGTABLE_REPL, 0, 0, 0, 0);

// Force current thread to use node 1's replica
prctl(PR_SET_PGTABLE_REPL_NODE, 1, 0, 0, 0);

// Return to automatic (local node) selection
prctl(PR_SET_PGTABLE_REPL_NODE, -1, 0, 0, 0);
```

### Sysctl Controls

```bash
# Auto-enable for new processes (default: -1 = disabled)
echo 1 > /proc/sys/kernel/mitosis_auto_enable

# Inheritance on fork (default: 1 = enabled)
echo 1 > /proc/sys/kernel/mitosis_inherit
```

### Monitoring

```bash
# View replication status
cat /proc/mitosis_status

# Example output:
# Mitosis Page Table Replication Status
# ======================================
# 
# Statistics:
#   CR3 writes: 12345
#   Replica uses: 10234
#   Primary uses: 2111
#   Replica hit rate: 82%
#
# Processes with replication:
#   PID 1234 (myapp): nodes=0,1,2,3 (total: 4 nodes)
#     Primary PGD on node 0
#     Has replica chain
```

## Key Features

1. **Automatic Enable/Disable**: Uses MAR and DTLB miss rate thresholds to determine when PTSR is beneficial

2. **PTL-Based Steering**: Measures actual memory latency between nodes and steers threads to the replica with lowest latency (not always local!)

3. **Memory Controller Contention Handling**: Unlike basic Mitosis, WASP can detect when local memory is congested and use remote replicas instead

4. **Per-Thread Replica Selection**: Different threads can use different replicas based on their execution location and the current PTL matrix

## Files

```
.
├── README.md                 # This file
├── prepare.sh               # Environment preparation script
├── install.sh               # Build and install script
└── waspd.c                  # Userspace daemon source
```

## References

This implementation is based on:

```bibtex
@inproceedings{wasp2024,
  author = {Qu, Hongliang and Yu, Zhibin},
  title = {WASP: Workload-Aware Self-Replicating Page-Tables for NUMA Servers},
  booktitle = {Proceedings of the 29th ACM International Conference on 
               Architectural Support for Programming Languages and 
               Operating Systems (ASPLOS '24)},
  year = {2024},
  doi = {10.1145/3620665.3640369}
}
```

## License

This implementation is provided for research and educational purposes.
