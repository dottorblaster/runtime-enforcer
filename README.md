# runtime-enforcer
A runtime enforcement solution for your Kubernetes cluster.

Still under development. For further information, please see the [RFCs](docs/rfc).

## Compatibility Matrix

See [docs/compatibility.adoc](docs/compatibility.adoc) for complete details.

### Supported Kubernetes Versions

| Kubernetes Version | Support Status |
|-------------------|----------------|
| 1.35.x | ✓ Supported |
| 1.36.x+ | ✓ Supported |

### Supported Operating Systems

| Operating System | Minimum Kernel | Recommended Kernel | x86_64 | ARM64 | Notes |
|-----------------|---------------|-------------------|--------|-------|-------|
| Ubuntu 22.04 LTS | 5.15 | 6.8+ | ✓ | ✓ | Verified on 6.8.0-52 |
| Ubuntu 24.04 LTS | 6.8 | 6.8+ | ✓ | ✓ | |
| SLES 15 SP4+ | 5.14 | 5.14+ | ✓ | ✓ | |
| RHEL 8.x | 4.18† | 4.18† | ✓ | ✓ | Requires BTF backport |
| RHEL 9.x | 5.14 | 5.14+ | ✓ | ✓ | |
| openSUSE Leap 15.4+ | 5.14 | 5.14+ | ✓ | ✓ | |
| Debian 11 (Bullseye) | 5.10 | 5.10+ | ✓ | ✓ | |
| Debian 12 (Bookworm) | 6.1 | 6.1+ | ✓ | ✓ | |

† RHEL 8.x kernel 4.18 includes backported eBPF features from newer kernels. BTF support required.

### Kernel Requirements

| Kernel Version | Support Level | Features Available |
|---------------|---------------|-------------------|
| 5.4 - 5.10 | Minimum | Basic eBPF, limited hash key sizes (≤512 bytes) |
| 5.11 - 5.12 | Supported | Extended hash keys (≤4096 bytes) |
| 5.13 - 6.3 | Recommended | bpf_loop support, improved performance |
| 6.4+ | Optimal | All features including bpf_iter_num for best performance |

**Required Kernel Features:**
- eBPF with BTF (BPF Type Format) - `CONFIG_DEBUG_INFO_BTF=y`
- BPF ring buffer support (kernel 5.8+)
- CO-RE (Compile Once - Run Everywhere) support
- Cgroup v1 or v2

### Rancher Integration

| Rancher Version | Support Status |
|----------------|----------------|
| 2.6.x - 2.12.x | ✓ Supported |

## Documentation

### Development

- [Setup a development environment](docs/setup-development-env.md)
- [Compatibility Matrix](docs/compatibility.adoc)
