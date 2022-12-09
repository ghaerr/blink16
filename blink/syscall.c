/*-*- mode:c;indent-tabs-mode:nil;c-basic-offset:2;tab-width:8;coding:utf-8 -*-│
│vi: set net ft=c ts=2 sts=2 sw=2 fenc=utf-8                                :vi│
╞══════════════════════════════════════════════════════════════════════════════╡
│ Copyright 2022 Justine Alexandra Roberts Tunney                              │
│                                                                              │
│ Permission to use, copy, modify, and/or distribute this software for         │
│ any purpose with or without fee is hereby granted, provided that the         │
│ above copyright notice and this permission notice appear in all copies.      │
│                                                                              │
│ THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL                │
│ WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED                │
│ WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE             │
│ AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL         │
│ DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR        │
│ PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER               │
│ TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR             │
│ PERFORMANCE OF THIS SOFTWARE.                                                │
╚─────────────────────────────────────────────────────────────────────────────*/
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <poll.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "blink/assert.h"
#include "blink/case.h"
#include "blink/debug.h"
#include "blink/endian.h"
#include "blink/errno.h"
#include "blink/iovs.h"
#include "blink/linux.h"
#include "blink/lock.h"
#include "blink/log.h"
#include "blink/machine.h"
#include "blink/macros.h"
#include "blink/map.h"
#include "blink/mop.h"
#include "blink/pml4t.h"
#include "blink/random.h"
#include "blink/signal.h"
#include "blink/swap.h"
#include "blink/syscall.h"
#include "blink/timespec.h"
#include "blink/timeval.h"
#include "blink/util.h"
#include "blink/xlat.h"

#define POLLING_INTERVAL_MS 50

#define ASSIGN(D, S) memcpy(&D, &S, MIN(sizeof(S), sizeof(D)))
#define SYSCALL(x, name, args)                                              \
  CASE(x, SYS_LOGF("%s(%#" PRIx64 ", %#" PRIx64 ", %#" PRIx64 ", %#" PRIx64 \
                   ", %#" PRIx64 ", %#" PRIx64 ")",                         \
                   #name, di, si, dx, r0, r8, r9);                          \
       ax = name args)

char *g_blink_path;

// delegate to work around function pointer errors, b/c
// old musl toolchains using `int ioctl(int, int, ...)`
static int SystemIoctl(int fd, unsigned long request, ...) {
  va_list va;
  intptr_t arg;
  va_start(va, request);
  arg = va_arg(va, intptr_t);
  va_end(va);
  return ioctl(fd, request, arg);
}

const struct FdCb kFdCbHost = {
    .close = close,
    .readv = readv,
    .writev = writev,
    .ioctl = SystemIoctl,
    .poll = poll,
};

void AddStdFd(struct Fds *fds, int fildes) {
  int flags;
  struct Fd *fd;
  if ((flags = fcntl(fildes, F_GETFL)) >= 0) {
    unassert((fd = AllocateFd(fds, fildes, flags)));
    unassert(fd->fildes == fildes);
    atomic_store_explicit(&fd->systemfd, fildes, memory_order_release);
  }
}

struct Fd *GetAndLockFd(struct Machine *m, int fildes) {
  struct Fd *fd;
  LockFds(&m->system->fds);
  if ((fd = GetFd(&m->system->fds, fildes))) LockFd(fd);
  UnlockFds(&m->system->fds);
  return fd;
}

int GetFildes(struct Machine *m, int fildes) {
  int systemfd;
  struct Fd *fd;
  LockFds(&m->system->fds);
  if ((fd = GetFd(&m->system->fds, fildes))) {
    systemfd = atomic_load_explicit(&fd->systemfd, memory_order_relaxed);
  } else {
    systemfd = -1;
  }
  UnlockFds(&m->system->fds);
  return systemfd;
}

static int GetDirFildes(struct Machine *m, int fildes) {
  if (fildes == AT_FDCWD_LINUX) return AT_FDCWD;
  return GetFildes(m, fildes);
}

int GetAfd(struct Machine *m, int fildes, struct Fd **out_fd) {
  struct Fd *fd;
  if (fildes == AT_FDCWD_LINUX) {
    *out_fd = 0;
    return 0;
  } else if ((fd = GetFd(&m->system->fds, fildes))) {
    *out_fd = fd;
    return 0;
  } else {
    return -1;
  }
}

static bool IsOrphan(struct Machine *m) {
  bool res;
  LOCK(&m->system->machines_lock);
  if (m->system->machines == m->system->machines->next &&
      m->system->machines == m->system->machines->prev) {
    unassert(m == MACHINE_CONTAINER(m->system->machines));
    res = true;
  } else {
    res = false;
  }
  UNLOCK(&m->system->machines_lock);
  return res;
}

_Noreturn static void SysExit(struct Machine *m, int rc) {
  atomic_int *ctid;
  if (m->ctid && (ctid = (atomic_int *)LookupAddress(m, m->ctid))) {
    atomic_store_explicit(ctid, 0, memory_order_seq_cst);
  }
  if (IsOrphan(m)) {
    HaltMachine(m, kMachineExit | (rc & 255));
  } else {
    FreeMachine(m);
    pthread_exit(0);
  }
}

_Noreturn static void SysExitGroup(struct Machine *m, int rc) {
  if (m->system->isfork) {
    _Exit(rc);
  } else {
    HaltMachine(m, kMachineExit | (rc & 255));
  }
}

static int SysFork(struct Machine *m) {
  int pid;
  pid = fork();
  if (!pid) m->system->isfork = true;
  return pid;
}

static int SysVfork(struct Machine *m) {
  return SysFork(m);
}

static void *OnSpawn(void *arg) {
  int rc;
  struct Machine *m = (struct Machine *)arg;
  g_machine = m;
  if (!(rc = setjmp(m->onhalt))) {
    unassert(!pthread_sigmask(SIG_SETMASK, &m->thread_sigmask, 0));
    Actor(m);
  } else {
    LOGF("halting machine from thread: %d", rc);
    exit(rc);
  }
}

static int SysSpawn(struct Machine *m, u64 flags, u64 stack, u64 ptid, u64 ctid,
                    u64 tls, u64 func) {
  int tid, err;
  int supported;
  int mandatory;
  sigset_t ss, oldss;
  pthread_attr_t attr;
  atomic_int *ptid_ptr;
  atomic_int *ctid_ptr;
  struct Machine *m2 = 0;
  supported = CLONE_THREAD_LINUX | CLONE_VM_LINUX | CLONE_FS_LINUX |
              CLONE_FILES_LINUX | CLONE_SIGHAND_LINUX | CLONE_SETTLS_LINUX |
              CLONE_PARENT_SETTID_LINUX | CLONE_CHILD_CLEARTID_LINUX |
              CLONE_CHILD_SETTID_LINUX | CLONE_SYSVSEM_LINUX;
  mandatory = CLONE_THREAD_LINUX | CLONE_VM_LINUX | CLONE_FS_LINUX |
              CLONE_FILES_LINUX | CLONE_SIGHAND_LINUX;
  if (flags & ~supported) {
    LOGF("unsupported clone() flags: %#x", flags);
    return einval();
  }
  if ((flags & mandatory) != mandatory) {
    LOGF("missing mandatory clone() thread flags: %#x",
         (flags & mandatory) ^ mandatory);
    return einval();
  }
  if (((flags & CLONE_PARENT_SETTID_LINUX) &&
       ((ptid & (sizeof(int) - 1)) ||
        !(ptid_ptr = (atomic_int *)LookupAddress(m, ptid)))) ||
      ((flags & CLONE_CHILD_SETTID_LINUX) &&
       ((ctid & (sizeof(int) - 1)) ||
        !(ctid_ptr = (atomic_int *)LookupAddress(m, ctid))))) {
    LOGF("bad clone() ptid / ctid pointers: %#x", flags);
    return efault();
  }
  if (!(m2 = NewMachine(m->system, m))) {
    return eagain();
  }
  sigfillset(&ss);
  unassert(!pthread_sigmask(SIG_SETMASK, &ss, &oldss));
  tid = m2->tid;
  if (flags & CLONE_SETTLS_LINUX) {
    m2->fs = tls;
  }
  if (flags & CLONE_CHILD_CLEARTID_LINUX) {
    m2->ctid = ctid;
  }
  if (flags & CLONE_CHILD_SETTID_LINUX) {
    atomic_store_explicit(ctid_ptr, Little32(tid), memory_order_release);
  }
  Put64(m2->ax, 0);
  Put64(m2->sp, stack);
  m2->thread_sigmask = oldss;
  unassert(!pthread_attr_init(&attr));
  unassert(!pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED));
  err = pthread_create(&m2->thread, &attr, OnSpawn, m2);
  unassert(!pthread_attr_destroy(&attr));
  if (err) {
    FreeMachine(m2);
    unassert(!pthread_sigmask(SIG_SETMASK, &oldss, 0));
    return eagain();
  }
  if (flags & CLONE_PARENT_SETTID_LINUX) {
    atomic_store_explicit(ptid_ptr, Little32(tid), memory_order_release);
  }
  unassert(!pthread_sigmask(SIG_SETMASK, &oldss, 0));
  return tid;
}

static int SysClone(struct Machine *m, u64 flags, u64 stack, u64 ptid, u64 ctid,
                    u64 tls, u64 func) {
  if (flags == SIGCHLD_LINUX) {
    if (stack) return einval();
    return SysFork(m);
  } else if (flags == (CLONE_VM_LINUX | CLONE_VFORK_LINUX | SIGCHLD_LINUX)) {
    if (stack) return einval();
    return SysVfork(m);
  } else {
    return SysSpawn(m, flags, stack, ptid, ctid, tls, func);
  }
}

static struct Futex *NewFutex(i64 addr) {
  struct Futex *f;
  if ((f = calloc(1, sizeof(struct Futex)))) {
    pthread_cond_init(&f->cond, 0);
    pthread_mutex_init(&f->lock, 0);
    dll_init(&f->elem);
    f->addr = addr;
  }
  return f;
}

static struct Futex *FindFutex(struct Machine *m, i64 addr) {
  struct Dll *e;
  for (e = dll_first(m->system->futexes); e;
       e = dll_next(m->system->futexes, e)) {
    if (FUTEX_CONTAINER(e)->addr == addr) {
      return FUTEX_CONTAINER(e);
    }
  }
  return 0;
}

static int SysFutexWait(struct Machine *m,  //
                        i64 uaddr,          //
                        i32 op,             //
                        u32 expect,         //
                        i64 timeout_addr) {
  int rc;
  u8 *mem;
  struct Futex *f;
  struct timespec timeout;
  struct timespec_linux gtimeout;
  if (timeout_addr) {
    CopyFromUserRead(m, &gtimeout, timeout_addr, sizeof(gtimeout));
    timeout.tv_sec = Read64(gtimeout.tv_sec);
    timeout.tv_nsec = Read64(gtimeout.tv_nsec);
    if (timeout.tv_nsec >= 1000000000) return einval();
    timeout = AddTime(GetTime(), timeout);
  } else {
    timeout = GetMaxTime();
  }
  if (!(mem = LookupAddress(m, uaddr))) return efault();
  LOCK(&m->system->futex_lock);
  if (Load32(mem) != expect) {
    UNLOCK(&m->system->futex_lock);
    return eagain();
  }
  if ((f = FindFutex(m, uaddr))) {
    LOCK(&f->lock);
  }
  if (!f) {
    if ((f = NewFutex(uaddr))) {
      m->system->futexes = dll_make_first(m->system->futexes, &f->elem);
      LOCK(&f->lock);
    } else {
      UNLOCK(&m->system->futex_lock);
      return -1;
    }
  }
  ++f->waiters;
  UNLOCK(&m->system->futex_lock);
  rc = pthread_cond_timedwait(&f->cond, &f->lock, &timeout);
  if (--f->waiters) {
    UNLOCK(&f->lock);
  } else {
    LOCK(&m->system->futex_lock);
    m->system->futexes = dll_remove(m->system->futexes, &f->elem);
    UNLOCK(&m->system->futex_lock);
    UNLOCK(&f->lock);
    free(f);
  }
  if (rc) {
    errno = rc;
    rc = -1;
  }
  return rc;
}

static int SysFutexWake(struct Machine *m,  //
                        i64 uaddr,          //
                        i32 op,             //
                        u32 count) {
  int rc;
  struct Futex *f;
  if (!count) return 0;
  LOCK(&m->system->futex_lock);
  if ((f = FindFutex(m, uaddr))) {
    LOCK(&f->lock);
  }
  UNLOCK(&m->system->futex_lock);
  if (f) {
    unassert(f->waiters);
    if (count == 1) {
      unassert(!pthread_cond_signal(&f->cond));
      rc = 1;
    } else {
      unassert(!pthread_cond_broadcast(&f->cond));
      rc = f->waiters;
    }
    UNLOCK(&f->lock);
  } else {
    rc = 0;
  }
  return rc;
}

static int SysFutex(struct Machine *m,  //
                    i64 uaddr,          //
                    i32 op,             //
                    u32 val,            //
                    i64 timeout_addr,   //
                    i64 uaddr2,         //
                    u32 val3) {
  if (uaddr & 3) return efault();
  switch (op) {
    case FUTEX_WAIT_LINUX:
    case FUTEX_WAIT_LINUX | FUTEX_PRIVATE_FLAG_LINUX:
      return SysFutexWait(m, uaddr, op, val, timeout_addr);
      break;
    case FUTEX_WAKE_LINUX:
    case FUTEX_WAKE_LINUX | FUTEX_PRIVATE_FLAG_LINUX:
      return SysFutexWake(m, uaddr, op, val);
    default:
      return einval();
  }
}

static int SysPrctl(struct Machine *m, int op, i64 a, i64 b, i64 c, i64 d) {
  return einval();
}

static int SysArchPrctl(struct Machine *m, int code, i64 addr) {
  u8 buf[8];
  switch (code) {
    case ARCH_SET_GS_LINUX:
      m->gs = addr;
      return 0;
    case ARCH_SET_FS_LINUX:
      m->fs = addr;
      return 0;
    case ARCH_GET_GS_LINUX:
      Write64(buf, m->gs);
      CopyToUserWrite(m, addr, buf, 8);
      return 0;
    case ARCH_GET_FS_LINUX:
      Write64(buf, m->fs);
      CopyToUserWrite(m, addr, buf, 8);
      return 0;
    default:
      return einval();
  }
}

static u64 Prot2Page(int prot) {
  u64 key = 0;
  if (prot & ~(PROT_READ | PROT_WRITE | PROT_EXEC)) return einval();
  if (prot & PROT_READ) key |= PAGE_U;
  if (prot & PROT_WRITE) key |= PAGE_RW;
  if (~prot & PROT_EXEC) key |= PAGE_XD;
  return key;
}

static int SysMprotect(struct Machine *m, i64 addr, u64 size, int prot) {
  u64 key;
  size_t i;
  long gotsome = 0;
  if (!IsValidAddrSize(addr, size)) return einval();
  if ((key = Prot2Page(prot)) == -1) return einval();
  LOCK(&m->system->mmap_lock);
  ProtectVirtual(m->system, addr, size, ~(PAGE_U | PAGE_RW | PAGE_XD), key);
  if (prot & PROT_EXEC) {
    for (i = 0; i < m->system->codesize; ++i) {
      if (m->system->codestart + i >= addr &&
          m->system->codestart + i < addr + size) {
        atomic_store_explicit(m->system->fun + i, GeneralDispatch,
                              memory_order_relaxed);
        ++gotsome;
      }
    }
  }
  UNLOCK(&m->system->mmap_lock);
  if (gotsome) {
    MEM_LOGF("mprotect(PROT_EXEC) reset %ld JIT hooks", gotsome);
    InvalidateSystem(m->system, false, true);
  }
  return 0;
}

static int SysMadvise(struct Machine *m, i64 addr, size_t len, int advice) {
  return 0;
}

static i64 SysBrk(struct Machine *m, i64 addr) {
  i64 rc;
  long pagesize;
  LOCK(&m->system->mmap_lock);
  MEM_LOGF("brk(%#" PRIx64 ") currently %#" PRIx64, addr, m->system->brk);
  pagesize = GetSystemPageSize();
  addr = ROUNDUP(addr, pagesize);
  if (addr >= kMinBrk) {
    if (addr > m->system->brk) {
      if (ReserveVirtual(m->system, m->system->brk, addr - m->system->brk,
                         PAGE_RW | PAGE_U, -1, false) != -1) {
        m->system->brk = addr;
      }
    } else if (addr < m->system->brk) {
      if (FreeVirtual(m->system, addr, m->system->brk - addr) != -1) {
        m->system->brk = addr;
      }
    }
  }
  rc = m->system->brk;
  UNLOCK(&m->system->mmap_lock);
  return rc;
}

static int SysMunmap(struct Machine *m, i64 virt, u64 size) {
  int rc;
  if (!IsValidAddrSize(virt, size)) return einval();
  LOCK(&m->system->mmap_lock);
  rc = FreeVirtual(m->system, virt, size);
  UNLOCK(&m->system->mmap_lock);
  return rc;
}

static i64 SysMmap(struct Machine *m, i64 virt, size_t size, int prot,
                   int flags, int fildes, i64 offset) {
  u64 key;
  void *tmp;
  ssize_t rc;
  int systemfd;
  long pagesize;
  struct Fd *fd;
  if (!IsValidAddrSize(virt, size)) return einval();
  if (flags & MAP_GROWSDOWN_LINUX) return enotsup();
  if ((key = Prot2Page(prot)) == -1) return einval();
  if (flags & MAP_FIXED_NOREPLACE_LINUX) return enotsup();
  if (fildes != -1) {
    if (flags & MAP_ANONYMOUS_LINUX) {
      return einval();
    }
    if ((fd = GetAndLockFd(m, fildes))) {
      systemfd = atomic_load_explicit(&fd->systemfd, memory_order_relaxed);
    } else {
      return -1;
    }
  } else {
    systemfd = -1;
    fd = 0;
  }
  LOCK(&m->system->mmap_lock);
  if (!(flags & MAP_FIXED_LINUX)) {
    if (!virt) {
      if ((virt = FindVirtual(m->system, m->system->brk, size)) == -1) {
        UNLOCK(&m->system->mmap_lock);
        goto Finished;
      }
      pagesize = GetSystemPageSize();
      m->system->brk = ROUNDUP(virt + size, pagesize);
    } else {
      if ((virt = FindVirtual(m->system, virt, size)) == -1) {
        UNLOCK(&m->system->mmap_lock);
        goto Finished;
      }
    }
  }
  rc = ReserveVirtual(m->system, virt, size, key, systemfd,
                      !!(flags & MAP_SHARED_LINUX));
  UNLOCK(&m->system->mmap_lock);
  if (rc != -1) {
    if (fd && m->system->nolinear) {
      // TODO(jart): Raise SIGBUS on i/o error.
      // TODO(jart): Support lazy file mappings.
      unassert((tmp = malloc(size)));
      for (;;) {
        rc = pread(systemfd, tmp, size, offset);
        if (rc != -1) break;
        if (errno != EINTR) {
          LOGF("failed to read %zu bytes at offset %" PRId64
               " from fd %d into memory map: %s",
               size, offset, systemfd, strerror(errno));
          abort();
        }
      }
      unassert(size == rc);
      CopyToUserWrite(m, virt, tmp, size);
      free(tmp);
    }
  } else {
    FreeVirtual(m->system, virt, size);
    virt = -1;
  }
Finished:
  if (fd) UnlockFd(fd);
  return virt;
}

static int SysMsync(struct Machine *m, i64 virt, size_t size, int flags) {
  return enosys();
}

static int SysDup1(struct Machine *m, i32 fildes) {
  return SysDup(m, fildes, -1, 0, 0);
}

static int SysDup2(struct Machine *m, i32 fildes, i32 newfildes) {
  if (newfildes < 0) return ebadf();
  return SysDup(m, fildes, newfildes, 0, 0);
}

static int SysDup3(struct Machine *m, i32 fildes, i32 newfildes, i32 flags) {
  if (newfildes < 0) return ebadf();
  if (fildes == newfildes) return einval();
  return SysDup(m, fildes, -1, 0, 0);
}

static void FixupSock(int systemfd, int flags) {
  if (flags & SOCK_CLOEXEC_LINUX) {
    unassert(!fcntl(systemfd, F_SETFD, FD_CLOEXEC));
  }
  if (flags & SOCK_NONBLOCK_LINUX) {
    unassert(!fcntl(systemfd, F_SETFL, O_NDELAY));
  }
}

void DropFd(struct Machine *m, struct Fd *fd) {
  LockFds(&m->system->fds);
  FreeFd(&m->system->fds, fd);
  UnlockFds(&m->system->fds);
}

static int SysSocket(struct Machine *m, i32 family, i32 type, i32 protocol) {
  struct Fd *fd;
  int flags, fildes, systemfd;
  flags = type & (SOCK_NONBLOCK_LINUX | SOCK_CLOEXEC_LINUX);
  type &= ~(SOCK_NONBLOCK_LINUX | SOCK_CLOEXEC_LINUX);
  if ((family = XlatSocketFamily(family)) == -1) return -1;
  if ((type = XlatSocketType(type)) == -1) return -1;
  if ((protocol = XlatSocketProtocol(protocol)) == -1) return -1;
  LockFds(&m->system->fds);
  fd = AllocateFd(&m->system->fds, 0,
                  O_RDWR | (flags & SOCK_CLOEXEC_LINUX ? O_CLOEXEC : 0) |
                      (flags & SOCK_NONBLOCK_LINUX ? O_NDELAY : 0));
  UnlockFds(&m->system->fds);
  if (fd) {
    if ((systemfd = socket(family, type, protocol)) != -1) {
      FixupSock(systemfd, flags);
      fildes = fd->fildes;
      atomic_store_explicit(&fd->systemfd, systemfd, memory_order_release);
    } else {
      fildes = -1;
    }
  } else {
    fildes = -1;
  }
  if (fildes == -1 && fd) DropFd(m, fd);
  return fildes;
}

static int SysSocketName(struct Machine *m, i32 fildes, i64 aa, i64 asa,
                         int SocketName(int, struct sockaddr *, socklen_t *)) {
  int rc;
  u32 addrsize;
  struct Fd *fd;
  u8 gaddrsize[4];
  struct sockaddr_in addr;
  struct sockaddr_in_linux gaddr;
  CopyFromUserRead(m, gaddrsize, asa, sizeof(gaddrsize));
  if (Read32(gaddrsize) < sizeof(gaddr)) return einval();
  if (!(fd = GetAndLockFd(m, fildes))) return -1;
  addrsize = sizeof(addr);
  rc = SocketName(fd->systemfd, (struct sockaddr *)&addr, &addrsize);
  if (rc != -1) {
    Write32(gaddrsize, sizeof(gaddr));
    XlatSockaddrToLinux(&gaddr, &addr);
    CopyToUser(m, asa, gaddrsize, sizeof(gaddrsize));
    CopyToUserWrite(m, aa, &gaddr, sizeof(gaddr));
  }
  UnlockFd(fd);
  return rc;
}

static int SysUname(struct Machine *m, i64 utsaddr) {
  struct utsname_linux uts = {
      .sysname = "blink",
      .nodename = "blink.local",
      .release = "4.0",        // or glibc whines
      .version = "blink 4.0",  // or glibc whines
      .machine = "x86_64",
  };
  strcpy(uts.sysname, "unknown");
  strcpy(uts.sysname, "unknown");
  CopyToUser(m, utsaddr, &uts, sizeof(uts));
  return 0;
}

static int SysGetsockname(struct Machine *m, int fd, i64 aa, i64 asa) {
  return SysSocketName(m, fd, aa, asa, getsockname);
}

static int SysGetpeername(struct Machine *m, int fd, i64 aa, i64 asa) {
  return SysSocketName(m, fd, aa, asa, getpeername);
}

static int SysAccept4(struct Machine *m, i32 fildes, i64 aa, i64 asa,
                      i32 flags) {
  u32 addrsize;
  int systemfd;
  u8 gaddrsize[4];
  struct Fd *fd1, *fd2;
  struct sockaddr_in addr;
  struct sockaddr_in_linux gaddr;
  if (m->system->redraw) m->system->redraw();
  if (flags & ~(SOCK_CLOEXEC_LINUX | SOCK_NONBLOCK_LINUX)) return einval();
  if (aa) {
    CopyFromUserRead(m, gaddrsize, asa, sizeof(gaddrsize));
    if (Read32(gaddrsize) < sizeof(gaddr)) return einval();
  }
  LockFds(&m->system->fds);
  if ((fd1 = GetFd(&m->system->fds, fildes))) {
    LockFd(fd1);
    fd2 = AllocateFd(&m->system->fds, 0,
                     O_RDWR | (flags & SOCK_CLOEXEC_LINUX ? O_CLOEXEC : 0) |
                         (flags & SOCK_NONBLOCK_LINUX ? O_NDELAY : 0));
  } else {
    fd2 = 0;
  }
  UnlockFds(&m->system->fds);
  if (fd1 && fd2) {
    addrsize = sizeof(addr);
    systemfd = atomic_load_explicit(&fd1->systemfd, memory_order_relaxed);
    systemfd = accept(systemfd, (struct sockaddr *)&addr, &addrsize);
    if (systemfd != -1) {
      FixupSock(systemfd, flags);
      if (aa) {
        Write32(gaddrsize, sizeof(gaddr));
        XlatSockaddrToLinux(&gaddr, &addr);
        CopyToUser(m, asa, gaddrsize, sizeof(gaddrsize));
        CopyToUserWrite(m, aa, &gaddr, sizeof(gaddr));
      }
      fildes = fd2->fildes;
      atomic_store_explicit(&fd2->systemfd, systemfd, memory_order_release);
    } else {
      fildes = -1;
    }
  } else {
    fildes = -1;
  }
  if (fd1) UnlockFd(fd1);
  if (fd2 && fildes == -1) DropFd(m, fd2);
  return fildes;
}

static int SysConnectBind(struct Machine *m, i32 fildes, i64 aa, u32 as,
                          int impl(int, const struct sockaddr *, u32)) {
  int rc;
  struct Fd *fd;
  struct sockaddr_in addr;
  struct sockaddr_in_linux gaddr;
  if (as != sizeof(gaddr)) return einval();
  CopyFromUserRead(m, &gaddr, aa, sizeof(gaddr));
  if (XlatSockaddrToHost(&addr, &gaddr) == -1) return -1;
  if (!(fd = GetAndLockFd(m, fildes))) return -1;
  rc = impl(fd->systemfd, (const struct sockaddr *)&addr, sizeof(addr));
  UnlockFd(fd);
  return rc;
}

static int SysBind(struct Machine *m, int fd, i64 aa, u32 as) {
  return SysConnectBind(m, fd, aa, as, bind);
}

static int SysConnect(struct Machine *m, int fd, i64 aa, u32 as) {
  return SysConnectBind(m, fd, aa, as, connect);
}

static int SysSetsockopt(struct Machine *m, i32 fildes, i32 level, i32 optname,
                         i64 optvaladdr, u32 optvalsize) {
  int rc;
  void *optval;
  struct Fd *fd;
  if (optvalsize > 256) return einval();
  if ((level = XlatSocketLevel(level)) == -1) return -1;
  if ((optname = XlatSocketOptname(level, optname)) == -1) return -1;
  if (!(optval = calloc(1, optvalsize))) return -1;
  if (!(fd = GetAndLockFd(m, fildes))) {
    free(optval);
    return -1;
  }
  CopyFromUserRead(m, optval, optvaladdr, optvalsize);
  rc = setsockopt(fd->systemfd, level, optname, optval, optvalsize);
  UnlockFd(fd);
  free(optval);
  return rc;
}

static i64 SysReadImpl(struct Machine *m, struct Fd *fd, i64 addr, u64 size) {
  i64 rc;
  struct Iovs iv;
  unassert(fd->cb);
  InitIovs(&iv);
  if ((rc = AppendIovsReal(m, &iv, addr, size)) != -1 &&
      (rc = IB(fd->cb->readv)(fd->systemfd, iv.p, iv.i)) != -1) {
    SetWriteAddr(m, addr, rc);
  }
  FreeIovs(&iv);
  return rc;
}

static i64 SysWriteImpl(struct Machine *m, struct Fd *fd, i64 addr, u64 size) {
  i64 rc;
  struct Iovs iv;
  unassert(fd->cb);
  InitIovs(&iv);
  if ((rc = AppendIovsReal(m, &iv, addr, size)) != -1 &&
      (rc = IB(fd->cb->writev)(fd->systemfd, iv.p, iv.i)) != -1) {
    SetReadAddr(m, addr, rc);
  }
  FreeIovs(&iv);
  return rc;
}

static i64 SysRead(struct Machine *m, i32 fildes, i64 addr, u64 size) {
  i64 rc;
  struct Fd *fd;
  if (!(fd = GetAndLockFd(m, fildes))) return -1;
  rc = SysReadImpl(m, fd, addr, size);
  UnlockFd(fd);
  return rc;
}

static i64 SysWrite(struct Machine *m, i32 fildes, i64 addr, u64 size) {
  i64 rc;
  struct Fd *fd;
  if (!(fd = GetAndLockFd(m, fildes))) return -1;
  rc = SysWriteImpl(m, fd, addr, size);
  UnlockFd(fd);
  return rc;
}

static off_t TellAndSeek(struct Fd *fd, u64 offset) {
  off_t oldpos;
  if ((oldpos = lseek(fd->systemfd, 0, SEEK_CUR)) != -1 &&
      lseek(fd->systemfd, offset, SEEK_SET) != -1) {
    return oldpos;
  } else {
    return -1;
  }
}

static i64 SysPread(struct Machine *m, i32 fildes, i64 addr, u64 size,
                    u64 offset) {
  i64 rc;
  off_t oldpos;
  struct Fd *fd;
  if (!(fd = GetAndLockFd(m, fildes))) return -1;
  if ((oldpos = TellAndSeek(fd, offset)) != -1) {
    rc = SysReadImpl(m, fd, addr, size);
    lseek(fd->systemfd, oldpos, SEEK_SET);
  } else {
    rc = -1;
  }
  UnlockFd(fd);
  return rc;
}

static i64 SysPwrite(struct Machine *m, i32 fildes, i64 addr, u64 size,
                     u64 offset) {
  i64 rc;
  off_t oldpos;
  struct Fd *fd;
  if (!(fd = GetAndLockFd(m, fildes))) return -1;
  if ((oldpos = TellAndSeek(fd, offset)) != -1) {
    rc = SysWriteImpl(m, fd, addr, size);
    lseek(fd->systemfd, oldpos, SEEK_SET);
  } else {
    rc = -1;
  }
  UnlockFd(fd);
  return rc;
}

static i64 SysReadv(struct Machine *m, i32 fildes, i64 iovaddr, i32 iovlen) {
  i64 rc;
  struct Fd *fd;
  struct Iovs iv;
  if (!(fd = GetAndLockFd(m, fildes))) return -1;
  unassert(fd->cb);
  InitIovs(&iv);
  if ((rc = AppendIovsGuest(m, &iv, iovaddr, iovlen)) != -1) {
    rc = IB(fd->cb->readv)(fd->systemfd, iv.p, iv.i);
  }
  UnlockFd(fd);
  FreeIovs(&iv);
  return rc;
}

static i64 SysWritev(struct Machine *m, i32 fildes, i64 iovaddr, i32 iovlen) {
  i64 rc;
  struct Fd *fd;
  struct Iovs iv;
  if (!(fd = GetAndLockFd(m, fildes))) return -1;
  unassert(fd->cb);
  InitIovs(&iv);
  if ((rc = AppendIovsGuest(m, &iv, iovaddr, iovlen)) != -1) {
    rc = IB(fd->cb->writev)(fd->systemfd, iv.p, iv.i);
  }
  UnlockFd(fd);
  FreeIovs(&iv);
  return rc;
}

static int UnXlatDt(int x) {
  switch (x) {
    XLAT(DT_UNKNOWN, DT_UNKNOWN_LINUX);
    XLAT(DT_FIFO, DT_FIFO_LINUX);
    XLAT(DT_CHR, DT_CHR_LINUX);
    XLAT(DT_DIR, DT_DIR_LINUX);
    XLAT(DT_BLK, DT_BLK_LINUX);
    XLAT(DT_REG, DT_REG_LINUX);
    XLAT(DT_LNK, DT_LNK_LINUX);
    XLAT(DT_SOCK, DT_SOCK_LINUX);
    default:
      __builtin_unreachable();
  }
}

static i64 SysGetdents(struct Machine *m, i32 fildes, i64 addr, i64 size) {
  int type;
  off_t off;
  int reclen;
  i64 i, dlz;
  size_t len;
  struct Fd *fd;
  struct dirent *ent;
  struct dirent_linux rec;
  dlz = sizeof(struct dirent_linux);
  if (size < dlz) return einval();
  if (!(fd = GetAndLockFd(m, fildes))) return -1;
  if (!fd->dirstream && !(fd->dirstream = fdopendir(fd->systemfd))) {
    UnlockFd(fd);
    return -1;
  }
  for (i = 0; i + dlz <= size; i += reclen) {
    unassert((off = telldir(fd->dirstream)) >= 0);
    if (!(ent = readdir(fd->dirstream))) break;
    len = strlen(ent->d_name);
    if (len + 1 > sizeof(rec.d_name)) {
      LOGF("ignoring %ld byte d_name: %s", len, ent->d_name);
      reclen = 0;
      continue;
    }
    type = UnXlatDt(ent->d_type);
    reclen = 8 + 8 + 2 + 1 + len + 1;
    Write64(rec.d_ino, 0);
    Write64(rec.d_off, off);
    Write16(rec.d_reclen, reclen);
    Write8(rec.d_type, type);
    strcpy(rec.d_name, ent->d_name);
    CopyToUserWrite(m, addr + i, &rec, reclen);
  }
  UnlockFd(fd);
  return i;
}

static int SysSetTidAddress(struct Machine *m, i64 ctid) {
  m->ctid = ctid;
  return m->tid;
}

static int IoctlTiocgwinsz(struct Machine *m, int fd, i64 addr,
                           int fn(int, unsigned long, ...)) {
  int rc;
  struct winsize ws;
  struct winsize_linux gws;
  if ((rc = fn(fd, TIOCGWINSZ, &ws)) != -1) {
    XlatWinsizeToLinux(&gws, &ws);
    CopyToUserWrite(m, addr, &gws, sizeof(gws));
  }
  return rc;
}

static int IoctlTcgets(struct Machine *m, int fd, i64 addr,
                       int fn(int, unsigned long, ...)) {
  int rc;
  struct termios tio;
  struct termios_linux gtio;
  if ((rc = fn(fd, TCGETS, &tio)) != -1) {
    XlatTermiosToLinux(&gtio, &tio);
    CopyToUserWrite(m, addr, &gtio, sizeof(gtio));
  }
  return rc;
}

static int IoctlTcsets(struct Machine *m, int fd, int request, i64 addr,
                       int fn(int, unsigned long, ...)) {
  struct termios tio;
  struct termios_linux gtio;
  CopyFromUserRead(m, &gtio, addr, sizeof(gtio));
  XlatLinuxToTermios(&tio, &gtio);
  return fn(fd, request, &tio);
}

static int SysIoctl(struct Machine *m, int fildes, u64 request, i64 addr) {
  struct Fd *fd;
  int rc, systemfd;
  int (*func)(int, unsigned long, ...);
  if (!(fd = GetAndLockFd(m, fildes))) return -1;
  unassert(fd->cb);
  func = IB(fd->cb->ioctl);
  systemfd = atomic_load_explicit(&fd->systemfd, memory_order_relaxed);
  switch (request) {
    case TIOCGWINSZ_LINUX:
      rc = IoctlTiocgwinsz(m, systemfd, addr, func);
      break;
    case TCGETS_LINUX:
      rc = IoctlTcgets(m, systemfd, addr, func);
      break;
    case TCSETS_LINUX:
      rc = IoctlTcsets(m, systemfd, TCSETS, addr, func);
      break;
    case TCSETSW_LINUX:
      rc = IoctlTcsets(m, systemfd, TCSETSW, addr, func);
      break;
    case TCSETSF_LINUX:
      rc = IoctlTcsets(m, systemfd, TCSETSF, addr, func);
      break;
    default:
      rc = einval();
      break;
  }
  UnlockFd(fd);
  return rc;
}

static i64 SysLseek(struct Machine *m, i32 fildes, i64 offset, int whence) {
  i64 rc;
  struct Fd *fd;
  if (!(fd = GetAndLockFd(m, fildes))) return -1;
  if (!fd->dirstream) {
    rc = lseek(fd->systemfd, offset, XlatWhence(whence));
  } else if (whence == SEEK_SET_LINUX) {
    seekdir(fd->dirstream, offset);
    rc = 0;
  } else {
    rc = einval();
  }
  UnlockFd(fd);
  return rc;
}

static i64 SysFtruncate(struct Machine *m, i32 fd, i64 size) {
  return ftruncate(GetFildes(m, fd), size);
}

static int SysFaccessat(struct Machine *m, i32 dirfd, i64 path, i32 mode,
                        i32 flags) {
  return faccessat(GetDirFildes(m, dirfd), LoadStr(m, path), XlatAccess(mode),
                   XlatAtf(flags));
}

static int SysFstatat(struct Machine *m, i32 dirfd, i64 path, i64 staddr,
                      i32 flags) {
  int rc;
  struct stat st;
  struct stat_linux gst;
  if ((rc = fstatat(GetDirFildes(m, dirfd), LoadStr(m, path), &st,
                    XlatAtf(flags))) != -1) {
    XlatStatToLinux(&gst, &st);
    CopyToUserWrite(m, staddr, &gst, sizeof(gst));
  }
  return rc;
}

static int SysFstat(struct Machine *m, i32 fd, i64 staddr) {
  int rc;
  struct stat st;
  struct stat_linux gst;
  if ((rc = fstat(GetFildes(m, fd), &st)) != -1) {
    XlatStatToLinux(&gst, &st);
    CopyToUserWrite(m, staddr, &gst, sizeof(gst));
  }
  return rc;
}

static int SysFsync(struct Machine *m, i32 fd) {
  return fsync(GetFildes(m, fd));
}

static int SysFdatasync(struct Machine *m, i32 fd) {
  return fdatasync(GetFildes(m, fd));
}

static int SysChdir(struct Machine *m, i64 path) {
  return chdir(LoadStr(m, path));
}

static int SysFlock(struct Machine *m, i32 fd, i32 lock) {
  return flock(GetFildes(m, fd), XlatLock(lock));
}

static int SysShutdown(struct Machine *m, i32 fd, i32 how) {
  return shutdown(GetFildes(m, fd), XlatShutdown(how));
}

static int SysListen(struct Machine *m, i32 fd, i32 backlog) {
  return listen(GetFildes(m, fd), backlog);
}

static int SysMkdir(struct Machine *m, i64 path, i32 mode) {
  return mkdir(LoadStr(m, path), mode);
}

static int SysFchmod(struct Machine *m, i32 fd, u32 mode) {
  return fchmod(GetFildes(m, fd), mode);
}

static int SysFcntl(struct Machine *m, i32 fildes, i32 cmd, i64 arg) {
  int rc, fl;
  struct Fd *fd;
  if (cmd == F_DUPFD_LINUX) {
    return SysDup(m, fildes, -1, 0, arg);
  }
  if (cmd == F_DUPFD_CLOEXEC_LINUX) {
    return SysDup(m, fildes, -1, O_CLOEXEC_LINUX, arg);
  }
  if (!(fd = GetAndLockFd(m, fildes))) return -1;
  if (cmd == F_GETFD_LINUX) {
    rc = fd->cloexec ? FD_CLOEXEC_LINUX : 0;
  } else if (cmd == F_GETFL_LINUX) {
    rc = UnXlatOpenFlags(fd->oflags);
  } else if (cmd == F_SETFD_LINUX) {
    if (!(arg & ~FD_CLOEXEC_LINUX)) {
      if (fcntl(fd->systemfd, F_SETFD, arg ? FD_CLOEXEC : 0) != -1) {
        fd->cloexec = !!arg;
        rc = 0;
      } else {
        rc = -1;
      }
    } else {
      rc = einval();
    }
  } else if (cmd == F_SETFL_LINUX) {
    fl = XlatOpenFlags(arg & (O_APPEND_LINUX | O_ASYNC_LINUX | O_DIRECT_LINUX |
                              O_NOATIME_LINUX | O_NDELAY_LINUX));
    if (fcntl(fd->systemfd, F_SETFL, fl) != -1) {
      fd->oflags &= ~(O_APPEND | O_ASYNC |
#ifdef O_DIRECT
                      O_DIRECT |
#endif
#ifdef O_NOATIME
                      O_NOATIME |
#endif
                      O_NDELAY);
      fd->oflags |= fl;
      rc = 0;
    } else {
      rc = -1;
    }
  } else {
    LOGF("missing fcntl() command %" PRId32, cmd);
    rc = einval();
  }
  UnlockFd(fd);
  return rc;
}

static ssize_t SysReadlinkat(struct Machine *m, int dirfd, i64 path,
                             i64 bufaddr, i64 size) {
  char *buf;
  ssize_t rc;
  if (size < 0) return einval();
  if (size > PATH_MAX) return enomem();
  if (!(buf = (char *)malloc(size))) return -1;
  if ((rc = readlinkat(GetDirFildes(m, dirfd), LoadStr(m, path), buf, size)) !=
      -1) {
    CopyToUserWrite(m, bufaddr, buf, rc);
  }
  free(buf);
  return rc;
}

static int SysRmdir(struct Machine *m, i64 path) {
  return rmdir(LoadStr(m, path));
}

static int SysUnlink(struct Machine *m, i64 path) {
  return unlink(LoadStr(m, path));
}

static int SysRename(struct Machine *m, i64 srcpath, i64 dstpath) {
  return rename(LoadStr(m, srcpath), LoadStr(m, dstpath));
}

static int SysChmod(struct Machine *m, i64 path, u32 mode) {
  return chmod(LoadStr(m, path), mode);
}

static int SysTruncate(struct Machine *m, i64 path, u64 length) {
  return truncate(LoadStr(m, path), length);
}

static int SysSymlink(struct Machine *m, i64 targetpath, i64 linkpath) {
  return symlink(LoadStr(m, targetpath), LoadStr(m, linkpath));
}

static int SysReadlink(struct Machine *m, i64 path, i64 bufaddr, u64 size) {
  return SysReadlinkat(m, AT_FDCWD_LINUX, path, bufaddr, size);
}

static int SysMkdirat(struct Machine *m, i32 dirfd, i64 path, i32 mode) {
  return mkdirat(GetDirFildes(m, dirfd), LoadStr(m, path), mode);
}

static int SysLink(struct Machine *m, i64 existingpath, i64 newpath) {
  return link(LoadStr(m, existingpath), LoadStr(m, newpath));
}

static int SysMknod(struct Machine *m, i64 path, i32 mode, u64 dev) {
  return mknod(LoadStr(m, path), mode, dev);
}

static int SysUnlinkat(struct Machine *m, i32 dirfd, i64 path, i32 flags) {
  return unlinkat(GetDirFildes(m, dirfd), LoadStr(m, path), XlatAtf(flags));
}

static int SysRenameat(struct Machine *m, int srcdirfd, i64 srcpath,
                       int dstdirfd, i64 dstpath) {
  return renameat(GetDirFildes(m, srcdirfd), LoadStr(m, srcpath),
                  GetDirFildes(m, dstdirfd), LoadStr(m, dstpath));
}

static int SysExecve(struct Machine *m, i64 pa, i64 aa, i64 ea) {
  if (m->system->exec) {
    _exit(m->system->exec(LoadStr(m, pa), LoadStrList(m, aa),
                          LoadStrList(m, ea)));
  } else {
    return enosys();
  }
}

static int SysWait4(struct Machine *m, int pid, i64 opt_out_wstatus_addr,
                    int options, i64 opt_out_rusage_addr) {
  int rc;
  i32 wstatus;
  struct rusage hrusage;
  struct rusage_linux grusage;
  if ((options = XlatWait(options)) == -1) return -1;
  if ((rc = wait4(pid, &wstatus, options, &hrusage)) != -1) {
    if (opt_out_wstatus_addr) {
      CopyToUserWrite(m, opt_out_wstatus_addr, &wstatus, sizeof(wstatus));
    }
    if (opt_out_rusage_addr) {
      XlatRusageToLinux(&grusage, &hrusage);
      CopyToUserWrite(m, opt_out_rusage_addr, &grusage, sizeof(grusage));
    }
  }
  return rc;
}

static int SysGetrusage(struct Machine *m, i32 resource, i64 rusageaddr) {
  int rc;
  struct rusage hrusage;
  struct rusage_linux grusage;
  if ((rc = getrusage(XlatRusage(resource), &hrusage)) != -1) {
    XlatRusageToLinux(&grusage, &hrusage);
    CopyToUserWrite(m, rusageaddr, &grusage, sizeof(grusage));
  }
  return rc;
}

static int SysGetrlimit(struct Machine *m, i32 resource, i64 rlimitaddr) {
  int rc;
  struct rlimit rlim;
  struct rlimit_linux lux;
  if ((rc = getrlimit(XlatResource(resource), &rlim)) != -1) {
    XlatRlimitToLinux(&lux, &rlim);
    CopyToUserWrite(m, rlimitaddr, &lux, sizeof(lux));
  }
  return rc;
}

static int SysSetrlimit(struct Machine *m, i32 resource, i64 rlimitaddr) {
  struct rlimit rlim;
  struct rlimit_linux lux;
  CopyFromUserRead(m, &lux, rlimitaddr, sizeof(lux));
  XlatRlimitToLinux(&lux, &rlim);
  return setrlimit(XlatResource(resource), &rlim);
}

static int SysPrlimit(struct Machine *m, i32 pid, i32 resource,
                      i64 new_rlimit_addr, i64 old_rlimit_addr) {
  int rc;
  struct rlimit old;
  struct rlimit_linux lux;
  if (pid && pid != m->system->pid) return eperm();
  if ((rc = getrlimit(XlatResource(resource), &old)) != -1) {
    if (new_rlimit_addr) {
      rc = SysSetrlimit(m, XlatResource(resource), new_rlimit_addr);
    }
    if (rc != -1 && old_rlimit_addr) {
      XlatRlimitToLinux(&lux, &old);
      CopyToUserWrite(m, old_rlimit_addr, &lux, sizeof(lux));
    }
  }
  return rc;
}

static i64 SysGetcwd(struct Machine *m, i64 bufaddr, size_t size) {
  size_t n;
  char *buf;
  i64 res;
  if (!(buf = (char *)malloc(size))) return -1;
  if ((getcwd)(buf, size)) {
    n = strlen(buf) + 1;
    CopyToUserWrite(m, bufaddr, buf, n);
    res = bufaddr;
  } else {
    res = -1;
  }
  free(buf);
  return res;
}

static ssize_t SysGetrandom(struct Machine *m, i64 a, size_t n, int f) {
  char *p;
  ssize_t rc;
  if (!(p = (char *)malloc(n))) return -1;
  if ((rc = GetRandom(p, n)) != -1) {
    CopyToUserWrite(m, a, p, rc);
  }
  free(p);
  return rc;
}

static int SysSigaction(struct Machine *m, int sig, i64 act, i64 old,
                        u64 sigsetsize) {
  if ((sig = XlatSignal(sig) - 1) != -1 &&
      (1 <= sig && sig <= ARRAYLEN(m->system->hands)) && sigsetsize == 8) {
    if (old) {
      CopyToUserWrite(m, old, &m->system->hands[sig],
                      sizeof(m->system->hands[0]));
    }
    if (act) {
      CopyFromUserRead(m, &m->system->hands[sig], act,
                       sizeof(m->system->hands[0]));
    }
    return 0;
  } else {
    return einval();
  }
}

static int SysGetitimer(struct Machine *m, int which, i64 curvaladdr) {
  int rc;
  struct itimerval it;
  struct itimerval_linux git;
  if ((rc = getitimer(which, &it)) != -1) {
    XlatItimervalToLinux(&git, &it);
    CopyToUserWrite(m, curvaladdr, &git, sizeof(git));
  }
  return rc;
}

static int SysSetitimer(struct Machine *m, int which, i64 neuaddr,
                        i64 oldaddr) {
  int rc;
  struct itimerval neu, old;
  struct itimerval_linux git;
  CopyFromUserRead(m, &git, neuaddr, sizeof(git));
  XlatLinuxToItimerval(&neu, &git);
  if ((rc = setitimer(which, &neu, &old)) != -1) {
    if (oldaddr) {
      XlatItimervalToLinux(&git, &old);
      CopyToUserWrite(m, oldaddr, &git, sizeof(git));
    }
  }
  return rc;
}

static int SysNanosleep(struct Machine *m, i64 req, i64 rem) {
  int rc;
  struct timespec hreq, hrem;
  struct timespec_linux gtimespec;
  if (req) {
    CopyFromUserRead(m, &gtimespec, req, sizeof(gtimespec));
    hreq.tv_sec = Read64(gtimespec.tv_sec);
    hreq.tv_nsec = Read64(gtimespec.tv_nsec);
  }
  rc = nanosleep(req ? &hreq : 0, rem ? &hrem : 0);
  if (rc == -1 && errno == EINTR && rem) {
    Write64(gtimespec.tv_sec, hrem.tv_sec);
    Write64(gtimespec.tv_nsec, hrem.tv_nsec);
    CopyToUserWrite(m, rem, &gtimespec, sizeof(gtimespec));
  }
  return rc;
}

static int SysClockNanosleep(struct Machine *m, int clock, int flags,
                             i64 reqaddr, i64 remaddr) {
  int rc;
  struct timespec req, rem;
  struct timespec_linux gtimespec;
  if ((clock = XlatClock(clock)) == -1) return -1;
  if (flags & ~TIMER_ABSTIME_LINUX) return einval();
  CopyFromUserRead(m, &gtimespec, reqaddr, sizeof(gtimespec));
  req.tv_sec = Read64(gtimespec.tv_sec);
  req.tv_nsec = Read64(gtimespec.tv_nsec);
#if defined(TIMER_ABSTIME) && !defined(__OpenBSD__)
  flags = flags & TIMER_ABSTIME_LINUX ? TIMER_ABSTIME : 0;
  if ((rc = clock_nanosleep(clock, flags, &req, &rem))) {
    errno = rc;
    rc = -1;
  }
#else
  struct timespec now;
  if (!flags) {
    if (clock == CLOCK_REALTIME) {
      rc = nanosleep(&req, &rem);
    } else {
      rc = einval();
    }
  } else if (!(rc = clock_gettime(clock, &now))) {
    if (CompareTime(now, req) < 0) {
      req = SubtractTime(req, now);
      rc = nanosleep(&req, &rem);
    } else {
      rc = 0;
    }
  }
#endif
  if (!flags && remaddr && rc == -1 && errno == EINTR) {
    Write64(gtimespec.tv_sec, rem.tv_sec);
    Write64(gtimespec.tv_nsec, rem.tv_nsec);
    CopyToUserWrite(m, remaddr, &gtimespec, sizeof(gtimespec));
  }
  return rc;
}

static int SysSigsuspend(struct Machine *m, i64 maskaddr) {
  u8 gmask[8];
  sigset_t mask;
  CopyFromUserRead(m, &gmask, maskaddr, 8);
  XlatLinuxToSigset(&mask, gmask);
  return sigsuspend(&mask);
}

static int SysSigaltstack(struct Machine *m, i64 newaddr, i64 oldaddr) {
  return 0;
}

static int SysClockGettime(struct Machine *m, int clock, i64 ts) {
  int rc;
  struct timespec htimespec;
  struct timespec_linux gtimespec;
  if ((rc = clock_gettime(XlatClock(clock), &htimespec)) != -1) {
    if (ts) {
      Write64(gtimespec.tv_sec, htimespec.tv_sec);
      Write64(gtimespec.tv_nsec, htimespec.tv_nsec);
      CopyToUserWrite(m, ts, &gtimespec, sizeof(gtimespec));
    }
  }
  return rc;
}

static int SysClockGetres(struct Machine *m, int clock, i64 ts) {
  int rc;
  struct timespec htimespec;
  struct timespec_linux gtimespec;
  if ((rc = clock_getres(XlatClock(clock), &htimespec)) != -1) {
    if (ts) {
      Write64(gtimespec.tv_sec, htimespec.tv_sec);
      Write64(gtimespec.tv_nsec, htimespec.tv_nsec);
      CopyToUserWrite(m, ts, &gtimespec, sizeof(gtimespec));
    }
  }
  return rc;
}

static int SysGettimeofday(struct Machine *m, i64 tv, i64 tz) {
  int rc;
  struct timeval htimeval;
  struct timezone htimezone;
  struct timeval_linux gtimeval;
  struct timezone_linux gtimezone;
  if ((rc = gettimeofday(&htimeval, tz ? &htimezone : 0)) != -1) {
    Write64(gtimeval.tv_sec, htimeval.tv_sec);
    Write64(gtimeval.tv_usec, htimeval.tv_usec);
    CopyToUserWrite(m, tv, &gtimeval, sizeof(gtimeval));
    if (tz) {
      Write32(gtimezone.tz_minuteswest, htimezone.tz_minuteswest);
      Write32(gtimezone.tz_dsttime, htimezone.tz_dsttime);
      CopyToUserWrite(m, tz, &gtimezone, sizeof(gtimezone));
    }
  }
  return rc;
}

static int SysUtimes(struct Machine *m, i64 pathaddr, i64 tvsaddr) {
  const char *path;
  struct timeval tvs[2];
  struct timeval_linux gtvs[2];
  path = LoadStr(m, pathaddr);
  if (tvsaddr) {
    CopyFromUserRead(m, gtvs, tvsaddr, sizeof(gtvs));
    tvs[0].tv_sec = Read64(gtvs[0].tv_sec);
    tvs[0].tv_usec = Read64(gtvs[0].tv_usec);
    tvs[1].tv_sec = Read64(gtvs[1].tv_sec);
    tvs[1].tv_usec = Read64(gtvs[1].tv_usec);
    return utimes(path, tvs);
  } else {
    return utimes(path, 0);
  }
}

static int SysPoll(struct Machine *m, i64 fdsaddr, u64 nfds, i32 timeout_ms) {
  long i;
  u64 gfdssize;
  struct Fd *fd;
  int fildes, rc, ev;
  struct pollfd hfds[1];
  struct timeval ts1, ts2;
  struct pollfd_linux *gfds;
  long wait, elapsed, timeout;
  timeout = timeout_ms * 1000L;
  if (!mulo(nfds, sizeof(struct pollfd_linux), &gfdssize) &&
      gfdssize <= 0x7ffff000) {
    if ((gfds = (struct pollfd_linux *)malloc(gfdssize))) {
      rc = 0;
      CopyFromUserRead(m, gfds, fdsaddr, gfdssize);
      unassert(!gettimeofday(&ts1, 0));
      for (;;) {
        for (i = 0; i < nfds; ++i) {
          fildes = Read32(gfds[i].fd);
          if ((fd = GetFd(&m->system->fds, fildes))) {
            hfds[0].fd =
                atomic_load_explicit(&fd->systemfd, memory_order_relaxed);
            ev = Read16(gfds[i].events);
            hfds[0].events = (((ev & POLLIN_LINUX) ? POLLIN : 0) |
                              ((ev & POLLOUT_LINUX) ? POLLOUT : 0) |
                              ((ev & POLLPRI_LINUX) ? POLLPRI : 0));
            switch (IB(fd->cb->poll)(hfds, 1, 0)) {
              case 0:
                Write16(gfds[i].revents, 0);
                break;
              case 1:
                ++rc;
                ev = 0;
                if (hfds[0].revents & POLLIN) ev |= POLLIN_LINUX;
                if (hfds[0].revents & POLLPRI) ev |= POLLPRI_LINUX;
                if (hfds[0].revents & POLLOUT) ev |= POLLOUT_LINUX;
                if (hfds[0].revents & POLLERR) ev |= POLLERR_LINUX;
                if (hfds[0].revents & POLLHUP) ev |= POLLHUP_LINUX;
                if (hfds[0].revents & POLLNVAL) ev |= POLLERR_LINUX;
                if (!ev) ev |= POLLERR_LINUX;
                Write16(gfds[i].revents, ev);
                break;
              case -1:
                ++rc;
                Write16(gfds[i].revents, POLLERR_LINUX);
                break;
              default:
                break;
            }
          } else {
            Write16(gfds[i].revents, POLLNVAL_LINUX);
          }
        }
        if (rc || !timeout) break;
        wait = POLLING_INTERVAL_MS * 1000;
        if (timeout < 0) {
          if (usleep(wait)) {
            rc = eintr();
            goto Finished;
          }
        } else {
          unassert(!gettimeofday(&ts2, 0));
          elapsed = timeval_tomicros(timeval_sub(ts2, ts1));
          if (elapsed >= timeout) {
            break;
          }
          if (timeout - elapsed < wait) {
            wait = timeout - elapsed;
          }
          if (usleep(wait)) {
            rc = eintr();
            goto Finished;
          }
        }
      }
      CopyToUserWrite(m, fdsaddr, gfds, nfds * sizeof(*gfds));
    } else {
      rc = enomem();
    }
  Finished:
    free(gfds);
    return rc;
  } else {
    return einval();
  }
}

static int SysSigprocmask(struct Machine *m, int how, i64 setaddr,
                          i64 oldsetaddr, u64 sigsetsize) {
  u8 set[8], mask[8];
  if ((how = XlatSig(how)) != -1 && sigsetsize == sizeof(set)) {
    if (oldsetaddr) {
      Write64(mask, m->sigmask);
      CopyToUserWrite(m, oldsetaddr, mask, sizeof(mask));
    }
    if (setaddr) {
      CopyFromUserRead(m, set, setaddr, sizeof(set));
      if (how == SIG_BLOCK) {
        m->sigmask = m->sigmask | Read64(set);
      } else if (how == SIG_UNBLOCK) {
        m->sigmask = m->sigmask & ~Read64(set);
      } else {
        m->sigmask = Read64(set);
      }
    }
    return 0;
  } else {
    return einval();
  }
}

static int SysKill(struct Machine *m, int pid, int sig) {
  if (pid == m->system->pid) {
    // TODO(jart): Enqueue signal instead.
    ThrowProtectionFault(m);
  } else {
    return kill(pid, sig);
  }
}

static int SysTkill(struct Machine *m, int tid, int sig) {
  struct Dll *e;
  bool gotsome = false;
  if (!(1 <= sig && sig <= 64)) return einval();
  LOCK(&m->system->machines_lock);
  for (e = dll_first(m->system->machines); e;
       e = dll_next(m->system->machines, e)) {
    if (MACHINE_CONTAINER(e)->tid == tid) {
      MACHINE_CONTAINER(e)->signals |= 1ull << (sig - 1);
      gotsome = true;
      break;
    }
  }
  UNLOCK(&m->system->machines_lock);
  if (!gotsome) return esrch();
  return 0;
}

static int SysPause(struct Machine *m) {
  return pause();
}

static int SysSetsid(struct Machine *m) {
  return setsid();
}

static int SysGetpid(struct Machine *m) {
  return m->system->pid;
}

static int SysGettid(struct Machine *m) {
  return m->tid;
}

static int SysGetppid(struct Machine *m) {
  return getppid();
}

static int SysGetuid(struct Machine *m) {
  return getuid();
}

static int SysGetgid(struct Machine *m) {
  return getgid();
}

static int SysGeteuid(struct Machine *m) {
  return geteuid();
}

static int SysGetegid(struct Machine *m) {
  return getegid();
}

static int SysSchedYield(struct Machine *m) {
  return sched_yield();
}

static int SysUmask(struct Machine *m, int mask) {
  return umask(mask);
}

static int SysSetuid(struct Machine *m, int uid) {
  return setuid(uid);
}

static int SysSetgid(struct Machine *m, int gid) {
  return setgid(gid);
}

static int SysGetpgid(struct Machine *m, int pid) {
  return getpgid(pid);
}

static int SysAlarm(struct Machine *m, unsigned seconds) {
  return alarm(seconds);
}

static int SysSetpgid(struct Machine *m, int pid, int gid) {
  return setpgid(pid, gid);
}

static int SysCreat(struct Machine *m, i64 path, int mode) {
  return SysOpenat(m, AT_FDCWD_LINUX, path,
                   O_WRONLY_LINUX | O_CREAT_LINUX | O_TRUNC_LINUX, mode);
}

static int SysAccess(struct Machine *m, i64 path, int mode) {
  return SysFaccessat(m, AT_FDCWD_LINUX, path, mode, 0);
}

static int SysStat(struct Machine *m, i64 path, i64 st) {
  return SysFstatat(m, AT_FDCWD_LINUX, path, st, 0);
}

static int SysLstat(struct Machine *m, i64 path, i64 st) {
  return SysFstatat(m, AT_FDCWD_LINUX, path, st, 0x0400);
}

static int SysOpen(struct Machine *m, i64 path, int flags, int mode) {
  return SysOpenat(m, AT_FDCWD_LINUX, path, flags, mode);
}

static int SysAccept(struct Machine *m, int fd, i64 sa, i64 sas) {
  return SysAccept4(m, fd, sa, sas, 0);
}

void OpSyscall(P) {
  u64 ax, di, si, dx, r0, r8, r9;
  ax = Get64(m->ax);
  di = Get64(m->di);
  si = Get64(m->si);
  dx = Get64(m->dx);
  r0 = Get64(m->r10);
  r8 = Get64(m->r8);
  r9 = Get64(m->r9);
  switch (ax & 0x1ff) {
    SYSCALL(0x000, SysRead, (m, di, si, dx));
    SYSCALL(0x001, SysWrite, (m, di, si, dx));
    SYSCALL(0x002, SysOpen, (m, di, si, dx));
    SYSCALL(0x003, SysClose, (m->system, di));
    SYSCALL(0x004, SysStat, (m, di, si));
    SYSCALL(0x005, SysFstat, (m, di, si));
    SYSCALL(0x006, SysLstat, (m, di, si));
    SYSCALL(0x007, SysPoll, (m, di, si, dx));
    SYSCALL(0x008, SysLseek, (m, di, si, dx));
    SYSCALL(0x009, SysMmap, (m, di, si, dx, r0, r8, r9));
    SYSCALL(0x011, SysPread, (m, di, si, dx, r0));
    SYSCALL(0x012, SysPwrite, (m, di, si, dx, r0));
    SYSCALL(0x01A, SysMsync, (m, di, si, dx));
    SYSCALL(0x00A, SysMprotect, (m, di, si, dx));
    SYSCALL(0x00B, SysMunmap, (m, di, si));
    SYSCALL(0x00C, SysBrk, (m, di));
    SYSCALL(0x00D, SysSigaction, (m, di, si, dx, r0));
    SYSCALL(0x00E, SysSigprocmask, (m, di, si, dx, r0));
    SYSCALL(0x010, SysIoctl, (m, di, si, dx));
    SYSCALL(0x013, SysReadv, (m, di, si, dx));
    SYSCALL(0x014, SysWritev, (m, di, si, dx));
    SYSCALL(0x015, SysAccess, (m, di, si));
    SYSCALL(0x016, SysPipe, (m, di, 0));
    SYSCALL(0x125, SysPipe, (m, di, si));
    SYSCALL(0x018, SysSchedYield, (m));
    SYSCALL(0x01C, SysMadvise, (m, di, si, dx));
    SYSCALL(0x020, SysDup1, (m, di));
    SYSCALL(0x021, SysDup2, (m, di, si));
    SYSCALL(0x124, SysDup3, (m, di, si, dx));
    SYSCALL(0x022, SysPause, (m));
    SYSCALL(0x023, SysNanosleep, (m, di, si));
    SYSCALL(0x024, SysGetitimer, (m, di, si));
    SYSCALL(0x025, SysAlarm, (m, di));
    SYSCALL(0x026, SysSetitimer, (m, di, si, dx));
    SYSCALL(0x027, SysGetpid, (m));
    SYSCALL(0x0BA, SysGettid, (m));
    SYSCALL(0x029, SysSocket, (m, di, si, dx));
    SYSCALL(0x02A, SysConnect, (m, di, si, dx));
    SYSCALL(0x02B, SysAccept, (m, di, di, dx));
    SYSCALL(0x030, SysShutdown, (m, di, si));
    SYSCALL(0x031, SysBind, (m, di, si, dx));
    SYSCALL(0x032, SysListen, (m, di, si));
    SYSCALL(0x033, SysGetsockname, (m, di, si, dx));
    SYSCALL(0x034, SysGetpeername, (m, di, si, dx));
    SYSCALL(0x036, SysSetsockopt, (m, di, si, dx, r0, r8));
    SYSCALL(0x038, SysClone, (m, di, si, dx, r0, r8, r9));
    SYSCALL(0x039, SysFork, (m));
    SYSCALL(0x03A, SysVfork, (m));
    SYSCALL(0x03B, SysExecve, (m, di, si, dx));
    SYSCALL(0x03D, SysWait4, (m, di, si, dx, r0));
    SYSCALL(0x03E, SysKill, (m, di, si));
    SYSCALL(0x03F, SysUname, (m, di));
    SYSCALL(0x048, SysFcntl, (m, di, si, dx));
    SYSCALL(0x049, SysFlock, (m, di, si));
    SYSCALL(0x04A, SysFsync, (m, di));
    SYSCALL(0x04B, SysFdatasync, (m, di));
    SYSCALL(0x04C, SysTruncate, (m, di, si));
    SYSCALL(0x04D, SysFtruncate, (m, di, si));
    SYSCALL(0x04F, SysGetcwd, (m, di, si));
    SYSCALL(0x050, SysChdir, (m, di));
    SYSCALL(0x052, SysRename, (m, di, si));
    SYSCALL(0x053, SysMkdir, (m, di, si));
    SYSCALL(0x054, SysRmdir, (m, di));
    SYSCALL(0x055, SysCreat, (m, di, si));
    SYSCALL(0x056, SysLink, (m, di, si));
    SYSCALL(0x057, SysUnlink, (m, di));
    SYSCALL(0x058, SysSymlink, (m, di, si));
    SYSCALL(0x059, SysReadlink, (m, di, si, dx));
    SYSCALL(0x05A, SysChmod, (m, di, si));
    SYSCALL(0x05B, SysFchmod, (m, di, si));
    SYSCALL(0x05F, SysUmask, (m, di));
    SYSCALL(0x060, SysGettimeofday, (m, di, si));
    SYSCALL(0x061, SysGetrlimit, (m, di, si));
    SYSCALL(0x062, SysGetrusage, (m, di, si));
    SYSCALL(0x070, SysSetsid, (m));
    SYSCALL(0x079, SysGetpgid, (m, di));
    SYSCALL(0x06D, SysSetpgid, (m, di, si));
    SYSCALL(0x066, SysGetuid, (m));
    SYSCALL(0x068, SysGetgid, (m));
    SYSCALL(0x069, SysSetuid, (m, di));
    SYSCALL(0x06A, SysSetgid, (m, di));
    SYSCALL(0x06B, SysGeteuid, (m));
    SYSCALL(0x06C, SysGetegid, (m));
    SYSCALL(0x06E, SysGetppid, (m));
    SYSCALL(0x082, SysSigsuspend, (m, di));
    SYSCALL(0x083, SysSigaltstack, (m, di, si));
    SYSCALL(0x085, SysMknod, (m, di, si, dx));
    SYSCALL(0x09D, SysPrctl, (m, di, si, dx, r0, r8));
    SYSCALL(0x09E, SysArchPrctl, (m, di, si));
    SYSCALL(0x0A0, SysSetrlimit, (m, di, si));
    SYSCALL(0x0C8, SysTkill, (m, di, si));
    SYSCALL(0x0CA, SysFutex, (m, di, si, dx, r0, r8, r9));
    SYSCALL(0x0D9, SysGetdents, (m, di, si, dx));
    SYSCALL(0x0DA, SysSetTidAddress, (m, di));
    SYSCALL(0x0E4, SysClockGettime, (m, di, si));
    SYSCALL(0x0E5, SysClockGetres, (m, di, si));
    SYSCALL(0x0E6, SysClockNanosleep, (m, di, si, dx, r0));
    SYSCALL(0x0EB, SysUtimes, (m, di, si));
    SYSCALL(0x101, SysOpenat, (m, di, si, dx, r0));
    SYSCALL(0x102, SysMkdirat, (m, di, si, dx));
    SYSCALL(0x106, SysFstatat, (m, di, si, dx, r0));
    SYSCALL(0x107, SysUnlinkat, (m, di, si, dx));
    SYSCALL(0x108, SysRenameat, (m, di, si, dx, r0));
    SYSCALL(0x10B, SysReadlinkat, (m, di, si, dx, r0));
    SYSCALL(0x10D, SysFaccessat, (m, di, si, dx, r0));
    SYSCALL(0x120, SysAccept4, (m, di, si, dx, r0));
    SYSCALL(0x12E, SysPrlimit, (m, di, si, dx, r0));
    SYSCALL(0x13E, SysGetrandom, (m, di, si, dx));
    SYSCALL(0x1B4, SysCloseRange, (m->system, di, si, dx));
    case 0x3C:
      SysExit(m, di);
    case 0xE7:
      SysExitGroup(m, di);
    case 0x00F:
      SigRestore(m);
      return;
    default:
      SYS_LOGF("missing syscall 0x%03" PRIx64, ax);
      ax = enosys();
      break;
  }
  Put64(m->ax, ax != -1 ? ax : -(XlatErrno(errno) & 0xfff));
  CollectGarbage(m);
}
