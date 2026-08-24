/*
 * iOS arm64 PE inject (jailbreak).
 *
 * Usage: ./injector <target> <payload.dylib>
 *
 * No dlopen: parse Mach-O locally → mach_vm map segments into target →
 * chained rebase + bind _dlsym → pthread_create_from_mach_thread(_last).
 *
 * Payload: export _last; only undefined import should be _dlsym.
 * arm64e: not supported yet (see opainject pac.h + set_pc_fptr when needed).
 */

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <mach-o/dyld.h>
#include <mach-o/dyld_images.h>
#include <mach-o/fat.h>
#include <mach-o/fixup-chains.h>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>
#include <mach/mach.h>
#include <mach/thread_status.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <unistd.h>

typedef uint64_t mach_vm_address_t;
typedef uint64_t mach_vm_size_t;

kern_return_t mach_vm_allocate(vm_map_t target, mach_vm_address_t *address,
                               mach_vm_size_t size, int flags);
kern_return_t mach_vm_deallocate(vm_map_t target, mach_vm_address_t address,
                                 mach_vm_size_t size);
kern_return_t mach_vm_protect(vm_map_t target, mach_vm_address_t address,
                              mach_vm_size_t size, boolean_t set_maximum,
                              vm_prot_t new_protection);
kern_return_t mach_vm_write(vm_map_t target, mach_vm_address_t address,
                            vm_offset_t data, mach_msg_type_number_t dataCnt);
kern_return_t mach_vm_read(vm_map_t target, mach_vm_address_t address,
                           mach_vm_size_t size, vm_offset_t *data,
                           mach_msg_type_number_t *dataCnt);

extern char **environ;

#define PAGE_SZ 0x4000ull
#define STACK_SZ (256 * 1024ull)

static void die(const char *msg) {
  fprintf(stderr, "[injector] %s\n", msg);
  exit(1);
}

static void die_kr(const char *what, kern_return_t kr) {
  fprintf(stderr, "[injector] %s: %s (0x%x)\n", what, mach_error_string(kr),
          kr);
  exit(1);
}

static uint64_t align_up(uint64_t n, uint64_t a) {
  return (n + a - 1) & ~(a - 1);
}

/* ---- process ---- */

static int is_all_digits(const char *s) {
  if (!s || !*s)
    return 0;
  for (; *s; s++)
    if (*s < '0' || *s > '9')
      return 0;
  return 1;
}

static pid_t pid_for_name(const char *name) {
  int mib[4] = {CTL_KERN, KERN_PROC, KERN_PROC_ALL, 0};
  size_t size = 0;
  if (sysctl(mib, 4, NULL, &size, NULL, 0) < 0)
    die("sysctl size failed");
  struct kinfo_proc *procs = calloc(1, size);
  if (!procs)
    die("oom");
  if (sysctl(mib, 4, procs, &size, NULL, 0) < 0) {
    free(procs);
    die("sysctl procs failed");
  }
  size_t n = size / sizeof(struct kinfo_proc);
  pid_t found = -1;
  size_t matches = 0;
  for (size_t i = 0; i < n; i++) {
    if (strncmp(procs[i].kp_proc.p_comm, name, MAXCOMLEN) == 0) {
      found = procs[i].kp_proc.p_pid;
      matches++;
      printf("[injector] match pid=%d name=%s\n", found,
             procs[i].kp_proc.p_comm);
    }
  }
  free(procs);
  if (matches == 0) {
    fprintf(stderr, "[injector] no process named '%s'\n", name);
    exit(1);
  }
  if (matches > 1)
    printf("[injector] warning: %zu matches, using last pid=%d\n", matches,
           found);
  return found;
}

static pid_t resolve_target(const char *target) {
  if (is_all_digits(target))
    return (pid_t)atoi(target);
  return pid_for_name(target);
}

/* ---- remote helpers ---- */

static kern_return_t remote_read(task_t task, mach_vm_address_t addr, void *buf,
                                 mach_vm_size_t size) {
  vm_offset_t out = 0;
  mach_msg_type_number_t outCnt = 0;
  kern_return_t kr = mach_vm_read(task, addr, size, &out, &outCnt);
  if (kr != KERN_SUCCESS)
    return kr;
  memcpy(buf, (void *)out, size);
  vm_deallocate(mach_task_self(), out, outCnt);
  return KERN_SUCCESS;
}

static kern_return_t remote_write(task_t task, mach_vm_address_t addr,
                                  const void *buf, mach_vm_size_t size) {
  return mach_vm_write(task, addr, (vm_offset_t)buf,
                       (mach_msg_type_number_t)size);
}

static mach_vm_address_t remote_alloc_rw(task_t task, mach_vm_size_t size) {
  mach_vm_address_t addr = 0;
  size = align_up(size, PAGE_SZ);
  kern_return_t kr = mach_vm_allocate(task, &addr, size, VM_FLAGS_ANYWHERE);
  if (kr != KERN_SUCCESS)
    die_kr("mach_vm_allocate", kr);
  kr = mach_vm_protect(task, addr, size, FALSE, VM_PROT_READ | VM_PROT_WRITE);
  if (kr != KERN_SUCCESS)
    die_kr("mach_vm_protect(RW)", kr);
  return addr;
}

static uint64_t remote_image_slide(task_t task, uint64_t header) {
  struct mach_header_64 mh;
  if (remote_read(task, header, &mh, sizeof(mh)) != KERN_SUCCESS)
    return 0;
  uint64_t cursor = header + sizeof(mh);
  for (uint32_t i = 0; i < mh.ncmds; i++) {
    struct load_command lc;
    if (remote_read(task, cursor, &lc, sizeof(lc)) != KERN_SUCCESS)
      return 0;
    if (lc.cmd == LC_SEGMENT_64) {
      struct segment_command_64 seg;
      if (remote_read(task, cursor, &seg, sizeof(seg)) != KERN_SUCCESS)
        return 0;
      if (strncmp(seg.segname, "__TEXT", 16) == 0)
        return header - seg.vmaddr;
    }
    cursor += lc.cmdsize;
  }
  return 0;
}

static uint64_t remote_dlsym(task_t task, uint64_t header, const char *symbol) {
  struct mach_header_64 mh;
  if (remote_read(task, header, &mh, sizeof(mh)) != KERN_SUCCESS)
    return 0;
  uint64_t slide = remote_image_slide(task, header);
  uint64_t cursor = header + sizeof(mh);
  struct symtab_command symtab = {0};
  struct segment_command_64 linkedit = {0};
  int have_sym = 0, have_le = 0;
  for (uint32_t i = 0; i < mh.ncmds; i++) {
    struct load_command lc;
    if (remote_read(task, cursor, &lc, sizeof(lc)) != KERN_SUCCESS)
      return 0;
    if (lc.cmd == LC_SYMTAB) {
      remote_read(task, cursor, &symtab, sizeof(symtab));
      have_sym = 1;
    } else if (lc.cmd == LC_SEGMENT_64) {
      struct segment_command_64 seg;
      remote_read(task, cursor, &seg, sizeof(seg));
      if (strncmp(seg.segname, "__LINKEDIT", 16) == 0) {
        linkedit = seg;
        have_le = 1;
      }
    }
    cursor += lc.cmdsize;
  }
  if (!have_sym || !have_le)
    return 0;
  uint64_t linkedit_base = linkedit.vmaddr + slide - linkedit.fileoff;
  uint64_t strtab = linkedit_base + symtab.stroff;
  uint64_t symoff = linkedit_base + symtab.symoff;
  for (uint32_t i = 0; i < symtab.nsyms; i++) {
    struct nlist_64 nl;
    if (remote_read(task, symoff + i * sizeof(nl), &nl, sizeof(nl)) !=
        KERN_SUCCESS)
      return 0;
    if (!nl.n_un.n_strx)
      continue;
    char name[256];
    memset(name, 0, sizeof(name));
    if (remote_read(task, strtab + nl.n_un.n_strx, name, sizeof(name) - 1) !=
        KERN_SUCCESS)
      continue;
    if (strcmp(name, symbol) == 0)
      return nl.n_value + slide;
  }
  return 0;
}

static uint64_t find_remote_image(task_t task, uint64_t all_info_addr,
                                  const char *needle) {
  struct dyld_all_image_infos infos;
  if (remote_read(task, all_info_addr, &infos, sizeof(infos)) != KERN_SUCCESS)
    die("read dyld_all_image_infos failed");
  size_t arr_sz = sizeof(struct dyld_image_info) * infos.infoArrayCount;
  struct dyld_image_info *arr = calloc(1, arr_sz);
  if (!arr)
    die("oom");
  if (remote_read(task, (mach_vm_address_t)infos.infoArray, arr, arr_sz) !=
      KERN_SUCCESS) {
    free(arr);
    die("read infoArray failed");
  }
  uint64_t hit = 0;
  for (uint32_t i = 0; i < infos.infoArrayCount; i++) {
    char path[PATH_MAX];
    memset(path, 0, sizeof(path));
    if (remote_read(task, (mach_vm_address_t)arr[i].imageFilePath, path,
                    sizeof(path) - 1) != KERN_SUCCESS)
      continue;
    if (strstr(path, needle)) {
      hit = (uint64_t)arr[i].imageLoadAddress;
      break;
    }
  }
  free(arr);
  return hit;
}

/* ---- local Mach-O: fat slice + map image ---- */

typedef struct {
  uint8_t *file; /* whole file or thin slice base */
  size_t file_size;
  uint8_t *mh; /* mach_header_64 inside file */
  size_t slice_size;
  int owns_file;
} macho_buf_t;

static void macho_load(const char *path, macho_buf_t *out) {
  memset(out, 0, sizeof(*out));
  int fd = open(path, O_RDONLY);
  if (fd < 0) {
    fprintf(stderr, "[injector] open %s: %s\n", path, strerror(errno));
    exit(1);
  }
  struct stat st;
  if (fstat(fd, &st) < 0)
    die("fstat failed");
  size_t sz = (size_t)st.st_size;
  uint8_t *map = mmap(NULL, sz, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
  close(fd);
  if (map == MAP_FAILED)
    die("mmap payload failed");
  out->file = map;
  out->file_size = sz;
  out->owns_file = 1;

  uint32_t magic = *(uint32_t *)map;
  if (magic == MH_MAGIC_64) {
    out->mh = map;
    out->slice_size = sz;
    return;
  }
  if (magic != FAT_MAGIC && magic != FAT_CIGAM)
    die("not mach-o / fat");

  struct fat_header fh = *(struct fat_header *)map;
  uint32_t nfat = ntohl(fh.nfat_arch);
  struct fat_arch *fa = (struct fat_arch *)(map + sizeof(fh));
  int best = -1;
  for (uint32_t i = 0; i < nfat; i++) {
    cpu_type_t t = (cpu_type_t)ntohl((uint32_t)fa[i].cputype);
    cpu_subtype_t s =
        (cpu_subtype_t)ntohl((uint32_t)fa[i].cpusubtype) & ~CPU_SUBTYPE_MASK;
    if (t != CPU_TYPE_ARM64)
      continue;
    if (s == CPU_SUBTYPE_ARM64E)
      continue; /* arm64-only demo */
    if (best < 0)
      best = (int)i;
  }
  if (best < 0)
    die("no arm64 slice in fat payload");
  uint32_t off = ntohl(fa[best].offset);
  uint32_t fsz = ntohl(fa[best].size);
  out->mh = map + off;
  out->slice_size = fsz;
  printf("[injector] fat slice #%d off=0x%x size=0x%x\n", best, off, fsz);
}

static void macho_unload(macho_buf_t *m) {
  if (m->owns_file && m->file)
    munmap(m->file, m->file_size);
  memset(m, 0, sizeof(*m));
}

typedef struct {
  struct segment_command_64 seg;
  uint8_t *file_data; /* pointer into slice */
} mapped_seg_t;

#define MAX_SEGS 32

typedef struct {
  struct mach_header_64 *hdr;
  mapped_seg_t segs[MAX_SEGS];
  uint32_t nsegs;
  uint64_t vmin, vmax;
  uint64_t last_vmaddr; /* preferred vmaddr of _last */
  struct linkedit_data_command chained;
  int have_chained;
} image_info_t;

static int parse_image(macho_buf_t *m, image_info_t *img) {
  memset(img, 0, sizeof(*img));
  img->hdr = (struct mach_header_64 *)m->mh;
  if (img->hdr->magic != MH_MAGIC_64)
    die("slice not MH_MAGIC_64");

  img->vmin = UINT64_MAX;
  img->vmax = 0;
  uint8_t *lc = m->mh + sizeof(struct mach_header_64);
  struct symtab_command symtab = {0};
  int have_sym = 0;

  for (uint32_t i = 0; i < img->hdr->ncmds; i++) {
    struct load_command *cmd = (struct load_command *)lc;
    if (cmd->cmd == LC_SEGMENT_64) {
      struct segment_command_64 *seg = (struct segment_command_64 *)lc;
      if (img->nsegs >= MAX_SEGS)
        die("too many segments");
      /* Keep LC order (incl. __PAGEZERO) so chained seg_index matches. */
      img->segs[img->nsegs].seg = *seg;
      img->segs[img->nsegs].file_data =
          seg->filesize ? (m->mh + seg->fileoff) : NULL;
      img->nsegs++;
      if (strncmp(seg->segname, "__PAGEZERO", 16) != 0) {
        if (seg->vmaddr < img->vmin)
          img->vmin = seg->vmaddr;
        if (seg->vmaddr + seg->vmsize > img->vmax)
          img->vmax = seg->vmaddr + seg->vmsize;
      }
    } else if (cmd->cmd == LC_SYMTAB) {
      memcpy(&symtab, lc, sizeof(symtab));
      have_sym = 1;
    } else if (cmd->cmd == LC_DYLD_CHAINED_FIXUPS) {
      memcpy(&img->chained, lc, sizeof(img->chained));
      img->have_chained = 1;
    }
    lc += cmd->cmdsize;
  }

  if (img->vmin == UINT64_MAX)
    die("no segments");

  if (!have_sym)
    die("no LC_SYMTAB");
  struct nlist_64 *syms = (struct nlist_64 *)(m->mh + symtab.symoff);
  char *str = (char *)(m->mh + symtab.stroff);
  int found = 0;
  for (uint32_t i = 0; i < symtab.nsyms; i++) {
    const char *name = str + syms[i].n_un.n_strx;
    if (strcmp(name, "_last") == 0) {
      img->last_vmaddr = syms[i].n_value;
      found = 1;
      break;
    }
  }
  if (!found)
    die("export _last not found (PE payload must export it)");

  printf("[injector] image va=[0x%llx,0x%llx) last@0x%llx chained=%d\n",
         (unsigned long long)img->vmin, (unsigned long long)img->vmax,
         (unsigned long long)img->last_vmaddr, img->have_chained);
  return 0;
}

/*
 * ========== Chained Fixups（arm64 · DYLD_CHAINED_PTR_64）==========
 *
 * dyld 把「需要改的指针」编成链表，存在 LC_DYLD_CHAINED_FIXUPS 指向的 blob 里。
 * 每个 8 字节槽位不是最终地址，而是编码：
 *   - bind=0 → rebase：指向本镜像内部某处
 *   - bind=1 → bind：指向外部符号（imports 表里的 ordinal）
 *   - next   → 距下一个槽位多少个 stride（链表）
 *
 * 正常加载：dyld 按 slide / 符号表改完，再把槽位写成普通指针。
 * 本 demo：injector 代替 dyld 做这件事（PE map，不走 dlopen）。
 *
 * 术语：
 *   rebase — 本镜像内指针：文件里是 preferred VA 或 runtimeOffset，
 *            映射到 remote_base 后要加上 slide。
 *   bind   — 外部符号：用 ordinal 查 imports → 名字（如 _dlsym），
 *            再填成目标进程里该符号的真实地址。
 *   slide  — remote_base - preferred_vmin（镜像实际加载基址相对链接基址的偏移）
 *
 * blob 布局（简化）：
 *   [dyld_chained_fixups_header]
 *     starts_offset  → 每 segment 的 page_start[]（链表入口）
 *     imports_offset → import 数组（ordinal → 符号名）
 *     symbols_offset → 符号名字串池
 */

/* ordinal → 符号名 + import 表 addend（无 ADDEND 格式则为 0） */
static const char *chained_import_lookup(uint8_t *fixups,
                                         struct dyld_chained_fixups_header *hdr,
                                         uint32_t ordinal,
                                         int64_t *out_addend) {
  if (out_addend)
    *out_addend = 0;
  if (ordinal >= hdr->imports_count)
    return NULL;
  uint8_t *imports = fixups + hdr->imports_offset;
  const char *symbols = (const char *)(fixups + hdr->symbols_offset);
  uint32_t name_off = 0;
  switch (hdr->imports_format) {
  case DYLD_CHAINED_IMPORT: {
    struct dyld_chained_import *imp = (struct dyld_chained_import *)imports;
    name_off = imp[ordinal].name_offset;
    break;
  }
  case DYLD_CHAINED_IMPORT_ADDEND: {
    struct dyld_chained_import_addend *imp =
        (struct dyld_chained_import_addend *)imports;
    name_off = imp[ordinal].name_offset;
    if (out_addend)
      *out_addend = (int64_t)imp[ordinal].addend;
    break;
  }
  case DYLD_CHAINED_IMPORT_ADDEND64: {
    struct dyld_chained_import_addend64 *imp =
        (struct dyld_chained_import_addend64 *)imports;
    name_off = (uint32_t)imp[ordinal].name_offset;
    if (out_addend)
      *out_addend = (int64_t)imp[ordinal].addend;
    break;
  }
  default:
    return NULL;
  }
  return symbols + name_off;
}

/*
 * bind：ordinal → 名字 → 目标地址。
 * demo 只支持 _dlsym（payload 其它符号用 dlsym(RTLD_DEFAULT) 自己解析）。
 * 返回值写入指针槽，运行时就是普通函数指针。
 */
static uint64_t resolve_bind_ordinal(uint8_t *fixups,
                                     struct dyld_chained_fixups_header *hdr,
                                     uint32_t ordinal, int64_t addend,
                                     uint64_t dlsym_addr) {
  int64_t import_addend = 0;
  const char *name =
      chained_import_lookup(fixups, hdr, ordinal, &import_addend);
  if (!name) {
    fprintf(stderr, "[injector] bad import ordinal %u\n", ordinal);
    die("bind resolve failed");
  }
  if (strcmp(name, "_dlsym") != 0 && strcmp(name, "dlsym") != 0) {
    fprintf(stderr, "[injector] unsupported bind '%s' (only _dlsym)\n", name);
    die("bind not _dlsym");
  }
  /* 指针编码里的 addend + import 表里的 addend */
  return dlsym_addr + (uint64_t)(addend + import_addend);
}

/*
 * 拼出「已 fixup」的连续镜像，准备 mach_vm_write 进目标。
 *
 * 输出 buf 布局（相对 preferred [vmin, vmax)）：
 *   buf[seg.vmaddr - vmin ...] = segment 文件内容（已改指针）
 *
 * 之后 remote 地址 = remote_base + (preferred_va - vmin)
 */
static uint8_t *build_relocated_image(task_t task, macho_buf_t *m,
                                      image_info_t *img, uint64_t remote_base,
                                      size_t *out_size) {
  size_t span = (size_t)(img->vmax - img->vmin);
  uint8_t *buf = calloc(1, span);
  if (!buf)
    die("oom image");

  /* ---- 1) 按 preferred layout 拷贝各 segment（尚未改指针）---- */
  for (uint32_t i = 0; i < img->nsegs; i++) {
    struct segment_command_64 *s = &img->segs[i].seg;
    if (strncmp(s->segname, "__PAGEZERO", 16) == 0)
      continue;
    size_t off = (size_t)(s->vmaddr - img->vmin);
    if (s->filesize && img->segs[i].file_data)
      memcpy(buf + off, img->segs[i].file_data, (size_t)s->filesize);
  }

  /*
   * slide：链接时假设装在 vmin，实际装在 remote_base。
   * 例：vmin=0, remote_base=0x1008bc000 → slide=0x1008bc000
   * rebase 时：运行时指针 = preferred指针 + slide
   *           或（OFFSET 格式）= remote_base + runtimeOffset
   */
  int64_t slide = (int64_t)remote_base - (int64_t)img->vmin;

  /*
   * ---- 2) bind 用的外部地址：目标进程里的 _dlsym ----
   * 不能用 injector 自己的 dlsym：地址空间不同。
   * payload 跑在 SpringBoard 里，必须填 SB 的 libdyld._dlsym。
   */
  uint64_t dlsym_addr = 0;
  {
    struct task_dyld_info dyld_info;
    mach_msg_type_number_t cnt = TASK_DYLD_INFO_COUNT;
    kern_return_t kr =
        task_info(task, TASK_DYLD_INFO, (task_info_t)&dyld_info, &cnt);
    if (kr != KERN_SUCCESS)
      die_kr("task_info(TASK_DYLD_INFO) for bind", kr);
    uint64_t libdyld = find_remote_image(task, dyld_info.all_image_info_addr,
                                         "/libdyld.dylib");
    if (!libdyld)
      die("libdyld not found in target (need for bind _dlsym)");
    dlsym_addr = remote_dlsym(task, libdyld, "_dlsym");
    if (!dlsym_addr)
      die("_dlsym not found in target libdyld");
    printf("[injector] bind _dlsym → 0x%llx (target libdyld)\n",
           (unsigned long long)dlsym_addr);
  }

  int n_rebase = 0, n_bind = 0;

  if (img->have_chained) {
    /* LC_DYLD_CHAINED_FIXUPS.dataoff → 整块 fixups blob */
    uint8_t *fixups = m->mh + img->chained.dataoff;
    struct dyld_chained_fixups_header *hdr =
        (struct dyld_chained_fixups_header *)fixups;
    if (hdr->fixups_version > 0)
      die("unsupported chained fixups version");

    /*
     * starts：每个 Mach-O segment 一项。
     * seg_info_offset[i]==0 → 该 segment 没有链式指针。
     * 注意：i 必须与 LC_SEGMENT_64 顺序一致（含 __PAGEZERO）。
     */
    struct dyld_chained_starts_in_image *starts =
        (struct dyld_chained_starts_in_image *)(fixups + hdr->starts_offset);

    for (uint32_t segIdx = 0; segIdx < starts->seg_count; segIdx++) {
      uint32_t soff = starts->seg_info_offset[segIdx];
      if (soff == 0)
        continue;
      if (segIdx >= img->nsegs)
        die("chained seg index OOB");
      struct dyld_chained_starts_in_segment *segStarts =
          (struct dyld_chained_starts_in_segment *)((uint8_t *)starts + soff);

      /*
       * 每个 page 一个入口偏移 page_start[pg]：
       *   NONE  → 本页没有 fixup
       *   其它  → 页内第一个链式指针相对页首的字节偏移
       * 同一页内多个指针用 next 串成链（不是数组扫全页）。
       */
      for (uint32_t pg = 0; pg < segStarts->page_count; pg++) {
        uint16_t start = segStarts->page_start[pg];
        if (start == DYLD_CHAINED_PTR_START_NONE)
          continue;
        if (start & DYLD_CHAINED_PTR_START_MULTI)
          die("multi-start chained page not supported in demo");

        /* 该页 preferred VA；链上偏移 next 从 page_start 起步 */
        uint64_t page_va =
            img->segs[segIdx].seg.vmaddr + (uint64_t)pg * segStarts->page_size;
        uint32_t next = start;
        for (;;) {
          /* preferred VA → buf 内偏移 */
          uint64_t ptr_va = page_va + next;
          size_t ptr_off = (size_t)(ptr_va - img->vmin);
          if (ptr_off + 8 > span)
            die("fixup out of range");

          uint64_t raw;
          memcpy(&raw, buf + ptr_off, 8);
          uint16_t format = segStarts->pointer_format;
          uint64_t newv = 0; /* 写回槽位的「最终运行时指针」 */
          int walk_next = 0; /* 链上下一环的 next 字段 */

          /*
           * ---- arm64 主路径：PTR_64 / PTR_64_OFFSET ----
           * 同一 64bit 按 bind 位解释成 rebase 或 bind 结构。
           *
           * DYLD_CHAINED_PTR_64:
           *   rebase.target = preferred vmaddr（再加 slide）
           * DYLD_CHAINED_PTR_64_OFFSET:
           *   rebase.target = 相对镜像基址的 runtimeOffset
           *                   （直接 remote_base + target）
           */
          if (format == DYLD_CHAINED_PTR_64 ||
              format == DYLD_CHAINED_PTR_64_OFFSET) {
            struct dyld_chained_ptr_64_rebase rb;
            memcpy(&rb, &raw, sizeof(rb));
            if (rb.bind) {
              /* bind：ordinal → imports → 外部符号地址 */
              struct dyld_chained_ptr_64_bind bd;
              memcpy(&bd, &raw, sizeof(bd));
              newv = resolve_bind_ordinal(fixups, hdr, bd.ordinal, bd.addend,
                                          dlsym_addr);
              walk_next = (int)bd.next;
              n_bind++;
            } else {
              /* rebase：本镜像内指针，按格式加 slide / remote_base */
              newv = (format == DYLD_CHAINED_PTR_64_OFFSET)
                         ? (remote_base + rb.target)
                         : ((uint64_t)slide + rb.target);
              walk_next = (int)rb.next;
              n_rebase++;
            }
          } else {
            fprintf(stderr,
                    "[injector] pointer_format=%u (arm64e not supported)\n",
                    format);
            die("unsupported chained pointer format");
          }

          /* 链式编码 → 普通 64 位指针，CPU 可直接解引用 */
          memcpy(buf + ptr_off, &newv, 8);
          if (walk_next == 0)
            break; /* 本页链表结束 */
          /* PTR_64 / PTR_64_OFFSET: next 单位 stride = 4 字节 */
          next += (uint32_t)walk_next * 4;
        }
      }
    }
    /* 测试日志里 rebase=0 bind=1：几乎纯 PIC，只有一条 _dlsym bind */
    printf("[injector] fixups: rebase=%d bind=%d slide=%lld\n", n_rebase,
           n_bind, (long long)slide);
  } else {
    printf("[injector] no chained fixups — assuming pure PIC\n");
  }

  *out_size = span;
  (void)m;
  return buf;
}

/* ---- shellcode bootstrap → pthread(_last) ---- */

static uint32_t enc_movz_x(unsigned rd, uint16_t imm16, unsigned hw) {
  return 0xD2800000u | ((uint32_t)hw << 21) | ((uint32_t)imm16 << 5) | rd;
}
static uint32_t enc_movk_x(unsigned rd, uint16_t imm16, unsigned hw) {
  return 0xF2800000u | ((uint32_t)hw << 21) | ((uint32_t)imm16 << 5) | rd;
}
static void emit_mov64(uint32_t **p, unsigned rd, uint64_t imm) {
  *(*p)++ = enc_movz_x(rd, (uint16_t)(imm >> 0), 0);
  *(*p)++ = enc_movk_x(rd, (uint16_t)(imm >> 16), 1);
  *(*p)++ = enc_movk_x(rd, (uint16_t)(imm >> 32), 2);
  *(*p)++ = enc_movk_x(rd, (uint16_t)(imm >> 48), 3);
}

static void remote_pthread_call(task_t task, uint64_t fn, uint64_t arg) {
  struct task_dyld_info dyld_info;
  mach_msg_type_number_t cnt = TASK_DYLD_INFO_COUNT;
  kern_return_t kr =
      task_info(task, TASK_DYLD_INFO, (task_info_t)&dyld_info, &cnt);
  if (kr != KERN_SUCCESS)
    die_kr("task_info(TASK_DYLD_INFO)", kr);

  uint64_t libpthread = find_remote_image(task, dyld_info.all_image_info_addr,
                                          "/libsystem_pthread.dylib");
  if (!libpthread)
    die("libsystem_pthread not found in target");
  uint64_t pthread_cfm =
      remote_dlsym(task, libpthread, "_pthread_create_from_mach_thread");
  if (!pthread_cfm)
    die("_pthread_create_from_mach_thread not found");

  printf("[injector] pthread_create_from_mach_thread=0x%llx\n",
         (unsigned long long)pthread_cfm);
  printf("[injector] start_routine(_last)=0x%llx arg=0x%llx\n",
         (unsigned long long)fn, (unsigned long long)arg);

  mach_vm_address_t code = remote_alloc_rw(task, PAGE_SZ);
  mach_vm_address_t stack = remote_alloc_rw(task, STACK_SZ);
  mach_vm_address_t boot = code;
  /* pthread_t out-param must be writable — not on the RX bootstrap page. */
  uint64_t sp = stack + STACK_SZ - 0x40;
  uint64_t slot = sp - 0x10;

  uint32_t boot_code[48];
  uint32_t *p = boot_code;
  emit_mov64(&p, 0, slot);
  emit_mov64(&p, 1, 0);
  emit_mov64(&p, 2, fn);
  emit_mov64(&p, 3, arg);
  emit_mov64(&p, 8, pthread_cfm);
  *p++ = 0xD63F0100; /* blr x8 */
  *p++ = 0x14000000; /* b . */
  size_t boot_n = (size_t)(p - boot_code) * 4;
  if (remote_write(task, boot, boot_code, boot_n) != KERN_SUCCESS)
    die("write bootstrap failed");

  kr = mach_vm_protect(task, code, PAGE_SZ, FALSE,
                       VM_PROT_READ | VM_PROT_EXECUTE);
  if (kr != KERN_SUCCESS)
    die_kr("mach_vm_protect(boot RX)", kr);

  thread_act_t thread = MACH_PORT_NULL;
  kr = thread_create(task, &thread);
  if (kr != KERN_SUCCESS)
    die_kr("thread_create", kr);

  arm_thread_state64_t st;
  memset(&st, 0, sizeof(st));
  st.__pc = boot;
  st.__sp = sp;
  kr = thread_set_state(thread, ARM_THREAD_STATE64, (thread_state_t)&st,
                        ARM_THREAD_STATE64_COUNT);
  if (kr != KERN_SUCCESS)
    die_kr("thread_set_state", kr);
  kr = thread_resume(thread);
  if (kr != KERN_SUCCESS)
    die_kr("thread_resume", kr);
  printf("[injector] resumed → pthread(_last)\n");
}

static void pe_inject(task_t task, const char *dylib_path) {
  macho_buf_t macho;
  macho_load(dylib_path, &macho);
  image_info_t img;
  parse_image(&macho, &img);

  size_t span = (size_t)(img.vmax - img.vmin);
  mach_vm_size_t remote_size = align_up(span, PAGE_SZ);
  mach_vm_address_t remote_base = remote_alloc_rw(task, remote_size);
  printf("[injector] remote image base=0x%llx size=0x%llx\n",
         (unsigned long long)remote_base, (unsigned long long)remote_size);

  size_t buf_sz = 0;
  uint8_t *reloc =
      build_relocated_image(task, &macho, &img, remote_base, &buf_sz);
  if (remote_write(task, remote_base, reloc, buf_sz) != KERN_SUCCESS)
    die("write image failed");
  free(reloc);

  /* Segment protections */
  for (uint32_t i = 0; i < img.nsegs; i++) {
    struct segment_command_64 *s = &img.segs[i].seg;
    if (strncmp(s->segname, "__PAGEZERO", 16) == 0)
      continue;
    mach_vm_address_t a = remote_base + (s->vmaddr - img.vmin);
    mach_vm_size_t sz = align_up(s->vmsize, PAGE_SZ);
    vm_prot_t prot = 0;
    if (s->initprot & VM_PROT_READ)
      prot |= VM_PROT_READ;
    if (s->initprot & VM_PROT_WRITE)
      prot |= VM_PROT_WRITE;
    if (s->initprot & VM_PROT_EXECUTE)
      prot |= VM_PROT_EXECUTE;
    if (!prot)
      continue;
    if ((prot & VM_PROT_EXECUTE) && (prot & VM_PROT_WRITE))
      prot &= (vm_prot_t)~VM_PROT_WRITE;
    kern_return_t kr = mach_vm_protect(task, a, sz, FALSE, prot);
    if (kr != KERN_SUCCESS) {
      fprintf(stderr, "[injector] protect %s: %s — continuing\n", s->segname,
              mach_error_string(kr));
    } else {
      printf("[injector] protect %s @0x%llx prot=0x%x\n", s->segname,
             (unsigned long long)a, prot);
    }
  }

  uint64_t last_rt = remote_base + (img.last_vmaddr - img.vmin);
  remote_pthread_call(task, last_rt, 0);

  macho_unload(&macho);
}

static char *abspath_alloc(const char *path) {
  char buf[PATH_MAX];
  if (realpath(path, buf))
    return strdup(buf);
  if (path[0] == '/')
    return strdup(path);
  char cwd[PATH_MAX];
  if (!getcwd(cwd, sizeof(cwd)))
    return strdup(path);
  snprintf(buf, sizeof(buf), "%s/%s", cwd, path);
  return strdup(buf);
}

int main(int argc, char **argv) {
  setbuf(stdout, NULL);
  setbuf(stderr, NULL);

  if (argc != 3) {
    fprintf(stderr, "Usage: %s <target> <payload.dylib>\n", argv[0]);
    fprintf(stderr, "  PE map + pthread(_last), no dlopen\n");
    fprintf(stderr, "  target = pid or name (e.g. SpringBoard)\n");
    return 1;
  }

  const char *target = argv[1];
  const char *dylib_arg = argv[2];

  if (access(dylib_arg, R_OK) != 0) {
    fprintf(stderr, "[injector] cannot read %s: %s\n", dylib_arg,
            strerror(errno));
    return 1;
  }

  char *dylib = abspath_alloc(dylib_arg);
  printf("[injector] payload: %s\n", dylib);

  pid_t pid = resolve_target(target);
  printf("[injector] target pid=%d\n", pid);

  task_t task = MACH_PORT_NULL;
  kern_return_t kr = task_for_pid(mach_task_self(), pid, &task);
  if (kr != KERN_SUCCESS)
    die_kr("task_for_pid", kr);
  printf("[injector] task port=%d\n", task);

  unlink("/tmp/inject_demo_ok");
  pe_inject(task, dylib);
  free(dylib);

  sleep(3);
  if (access("/tmp/inject_demo_ok", F_OK) == 0)
    printf("[injector] SUCCESS — /tmp/inject_demo_ok exists\n");
  else
    printf("[injector] finished (no marker yet — check device logs)\n");
  return 0;
}
