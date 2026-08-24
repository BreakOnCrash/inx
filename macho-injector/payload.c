/*
 * PE payload: bind _dlsym only; everything else via dlsym(RTLD_DEFAULT, …).
 * Same pattern as POCLoader/poc.c (minus pthread TLS — already on pthread).
 */
#include <dlfcn.h>
#include <stdint.h>

typedef void *(*dlsym_fn)(void *, const char *);
typedef int (*open_fn)(const char *, int, ...);
typedef long (*write_fn)(int, const void *, unsigned long);
typedef int (*close_fn)(int);

__attribute__((visibility("default"), no_builtin("memcpy", "strlen", "memset")))
void *last(void *arg) {
  (void)arg;

  /* Import filled by injector chained bind → target libdyld._dlsym */
  dlsym_fn _dlsym = (dlsym_fn)dlsym;
  if (!_dlsym)
    return (void *)(intptr_t)-1;

  open_fn _open = (open_fn)_dlsym(RTLD_DEFAULT, "open");
  write_fn _write = (write_fn)_dlsym(RTLD_DEFAULT, "write");
  close_fn _close = (close_fn)_dlsym(RTLD_DEFAULT, "close");
  if (!_open || !_write || !_close)
    return (void *)(intptr_t)-2;

  const char *path = "/tmp/inject_demo_ok";
  const char *msg = "pe-map dlsym ok\n";
  int fd = _open(path, 0x601 /* O_CREAT|O_WRONLY|O_TRUNC */, 0644);
  if (fd >= 0) {
    (void)_write(fd, msg, 16);
    (void)_close(fd);
  }

  for (;;)
    __asm__ volatile("yield");
  return 0;
}
