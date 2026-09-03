/*
 * Minimal arm64 Mach-O dylib for Unicorn.
 *
 * Uses real stdio: printf is an undefined import (_printf). There is no
 * Darwin libc inside Unicorn, so the Go loader binds the GOT slot to a
 * `ret` stub and HOOK_CODE implements printf on the host (same idea as
 * SAP shims).
 *
 *   clang -arch arm64 -shared -fPIC -O0 -fno-stack-protector \
 *         -o guest.dylib guest/guest.c
 */

#include <stdio.h>

int run(const char *msg)
{
	printf("guest says: %s\n", msg);
	return 42;
}
