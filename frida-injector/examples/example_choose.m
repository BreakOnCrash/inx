// @Base: https://gist.github.com/samdmarshall/17f4e66b5e2e579fd396

#import <Foundation/Foundation.h>
#import <mach/mach_vm.h>
#import <malloc/malloc.h>
#import <objc/message.h>
#import <objc/runtime.h>

#if defined(__arm64__)
#define OBJC_ISA_MASK 0xffffffff8ULL
#elif defined(__i386__) // TODO
#define OBJC_ISA_MASK 0x7ffffffffff8ULL
#endif

// TODO
#define CLASS "TEST"

Class cls;
size_t cls_size;

void CanHasObjects(task_t task, void *context, unsigned type,
                   vm_range_t *ranges, unsigned count) {
  unsigned i;
  for (i = 0; i < count; i++) {
    vm_range_t *range = &ranges[i];
    uintptr_t *address = ((uintptr_t *)range->address);
    uintptr_t *isa;

    if (address == NULL) {
      continue;
    }

    isa = (uintptr_t *)address[0];
#ifdef OBJC_ISA_MASK
    isa = (uintptr_t *)((unsigned long long)isa & OBJC_ISA_MASK);
#endif

    if (isa > 0 && range->size >= sizeof(Class) && cls == (Class)isa) {
#ifdef DEBUG
      printf("[+] fond isa(%p)->'%s' instance %p \n", isa,
             object_getClassName((Class)isa), address);
#endif
      // TODO
      ((void (*)(id, SEL))objc_msgSend)((__bridge id)address,
                                        @selector(dododo));
    }
  }
}

static void __attribute__((constructor)) initialize(void) {
  @autoreleasepool {
    cls = NSClassFromString([NSString stringWithFormat:@"%s", CLASS]);
    if (cls == Nil) {
#ifdef DEBUG
      printf("[-] Class not found\n");
#endif
      return;
    }

    cls_size = class_getInstanceSize(cls);
    if (cls_size == 0) {
#ifdef DEBUG
      printf("[-] Class Instance size is %zu\n", cls_size);
#endif
      return;
    }

#ifdef DEBUG
    printf("[+] Class %p Instance size is %zu\n", cls, cls_size);
#endif

    vm_address_t *zones;
    unsigned count, i = 0;
    kern_return_t r =
        malloc_get_all_zones(mach_task_self(), NULL, &zones, &count);
    if (r == KERN_SUCCESS) {
      for (i = 0; i < count; i++) {
        vm_address_t zone_address = zones[i];
        malloc_zone_t *zone = (malloc_zone_t *)zone_address;

        if (zone != NULL && zone->introspect != NULL) {
          zone->introspect->enumerator(mach_task_self(), NULL,
                                       MALLOC_PTR_IN_USE_RANGE_TYPE,
                                       zone_address, NULL, &CanHasObjects);
        }
      }
    }
  }
}