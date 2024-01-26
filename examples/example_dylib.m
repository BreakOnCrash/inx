#import <Foundation/Foundation.h>

static void __attribute__((constructor)) initialize(void) {
  NSLog(@"insert_dylib: I'm here");
}