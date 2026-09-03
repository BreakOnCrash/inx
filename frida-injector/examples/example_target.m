#import <Foundation/Foundation.h>

@interface TEST : NSObject
- (void)dododo;
@end

@implementation TEST
- (void)dododo {
  NSLog(@"you did it!");
}
@end

int main(int argc, const char *argv[]) {
  @autoreleasepool {
    NSLog(@"pid -> %d", getpid());
    TEST *t = [[TEST alloc] init];
    while (YES) {}
  }
  return 0;
}