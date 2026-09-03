// Load an arm64 Mach-O into Unicorn, bind _printf, call _run.
package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/blacktop/go-macho"
	"github.com/blacktop/go-macho/types"

	uc "github.com/unicorn-engine/unicorn/bindings/go/unicorn"
)

const (
	pageSize = uint64(0x1000)

	// Guest layout (fixed, no ASLR):
	imageBase  = uint64(0x0000000100000000) // dylib
	returnAddr = uint64(0x0000000200000000) // BRK: _run returns here, emu stops
	shimBase   = uint64(0x0000000300000000) // fake libc (RET + hook)
	heapBase   = uint64(0x0000000400000000) // host-placed strings
	stackBase  = uint64(0x0000000500000000)

	heapSize  = uint64(64) << 10
	stackSize = uint64(64) << 10

	shimPrintf = shimBase
	// shimMalloc = shimBase + 16 // next import: another RET at shimBase+16
)

var arm64Ret = []byte{0xC0, 0x03, 0x5F, 0xD6} // RET
var arm64Brk = []byte{0x00, 0x00, 0x20, 0xD4} // BRK #0

func main() {
	path := "guest.dylib"

	if err := run(path); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func run(path string) error {
	file, err := openArm64(path)
	if err != nil {
		return err
	}
	defer file.Close()

	mu, err := uc.NewUnicorn(uc.ARCH_ARM64, uc.MODE_LITTLE_ENDIAN)
	if err != nil {
		return fmt.Errorf("unicorn: %w (install libunicorn, e.g. brew install unicorn)", err)
	}
	defer mu.Close()

	slide, err := loadImage(mu, file, imageBase)
	if err != nil {
		return err
	}

	runAddr, err := symbolAddr(file, "_run", slide)
	if err != nil {
		return err
	}

	fmt.Printf("load  image  @ %#x  (slide %#x)\n", imageBase, slide)
	fmt.Printf("sym   _run   %#x\n", runAddr)

	if err := mapWorkspace(mu); err != nil {
		return err
	}

	// No libSystem here: point GOT[_printf] at our shim (see bindImports).
	imports := map[string]uint64{
		"_printf": shimPrintf,
	}
	if err := bindImports(mu, file, slide, imports); err != nil {
		return err
	}

	heap := &bumpHeap{next: heapBase, end: heapBase + heapSize}

	// Hook fires before the shim RET. Implement printf in Go, then RET uses LR.
	_, err = mu.HookAdd(uc.HOOK_CODE, func(mu uc.Unicorn, addr uint64, size uint32) {
		if addr != shimPrintf {
			return
		}
		if hookErr := hostPrintf(mu); hookErr != nil {
			fmt.Fprintf(os.Stderr, "printf: %v\n", hookErr)
			_ = mu.Stop()
		}
	}, shimPrintf, shimPrintf)
	if err != nil {
		return fmt.Errorf("hook shims: %w", err)
	}

	msg := append([]byte("hello from guest"), 0)
	msgAddr, err := heap.alloc(uint64(len(msg)))
	if err != nil {
		return err
	}
	if err := mu.MemWrite(msgAddr, msg); err != nil {
		return err
	}

	if err := call(mu, runAddr, msgAddr); err != nil {
		return err
	}

	x0, err := mu.RegRead(uc.ARM64_REG_X0)
	if err != nil {
		return err
	}
	pc, err := mu.RegRead(uc.ARM64_REG_PC)
	if err != nil {
		return err
	}
	fmt.Printf("return x0=%d pc=%#x\n", x0, pc)
	return nil
}

func mapWorkspace(mu uc.Unicorn) error {
	for _, region := range []struct {
		addr, size uint64
	}{
		{returnAddr, pageSize},
		{shimBase, pageSize},
		{heapBase, heapSize},
		{stackBase, stackSize},
	} {
		if err := mu.MemMap(region.addr, region.size); err != nil {
			return fmt.Errorf("mmap %#x: %w", region.addr, err)
		}
	}

	if err := mu.MemWrite(returnAddr, arm64Brk); err != nil {
		return err
	}
	if err := mu.MemWrite(shimPrintf, arm64Ret); err != nil {
		return err
	}
	return nil
}

func call(mu uc.Unicorn, fn, x0 uint64) error {
	// AAPCS64: arg0 in X0, return address in LR, SP 16-byte aligned.
	sp := stackBase + stackSize
	if err := mu.RegWrite(uc.ARM64_REG_SP, sp); err != nil {
		return err
	}
	if err := mu.RegWrite(uc.ARM64_REG_LR, returnAddr); err != nil {
		return err
	}
	if err := mu.RegWrite(uc.ARM64_REG_X0, x0); err != nil {
		return err
	}

	fmt.Printf("call  _run(%#x)  sp=%#x lr=%#x\n", x0, sp, returnAddr)
	if err := mu.Start(fn, returnAddr); err != nil {
		return fmt.Errorf("emu: %w", err)
	}
	return nil
}

func hostPrintf(mu uc.Unicorn) error {
	formatAddr, err := mu.RegRead(uc.ARM64_REG_X0)
	if err != nil {
		return err
	}
	format, err := readCString(mu, formatAddr)
	if err != nil {
		return err
	}

	// Apple arm64: named args in registers; variadic args on the stack.
	sp, err := mu.RegRead(uc.ARM64_REG_SP)
	if err != nil {
		return err
	}

	var out strings.Builder
	var stackOff uint64
	for i := 0; i < len(format); i++ {
		if format[i] != '%' {
			out.WriteByte(format[i])
			continue
		}
		i++
		if i >= len(format) {
			out.WriteByte('%')
			break
		}
		switch format[i] {
		case '%':
			out.WriteByte('%')
		case 's':
			ptr, err := readU64(mu, sp+stackOff)
			if err != nil {
				return err
			}
			stackOff += 8
			s, err := readCString(mu, ptr)
			if err != nil {
				return err
			}
			out.WriteString(s)
		case 'd':
			v, err := readU64(mu, sp+stackOff)
			if err != nil {
				return err
			}
			stackOff += 8
			fmt.Fprintf(&out, "%d", int32(v))
		default:
			out.WriteByte('%')
			out.WriteByte(format[i])
		}
	}

	text := out.String()
	fmt.Print(text)
	return mu.RegWrite(uc.ARM64_REG_X0, uint64(len(text)))
}

// bindImports writes GOT[name] = shim. It does not patch _run or the stub.
//
// This guest is a dylib with LC_DYLD_CHAINED_FIXUPS. `bl _printf` is
// PC-relative, so ld64 plants a trampoline in __TEXT,__stubs:
//
//	_run:  bl stub                 // fixed local target
//	stub:  adrp/ldr x16, GOT[name] // load 8 bytes
//	       br   x16                // jump to shim
//
// We only replace the GOT pointer (file offset → vmaddr + slide).
func bindImports(mu uc.Unicorn, file *macho.File, slide uint64, shims map[string]uint64) error {
	if !file.HasDyldChainedFixups() {
		return errors.New("expected LC_DYLD_CHAINED_FIXUPS (rebuild guest.dylib)")
	}

	dcf, err := file.DyldChainedFixups()
	if err != nil {
		return err
	}
	if _, err := dcf.Parse(); err != nil {
		return fmt.Errorf("parse chained fixups: %w", err)
	}

	var n int
	for _, start := range dcf.Starts {
		for _, b := range start.Binds() {
			if err := applyBind(mu, file, slide, shims, b.Name(), b.Offset()); err != nil {
				return err
			}
			n++
		}
	}
	if n == 0 {
		return errors.New("chained fixups contain no binds")
	}
	return nil
}

// applyBind: GOT[name] = shim. Offset is the file offset of the GOT slot.
func applyBind(mu uc.Unicorn, file *macho.File, slide uint64, shims map[string]uint64, name string, fileOff uint64) error {
	shim, ok := shims[name]
	if !ok {
		return fmt.Errorf("unhooked import %s", name)
	}

	vmaddr, err := file.GetVMAddress(fileOff)
	if err != nil {
		return err
	}

	slot := vmaddr + slide
	if err := writeU64(mu, slot, shim); err != nil {
		return err
	}
	fmt.Printf("bind  %-16s GOT=%#x -> shim %#x\n", name, slot, shim)
	return nil
}

func loadImage(mu uc.Unicorn, file *macho.File, loadBase uint64) (uint64, error) {
	type segment struct {
		name  string
		addr  uint64
		memsz uint64
		data  []byte
	}

	var segs []segment
	for _, seg := range file.Segments() {
		if seg.Name == "__PAGEZERO" || seg.Memsz == 0 {
			continue
		}
		data, err := seg.Data()
		if err != nil {
			return 0, fmt.Errorf("segment %s: %w", seg.Name, err)
		}
		segs = append(segs, segment{seg.Name, seg.Addr, seg.Memsz, data})
	}
	if len(segs) == 0 {
		return 0, errors.New("mach-o has no loadable segments")
	}

	minAddr, maxAddr := segs[0].addr, segs[0].addr+segs[0].memsz
	for _, seg := range segs[1:] {
		if seg.addr < minAddr {
			minAddr = seg.addr
		}
		if end := seg.addr + seg.memsz; end > maxAddr {
			maxAddr = end
		}
	}

	// File vmaddr is often 0; slide = where we actually mapped it.
	slide := loadBase - minAddr
	span := alignUp(maxAddr-minAddr, pageSize)
	if err := mu.MemMap(loadBase, span); err != nil {
		return 0, fmt.Errorf("mmap image: %w", err)
	}

	const segFmt = "%-4s  %-16s addr=%#-14x mem=%#-10x file=%d\n"
	for _, seg := range segs {
		addr := seg.addr + slide
		if len(seg.data) != 0 {
			if err := mu.MemWrite(addr, seg.data); err != nil {
				return 0, fmt.Errorf("write %s: %w", seg.name, err)
			}
		}
		fmt.Printf(segFmt, "mmap", seg.name, addr, seg.memsz, len(seg.data))
	}
	return slide, nil
}

func openArm64(path string) (*macho.File, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	fat, err := macho.NewFatFile(bytes.NewReader(data))
	if err == nil {
		for _, arch := range fat.Arches {
			if arch.CPU == types.CPUArm64 {
				return arch.File, nil
			}
		}
		return nil, errors.New("fat mach-o has no arm64 slice")
	}
	if !errors.Is(err, macho.ErrNotFat) {
		return nil, err
	}

	file, err := macho.NewFile(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	if file.CPU != types.CPUArm64 {
		return nil, fmt.Errorf("expected arm64 mach-o, got %s", file.CPU)
	}
	return file, nil
}

func symbolAddr(file *macho.File, name string, slide uint64) (uint64, error) {
	addr, err := file.FindSymbolAddress(name)
	if err != nil {
		return 0, err
	}
	return addr + slide, nil
}

type bumpHeap struct {
	next, end uint64
}

func (h *bumpHeap) alloc(n uint64) (uint64, error) {
	if n == 0 {
		n = 1
	}
	n = alignUp(n, 16)
	if h.next > h.end || n > h.end-h.next {
		return 0, errors.New("guest heap exhausted")
	}
	addr := h.next
	h.next += n
	return addr, nil
}

func readCString(mu uc.Unicorn, addr uint64) (string, error) {
	var out []byte
	for len(out) < 4096 {
		b, err := mu.MemRead(addr+uint64(len(out)), 1)
		if err != nil {
			return "", err
		}
		if b[0] == 0 {
			return string(out), nil
		}
		out = append(out, b[0])
	}
	return "", errors.New("unterminated guest string")
}

func readU64(mu uc.Unicorn, addr uint64) (uint64, error) {
	data, err := mu.MemRead(addr, 8)
	if err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint64(data), nil
}

func writeU64(mu uc.Unicorn, addr, value uint64) error {
	var buf [8]byte
	binary.LittleEndian.PutUint64(buf[:], value)
	return mu.MemWrite(addr, buf[:])
}

func alignUp(v, a uint64) uint64 {
	return (v + a - 1) &^ (a - 1)
}
