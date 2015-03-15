package lldb

// This is a parsing wrapper for LLDB. It is designed for use with this tool,
// but may have independent utility, in which case I'll refactor it out later.
// It implements the simple Debugger() interface required by the crashwalk
// package. Essentially, crashwalk takes care of finding the files, this code
// takes care of running them under LLDB and parsing the output into
// crashwalk/crash's struct formats

import (
	"bufio"
	"bytes"
	"fmt"
	"github.com/bnagy/crashwalk/crash"
	"go/build"
	"io/ioutil"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

type Engine struct{}

// Frames in this blacklist are not eligible to be considered the faulting
// frame.
var libsystemRgx = regexp.MustCompile("libsystem")
var blacklist = []*regexp.Regexp{libsystemRgx}

// Example output
/*
Stack trace:
* thread #1: tid = 0x154da494, 0x00007fff97a33c9c libsystem_c.dylib`__vfprintf + 145, queue = 'com.apple.main-thread', stop reason = EXC_BAD_ACCESS (code=2, address=0x7fff5f3fffe8)
  * frame #0: 0x00007fff97a33c9c libsystem_c.dylib`__vfprintf + 145
    frame #1: 0x00007fff97a5d9cf libsystem_c.dylib`__v2printf + 679
    frame #2: 0x00007fff97a5dc64 libsystem_c.dylib`__xvprintf + 536
    frame #3: 0x00007fff97a33b92 libsystem_c.dylib`vfprintf_l + 54
    frame #4: 0x00007fff97a2c620 libsystem_c.dylib`fprintf + 186
    frame #5: 0x00000001000ca176 pdftoppm`error(category=<unavailable>, pos=<unavailable>, msg=<unavailable>) - 18446744069413756553
    frame #6: 0x00000001002783dd pdftoppm`Parser::makeStream(this=<unavailable>, dict=<unavailable>, fileKey=<unavailable>, encAlgorithm=<unavailable>, keyLength=<unavailable>, objNum=<unavailable>, objGen=<unavailable>, recursion=<unavailable>, strict=<unavailable>) - 18446744069411994658
    frame #7: 0x00000001002777d7 pdftoppm`Parser::getObj(this=<unavailable>, obj=<unavailable>, simpleOnly=<unavailable>, fileKey=<unavailable>, encAlgorithm=<unavailable>, keyLength=<unavailable>, objNum=<unavailable>, objGen=<unavailable>, recursion=<unavailable>, strict=<unavailable>) - 18446744069411997736
    frame #8: 0x000000010027685e pdftoppm`Parser::getObj(this=<unavailable>, obj=<unavailable>, simpleOnly=<unavailable>, fileKey=<unavailable>, encAlgorithm=<unavailable>, keyLength=<unavailable>, objNum=<unavailable>, objGen=<unavailable>, recursion=<unavailable>, strict=<unavailable>) - 18446744069412001697
    frame #9: 0x00000001002fefbc pdftoppm`XRef::fetch(this=<unavailable>, num=<unavailable>, gen=<unavailable>, obj=<unavailable>, recursion=<unavailable>) - 18446744069411442755
    frame #10: 0x00000001000c48d3 pdftoppm`Dict::lookup(this=<unavailable>, key=<unavailable>, obj=<unavailable>, recursion=<unavailable>) - 18446744069413779244
    frame #11: 0x000000010029b28e pdftoppm`Stream::addFilters(Object*, int) [inlined] Object::dictLookup(this=<unavailable>, key=<unavailable>, obj=0x0000000100000007, recursion=<unavailable>) - 18446744069411851633
    frame #12: 0x0000000100278fd6 pdftoppm`Parser::makeStream(this=<unavailable>, dict=<unavailable>, fileKey=<unavailable>, encAlgorithm=<unavailable>, keyLength=<unavailable>, objNum=<unavailable>, objGen=<unavailable>, recursion=<unavailable>, strict=<unavailable>) - 18446744069411991593
    frame #13: 0x00000001002777d7 pdftoppm`Parser::getObj(this=<unavailable>, obj=<unavailable>, simpleOnly=<unavailable>, fileKey=<unavailable>, encAlgorithm=<unavailable>, keyLength=<unavailable>, objNum=<unavailable>, objGen=<unavailable>, recursion=<unavailable>, strict=<unavailable>) - 18446744069411997736
    frame #14: 0x000000010027685e pdftoppm`Parser::getObj(this=<unavailable>, obj=<unavailable>, simpleOnly=<unavailable>, fileKey=<unavailable>, encAlgorithm=<unavailable>, keyLength=<unavailable>, objNum=<unavailable>, objGen=<unavailable>, recursion=<unavailable>, strict=<unavailable>) - 18446744069412001697
    frame #15: 0x00000001002fefbc pdftoppm`XRef::fetch(this=<unavailable>, num=<unavailable>, gen=<unavailable>, obj=<unavailable>, recursion=<unavailable>) - 18446744069411442755
    frame #16: 0x00000001000c48d3 pdftoppm`Dict::lookup(this=<unavailable>, key=<unavailable>, obj=<unavailable>, recursion=<unavailable>) - 18446744069413779244
    frame #17: 0x000000010029b28e pdftoppm`Stream::addFilters(Object*, int) [inlined] Object::dictLookup(this=<unavailable>, key=<unavailable>, obj=0x0000000100000007, recursion=<unavailable>) - 18446744069411851633
    frame #18: 0x0000000100278fd6 pdftoppm`Parser::makeStream(this=<unavailable>, dict=<unavailable>, fileKey=<unavailable>, encAlgorithm=<unavailable>, keyLength=<unavailable>, objNum=<unavailable>, objGen=<unavailable>, recursion=<unavailable>, strict=<unavailable>) - 18446744069411991593
    frame #19: 0x00000001002777d7 pdftoppm`Parser::getObj(this=<unavailable>, obj=<unavailable>, simpleOnly=<unavailable>, fileKey=<unavailable>, encAlgorithm=<unavailable>, keyLength=<unavailable>, objNum=<unavailable>, objGen=<unavailable>, recursion=<unavailable>, strict=<unavailable>) - 18446744069411997736
    frame #20: 0x000000010027685e pdftoppm`Parser::getObj(this=<unavailable>, obj=<unavailable>, simpleOnly=<unavailable>, fileKey=<unavailable>, encAlgorithm=<unavailable>, keyLength=<unavailable>, objNum=<unavailable>, objGen=<unavailable>, recursion=<unavailable>, strict=<unavailable>) - 18446744069412001697
    frame #21: 0x00000001002fefbc pdftoppm`XRef::fetch(this=<unavailable>, num=<unavailable>, gen=<unavailable>, obj=<unavailable>, recursion=<unavailable>) - 18446744069411442755
    frame #22: 0x00000001000c48d3 pdftoppm`Dict::lookup(this=<unavailable>, key=<unavailable>, obj=<unavailable>, recursion=<unavailable>) - 18446744069413779244
    frame #23: 0x000000010029b28e pdftoppm`Stream::addFilters(Object*, int) [inlined] Object::dictLookup(this=<unavailable>, key=<unavailable>, obj=0x0000000100000007, recursion=<unavailable>) - 18446744069411851633
    frame #24: 0x0000000100278fd6 pdftoppm`Parser::makeStream(this=<unavailable>, dict=<unavailable>, fileKey=<unavailable>, encAlgorithm=<unavailable>, keyLength=<unavailable>, objNum=<unavailable>, objGen=<unavailable>, recursion=<unavailable>, strict=<unavailable>) - 18446744069411991593

Nearby code:
libsystem_c.dylib`__vfprintf + 145:
-> 0x7fff97a33c9c:  e8 d9 01 04 00        call   0x7fff97a73e7a            ; symbol stub for: localeconv_l
   0x7fff97a33ca1:  48 8b 18              mov    rbx, qword ptr [rax]
   0x7fff97a33ca4:  80 7b 01 00           cmp    byte ptr [rbx + 0x1], 0x0
   0x7fff97a33ca8:  b8 01 00 00 00        mov    eax, 0x1
   0x7fff97a33cad:  74 08                 je     0x7fff97a33cb7            ; __vfprintf + 172
   0x7fff97a33caf:  48 89 df              mov    rdi, rbx
   0x7fff97a33cb2:  e8 a7 fc 03 00        call   0x7fff97a7395e            ; symbol stub for: strlen
   0x7fff97a33cb7:  48 89 85 50 fc ff ff  mov    qword ptr [rbp - 0x3b0], rax
   0x7fff97a33cbe:  48 89 9d 70 fc ff ff  mov    qword ptr [rbp - 0x390], rbx
   0x7fff97a33cc5:  4c 8d ad 48 fd ff ff  lea    r13, qword ptr [rbp - 0x2b8]

General Purpose Registers:
       rax = 0x00007fff5f400168
       rbx = 0x00007fff5f400528
       rcx = 0x00007fff5f400c40
       rdx = 0x000000010044b9a1  "%s (%lld): %s\n"
       rdi = 0x00007fff7df526b8  __global_locale
       rsi = 0x00007fff7df526b8  __global_locale
       rbp = 0x00007fff5f400410
       rsp = 0x00007fff5f3ffff0
        r8 = 0x000000010044b9a1  "%s (%lld): %s\n"
        r9 = 0x00007fff5f400bf0
       r10 = 0x000000001018f6b4
       r11 = 0x0000000000000451
       r12 = 0x00007fff7df526b8  __global_locale
       r13 = 0x000000010044b9a1  "%s (%lld): %s\n"
       r14 = 0x000000010044b9a1  "%s (%lld): %s\n"
       r15 = 0x0000000000000000
       rip = 0x00007fff97a33c9c  libsystem_c.dylib`__vfprintf + 145
    rflags = 0x0000000000010206
        cs = 0x000000000000002b
        fs = 0x0000000000000000
        gs = 0x0000000000000000


Hash: 3171efa808d0fdded15f3a5471ca9559.46ebc0f49f22e0b2db7e00fe58c1fd1e
ANALYSIS INDICATORS:
--------------------
StopDesc:           EXC_BAD_ACCESS (code=2, address=0x7fff5f3fffe8)
AvNearNull:         False
AvNearSP:           True
BadBeef             False
Access Type:        recursion
Registers:
BlockMov:           False
Weird PC:           False
Weird SP:           False
Suspicious Funcs:
Illegal Insn:       False
Huge Stack:         True

*/

func explode(raw []byte, cmd string) {
	s := `
BUG: Internal error parsing LLDB output!

Something went wrong trying to parse the output of LLDB and we can't continue
without emitting stupid results. If this is a crash that's not worth money,
please open an issue and include the raw LLDB output. If not then just wait, I
guess. :)

LLDB OUTPUT:

`
	panic(fmt.Sprintf("%s %s\nCOMMAND:\n%s\n", s, string(raw), cmd))
}

func mustParseHex(s string, die func()) (n uint64) {
	n, err := strconv.ParseUint(s, 0, 64)
	if err != nil {
		die()
	}
	return
}

func mustAddExtra(prefix string, scanner *bufio.Scanner, ci *crash.Info, die func()) {
	scanner.Scan()
	if !strings.HasPrefix(scanner.Text(), prefix) {
		die()
	}
	ci.Extra = append(ci.Extra, scanner.Text())
}

func mustAdvanceTo(token string, scanner *bufio.Scanner, die func()) {
	for scanner.Scan() {
		if scanner.Text() == token {
			return
		}
	}
	die()
}

func parseIndicators(raw []byte, ci *crash.Info, die func()) {
	// 	ANALYSIS INDICATORS:
	// --------------------
	// StopDesc:           EXC_BAD_ACCESS (code=2, address=0x7fff5f3fffe8)
	// AvNearNull:         False
	// [...]
	scanner := bufio.NewScanner(bytes.NewReader(raw))
	mustAdvanceTo("ANALYSIS INDICATORS:", scanner, die)
	scanner.Scan() // divider row -----
	mustAddExtra("StopDesc:", scanner, ci, die)
	mustAddExtra("AvNearNull:", scanner, ci, die)
	mustAddExtra("AvNearSP:", scanner, ci, die)
	mustAddExtra("BadBeef:", scanner, ci, die)
	mustAddExtra("Access Type:", scanner, ci, die)
	mustAddExtra("Registers:", scanner, ci, die)
	mustAddExtra("BlockMov:", scanner, ci, die)
	mustAddExtra("Weird PC:", scanner, ci, die)
	mustAddExtra("Weird SP:", scanner, ci, die)
	mustAddExtra("Suspicious Funcs:", scanner, ci, die)
	mustAddExtra("Illegal Insn:", scanner, ci, die)
	mustAddExtra("Huge Stack:", scanner, ci, die)
}

func parseExploitable(raw []byte, ci *crash.Info, die func()) {
	scanner := bufio.NewScanner(bytes.NewReader(raw))
	for scanner.Scan() {
		if strings.HasPrefix(scanner.Text(), "Hash:") {
			ff := strings.Fields(scanner.Text())
			if len(ff) < 2 {
				die()
			}
			ci.Hash = ff[1]
			break
		}
	}
}

func parseDisasm(raw []byte, die func()) (crash.Instruction, []crash.Instruction) {
	//Nearby code:
	// libsystem_c.dylib`__vfprintf + 145:
	// -> 0x7fff97a33c9c:  e8 d9 01 04 00        call   0x7fff97a73e7a            ; symbol stub for: localeconv_l
	//    0x7fff97a33ca1:  48 8b 18              mov    rbx, qword ptr [rax]
	//    0x7fff97a33ca4:  80 7b 01 00           cmp    byte ptr [rbx + 0x1], 0x0
	//    0x7fff97a33ca8:  b8 01 00 00 00        mov    eax, 0x1
	//    0x7fff97a33cad:  74 08                 je     0x7fff97a33cb7            ; __vfprintf + 172
	//    0x7fff97a33caf:  48 89 df              mov    rdi, rbx
	//    0x7fff97a33cb2:  e8 a7 fc 03 00        call   0x7fff97a7395e            ; symbol stub for: strlen
	//    0x7fff97a33cb7:  48 89 85 50 fc ff ff  mov    qword ptr [rbp - 0x3b0], rax
	//    0x7fff97a33cbe:  48 89 9d 70 fc ff ff  mov    qword ptr [rbp - 0x390], rbx
	//
	// Stack trace:

	disasm := []crash.Instruction{}
	fault := crash.Instruction{}
	scanner := bufio.NewScanner(bytes.NewReader(raw))
	mustAdvanceTo("Nearby code:", scanner, die)

	// Parse the nearby code
	for scanner.Scan() {

		if strings.HasPrefix(scanner.Text(), "Stack trace:") {
			break
		}

		ff := strings.Fields(scanner.Text())
		// sometimes we get extra crap like:
		// libsystem_kernel.dylib`__pthread_kill:
		if len(ff) == 0 || !((ff[0] == "->") || strings.HasPrefix(ff[0], "0x")) {
			continue
		}

		// The LLDB disasm output with opcodes is nicely formatted. Let's just
		// use theirs.
		colon := strings.Index(scanner.Text(), ":")
		if colon < 0 || len(ff) < 3 {
			die()
		}
		txt := scanner.Text()[colon:]

		if ff[0] == "->" {
			fault = crash.Instruction{
				Address: mustParseHex(strings.TrimSuffix(ff[1], ":"), die),
				Text:    txt,
			}
			disasm = append(disasm, fault)
			continue
		}

		disasm = append(
			disasm,
			crash.Instruction{
				Address: mustParseHex(strings.TrimSuffix(ff[0], ":"), die),
				Text:    txt,
			},
		)

	}
	return fault, disasm
}

func parseRegisters(raw []byte, die func()) (registers []crash.Register) {
	// General Purpose Registers:
	//        rax = 0x0000000000000000
	//        rbx = 0x0000000000000006
	//        rcx = 0x00007fff5fbffc88

	registers = make([]crash.Register, 0, 20)
	scanner := bufio.NewScanner(bytes.NewReader(raw))
	mustAdvanceTo("General Purpose Registers:", scanner, die)

	for scanner.Scan() {
		if scanner.Text() == "" {
			break
		}
		ff := strings.Fields(scanner.Text())
		if len(ff) < 3 {
			die()
		}
		registers = append(
			registers,
			crash.Register{
				Name:  ff[0],
				Value: mustParseHex(ff[2], die),
			},
		)
	}
	return
}

func parseStack(raw []byte, ci *crash.Info, die func()) {
	// Stack trace:
	// * thread #1: tid = 0x9f2fa1f, 0x00007fff97580282 libsystem_kernel.dylib`__pthread_kill + 10, queue = 'com.apple.main-thread', stop reason = signal SIGABRT
	//   * frame #0: 0x00007fff97580282 libsystem_kernel.dylib`__pthread_kill + 10
	//     frame #1: 0x00007fff8e3d54c3 libsystem_pthread.dylib`pthread_kill + 90
	//     frame #2: 0x00007fff97a4cb73 libsystem_c.dylib`abort + 129
	//     frame #3: 0x00000001000b4dc4 pdftoppm`Catalog::getNumPages() [inlined] Object::dictIs(this=0x0000000000000007, dictType=<unavailable>) - 18446744069413843515
	//     frame #4: 0x00000001000029c0 pdftoppm`main(argc=2, argv=<unavailable>) - 18446744069414573631
	//     frame #5: 0x00007fff9a2f35c9 libdyld.dylib`start + 1
	//     frame #6: 0x00007fff9a2f35c9 libdyld.dylib`start + 1

	scanner := bufio.NewScanner(bytes.NewReader(raw))
	mustAdvanceTo("Stack trace:", scanner, die)

	scanner.Scan()
	ff := strings.Fields(scanner.Text())
	if len(ff) < 8 || ff[1] != "thread" {
		die()
	}

	for scanner.Scan() {

		// scan until we run out of frames
		ff := strings.Fields(scanner.Text())
		if len(ff) == 0 {
			break
		}
		// A leading asterisk adjusts all our offsets by 1
		adjust := 0
		if ff[0] == "*" {
			adjust++
		}
		if ff[0+adjust] != "frame" {
			break
		}
		if len(ff) < 3 {
			die()
		}

		var address uint64
		var found bool
		for _, s := range ff {
			if strings.HasPrefix(s, "0x") {
				address = mustParseHex(s, die)
				found = true
			}
		}
		if !found {
			die()
		}
		splits := []string{"???", "???"}
		if len(ff) > 3+adjust {
			// split on backtick (`)
			// libsystem_pthread.dylib`pthread_kill + 90
			rest := strings.Join(ff[3+adjust:], " ")
			splits = strings.SplitN(rest, "`", 2)
			if len(splits) < 2 {
				die()
			}
		}
		entry := crash.StackEntry{
			Address: address,
			Module:  splits[0],
			Symbol:  splits[1],
		}
		ci.Stack = append(ci.Stack, entry)

	}

	// Set the fault to the first frame that's not blacklisted
walk:
	for _, frame := range ci.Stack {
		for _, r := range blacklist {
			if r.MatchString(frame.Module) {
				continue walk
			}
		}
		ci.FaultingFrame = frame
		break
	}

	// don't be too fussy about not finding a stack, here, some crashes set
	// those registers to values that are unreadable as addresses.
	return
}

func parse(raw []byte, cmd string) crash.Info {

	// this just prettifies the rest of the parsers slightly
	die := func() {
		explode(raw, cmd)
	}

	ci := crash.Info{}

	ci.Registers = parseRegisters(raw, die)
	parseStack(raw, &ci, die)
	parseExploitable(raw, &ci, die)
	ci.FaultingInsn, ci.Disassembly = parseDisasm(raw, die)
	parseIndicators(raw, &ci, die)

	return ci
}

func (e *Engine) Run(command []string) (crash.Info, error) {

	pkg, err := build.Import("github.com/bnagy/crashwalk", ".", build.FindOnly)
	if err != nil {
		return crash.Info{}, fmt.Errorf("Couldn't find import path: %s", err)
	}
	tool := filepath.Join(pkg.Dir, "lldb/exploitaben/exploitaben.py")

	cmdSlice := append([]string{tool, "--"}, command...)
	cmdStr := strings.Join(cmdSlice, " ")
	cmd := exec.Command(cmdSlice[0], cmdSlice[1:]...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return crash.Info{}, fmt.Errorf("Error creating pipe: %s", err)
	}
	if err := cmd.Start(); err != nil {
		return crash.Info{}, fmt.Errorf("Error launching tool: %s", err)
	}

	// We don't care about this error because we don't care about exploitaben's exit
	// status.
	out, _ := ioutil.ReadAll(stdout)
	cmd.Wait()

	if bytes.Contains(out, []byte("exited with status")) ||
		bytes.Contains(out, []byte("killing the process...")) {
		// No crash.
		return crash.Info{}, fmt.Errorf("No lldb output for %s", cmdStr)
	}

	ci := parse(out, cmdStr)
	return ci, nil

}
