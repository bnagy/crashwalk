Crashwalk
=======

## Documentation

If you want to use `import "github.com/bnagy/crashwalk"` in your own Go code, you
can get godoc at: http://godoc.org/github.com/bnagy/crashwalk

## cwtriage

To run the standalone cwtriage tool:
```
  cwtriage runs crashfiles with instrumentation and outputs results in various formats
  Usage: cwtriage -root /path/to/afl-dir [-match pattern] -- /path/to/target -in @@ -out whatever
  ( @@ will be substituted for each crashfile )

  -afl
        Prefer the AFL recorded crashing command, if present
  -engine string
        Debugging engine to use: [gdb lldb] (default "gdb")
  -every int
        Run every n seconds (default -1)
  -ignore string
        Directory skip pattern ( go regex syntax )
  -match string
        Match pattern for files ( go regex syntax )
  -mem int
        Memory limit for target processes (MB) (default -1)
  -output string
        Output format to use: [json pb text] (default "text")
  -root string
        Root directory to look for crashes
  -seen
        Include seen results from the DB in the output
  -strict
        Abort the whole run if any crashes fail to repro
  -t int
        Timeout for target processes (secs) (default 60)
  -tidy
        Move crashes that error under Run() to a tidy dir
  -workers int
        Number of concurrent workers (default 1)
```

### AFL Mode

If you're using AFL >= 1.50b then afl automatically records the command that was used in each crash dir ( in the README.txt file ). For most people, that means you can use the -afl switch to:
- Automatically set the -match pattern to match AFL crashfiles
- Automatically use the stored command from the README.txt in each crash directory
- Automatically set the same memory limit
- Automatically ignore queue/ and hang/ directories
- Use the supplied command (if any) as a default

If you are in the directory that contains your individual fuzz workers, then the minimal command would be something like
```
cwtriage -root . -afl
```

### Manual Mode

If you're triaging from an older version of AFL or you want to run the crashes with a different target command, then `-match crashes.\*id` should match AFL crashes.

The tool creates a BoltDB (in the current directory, by default) that is used to cache crash instrumentation results. This way you can run it multiple times on an active directory and only get the latest crashes, or run it with -seen and get all crashes, but faster. To "reset the cache" just `rm crashwalk.db`. NOTE that the cache DOES NOT contain the actual crashfile, only the metadata, so don't go deleting your crashes or anything.

### Output Formats

Supported output formats are JSON, protocol buffers or the text summary seen in the examples below. JSON and protbuf output is one crash per line, to facilitate piping that output to another process - for example to push each crash to a queue, write them to a database etc.


### Tidy

When you have crashfiles that don't repro under the debugger they are not added to the `cwtriage` cache database, which means that `cwtriage` will attempt to run then every time, even without `-seen`. If you have a lot of these files, or if they're particularly slow (such a memory eaters and hangs) then they can add a lot of time to each run. By using the `-tidy` flag, files that don't crash under the debugger will be moved to a directory inside the crash directory.

## cwdump

`cwdump` summarizes crashes in a crashwalk database by major / minor stack hash. Although AFL (for example) already de-dups crashes, bucketing summarizes those crashes by an order of magnitude or more. Crashes that bucket the same have _exactly_ the same stack contents, so they're likely (not guaranteed) to be the same bug.

Run `cwtriage` as above and then do something like
```
cwdump ./crashwalk.db > triage.txt
```

## cwfind

`cwfind` is a simple utility to output the filenames of all crashes matching a given hash. I use it in combination with `xargs` to bulk delete / move crashfiles.

```
$ cwfind a9060880abffbe2dcd5c9b4bb39c9233.0e358881a2545b216eee9aabe3723302
pdf-S3/crashes/id:000821,sig:08,src:019017+009441,op:splice,rep:16
pdf-S25/crashes/id:000823,sig:08,src:019101+013412,op:splice,rep:64
pdf-S17/crashes/id:000870,sig:08,src:025983+017873,op:splice,rep:8
pdf-S3/crashes/id:000822,sig:08,src:019017+009441,op:splice,rep:4
```
## Installation

1. You should follow the [instructions](https://golang.org/doc/install) to
install Go, if you haven't already done so.

2. (FOR LINUX ONLY) Install the 'exploitable' tool from [here](https://github.com/jfoote/exploitable). Right now the code is expecting to find the tool at `~/src/exploitable/exploitable/exploitable.py`. I plan to make this less hacky later, but the current license on the exploitable tool is in disarray, thus it (possibly) prevents me from bundling it with this repo.

3. (FOR LINUX ONLY) Make sure you have gdb in your path with `which gdb`

4. (FOR OSX ONLY) I wrote a very heavily modified mutant offspring of exploitable and one of the lldb sample tools, called `exploitaben.py`. Unless you do something unusual the `cwtriage` binary will install it as a dependency and use it for `-engine lldb`. You can check the lldb specific code [here](https://github.com/bnagy/francis)

5. (FOR OSX ONLY) Make sure lldb is installed. You might need to mess about with assorted Xcode hijinks etc.

Now, install crashwalk:
```bash
$ go get -u github.com/bnagy/crashwalk/cmd/...
```

The binaries produced are statically linked (Go just does that), so you can 'deploy' to other systems, docker containers etc by just copying them.

No overarching tests yet, sorry, it's a little fiddly to build a standalone testbed. The gdb / lldb parsers will panic if they get confused and give you the problematic input and a useful stack trace. If the input is not sensitive, use that to open an issue and I'll fix it.

`exploitaben` does have a reasonable set of tests, and you can check out [the results](https://github.com/bnagy/francis/exploitaben/test_results/test_output.txt). I suck at python so the diffing is not automatic. I included all of the exploitable project tests as well as all the CrashWrangler tests.

## Screenshots

#### GDB Example - unique faulting EIPs
```
./cwtriage -afl -root . -workers 16 | grep =\> | sort | uniq -c
2015/02/19 00:58:20 Workers started
2015/02/19 01:06:51 All done!
      1 => 0x00007ffff6184dfe: push r13
    140 => 0x00007ffff6184e17: mov DWORD PTR [rbp-0x4e0],eax
     75 => 0x00007ffff6184e7d: call 0x7ffff61cf5e0 <strchrnul>
      3 => 0x00007ffff6184fa9: call 0x7ffff6189f90 <buffered_vfprintf>
      1 => 0x00007ffff6189f92: push r12
    129 => 0x00007ffff6189fc5: mov QWORD PTR [rsp+0x100],rbx
     12 => 0x00007ffff6189fd8: mov DWORD PTR [rsp+0x20],0xfbad8004
      1 => 0x00007ffff61b70da: push r13
      5 => 0x00007ffff61b70de: push rbp
      1 => 0x00007ffff61b71c4: call 0x7ffff61c8230 <__mempcpy_sse2>
```

#### GDB Example - summary output
```
---CRASH SUMMARY---
Filename: /dev/shm/crashexplore/fuzz3/crashes/id:000359,sig:11,src:001295,op:havoc,rep:16
SHA1: 30d6e81570a67cb32bbd51b460d74bb193a85d98
Classification: EXPLOITABLE
Hash: 2f50f8e5a6fb7a55669dc8ead34fdba3.ba6f36a1a8447da016a175a99706a64b
Command: /home/ben/src/poppler-0.26.5/utils/pdftocairo -jpeg /dev/shm/crashexplore/fuzz3/crashes/id:000359,sig:11,src:001295,op:havoc,rep:16
Faulting Frame:
   fprintf @ 0x000000000044f7be: in /home/ben/src/poppler-0.26.5/utils/pdftocairo
Disassembly:
   0x00007ffff6184e60: mov QWORD PTR [rbp-0x460],rax
   0x00007ffff6184e67: mov rax,QWORD PTR [r15+0x8]
   0x00007ffff6184e6b: mov QWORD PTR [rbp-0x458],rax
   0x00007ffff6184e72: mov rax,QWORD PTR [r15+0x10]
   0x00007ffff6184e76: mov QWORD PTR [rbp-0x450],rax
=> 0x00007ffff6184e7d: call 0x7ffff61cf5e0 <strchrnul>
   0x00007ffff6184e82: and r12d,0x8000
   0x00007ffff6184e89: mov QWORD PTR [rbp-0x4e8],rax
   0x00007ffff6184e90: mov QWORD PTR [rbp-0x4d0],rax
   0x00007ffff6184e97: mov DWORD PTR [rbp-0x4dc],0x0
Stack Head (1001 entries):
   _IO_vfprintf_internal     @ 0x00007ffff6184e7d: in /lib/x86_64-linux-gnu/libc-2.19.so (BL)
   buffered_vfprintf         @ 0x00007ffff618a021: in /lib/x86_64-linux-gnu/libc-2.19.so (BL)
   _IO_vfprintf_internal     @ 0x00007ffff6184fae: in /lib/x86_64-linux-gnu/libc-2.19.so (BL)
   ___fprintf_chk            @ 0x00007ffff6245065: in /lib/x86_64-linux-gnu/libc-2.19.so (BL)
   fprintf                   @ 0x000000000044f7be: in /home/ben/src/poppler-0.26.5/utils/pdftocairo
   error                     @ 0x000000000044f7be: in /home/ben/src/poppler-0.26.5/utils/pdftocairo
   Parser::getObj            @ 0x0000000000569363: in /home/ben/src/poppler-0.26.5/utils/pdftocairo
   Parser::getObj            @ 0x0000000000568deb: in /home/ben/src/poppler-0.26.5/utils/pdftocairo
   Parser::getObj            @ 0x000000000056997b: in /home/ben/src/poppler-0.26.5/utils/pdftocairo
   XRef::fetch               @ 0x00000000005d2d01: in /home/ben/src/poppler-0.26.5/utils/pdftocairo
   dictLookup                @ 0x00000000005aa3a5: in /home/ben/src/poppler-0.26.5/utils/pdftocairo
   Stream::addFilters        @ 0x00000000005aa3a5: in /home/ben/src/poppler-0.26.5/utils/pdftocairo
   Parser::makeStream        @ 0x000000000056842e: in /home/ben/src/poppler-0.26.5/utils/pdftocairo
   Parser::getObj            @ 0x00000000005695d2: in /home/ben/src/poppler-0.26.5/utils/pdftocairo
   Parser::getObj            @ 0x000000000056997b: in /home/ben/src/poppler-0.26.5/utils/pdftocairo
   Parser::getObj            @ 0x000000000056997b: in /home/ben/src/poppler-0.26.5/utils/pdftocairo
Registers:
rax=0x00007fffff801ca0 rbx=0x00007fffff7ff560 rcx=0x00000000ffffffff rdx=0x00007fffff801c88 
rsi=0x0000000000000025 rdi=0x000000000083976a rbp=0x00007fffff7ff530 rsp=0x00007fffff7fef50 
 r8=0x00007ffff64fb9f0  r9=0x0000000001f21e10 r10=0x000000000083976a r11=0x0000000000aa8000 
r12=0x00000000fbad8004 r13=0x0000000000000024 r14=0x000000000083976a r15=0x00007fffff801c88 
rip=0x00007ffff6184e7d efl=0x0000000000010246  cs=0x0000000000000033  ss=0x000000000000002b 
 ds=0x0000000000000000  es=0x0000000000000000  fs=0x0000000000000000  gs=0x0000000000000000 
Extra Data:
   Description: Access violation during branch instruction
   Short description: BranchAv (4/22)
   Explanation: The target crashed on a branch instruction, which may indicate that the control flow is tainted.
---END SUMMARY---
```

### LLDB Example - summary output

For `exploitaben` I used "indicators" instead of a single classification. I'm hoping that this is more flexible and better suited to post-crash database searches and such. They're in the `Extra Data` field below, so that the crash summary protobufs are crossplatform.
```
---CRASH SUMMARY---
Filename: /Volumes/ramdisk/popplUNFIXED/crashes/id:000156,sig:06,src:006567,op:havoc,rep:16
SHA1: 53100e26a2eced52afa5a8f1708ced7a6dbb6435
Classification: 
Hash: 8263c96a28b14639c338ffd408d3701e.0add20a3424f9105c8476367f36eb255
Command: /Users/ben/src/poppler-0.31.0/utils/pdftoppm -aa no -r 36 -png /Volumes/ramdisk/popplUNFIXED/crashes/id:000156,sig:06,src:006567,op:havoc,rep:16
Faulting Frame:
   Catalog::getNumPages() [inlined] Object::dictIs(this=0x000a000000000007, dictType=<unavailable>) - 18446744069413943243 @ 0x000000010009c834: in pdftoppm
Disassembly:
=> 0x00007fff97580282: :  73 08           jae    0x7fff9758028c            ; __pthread_kill + 20
   0x00007fff97580284: :  48 89 c7        mov    rdi, rax
   0x00007fff97580287: :  e9 17 ba ff ff  jmp    0x7fff9757bca3            ; cerror_nocancel
   0x00007fff9758028c: :  c3              ret
   0x00007fff9758028d: :  90              nop
   0x00007fff9758028e: :  90              nop
   0x00007fff9758028f: :  90              nop
   0x00007fff97580290: :  b8 4c 01 00 02  mov    eax, 0x200014c
   0x00007fff97580295: :  49 89 ca        mov    r10, rcx
   0x00007fff97580298: :  0f 05           syscall 
Stack Head (6 entries):
   __pthread_kill + 10       @ 0x00007fff97580282: in libsystem_kernel.dylib
   pthread_kill + 90         @ 0x00007fff8e3d54c3: in libsystem_pthread.dylib
   abort + 129               @ 0x00007fff97a4cb73: in libsystem_c.dylib
   Catalog::getNumPages() [i @ 0x000000010009c834: in pdftoppm
   main(argc=2, argv=<unavai @ 0x0000000100002bb0: in pdftoppm
   start + 1                 @ 0x00007fff9a2f35c9: in libdyld.dylib
Registers:
rax=0x0000000000000000 rbx=0x0000000000000006 rcx=0x00007fff5fbffc88 rdx=0x0000000000000000 
rdi=0x000000000000030b rsi=0x0000000000000006 rbp=0x00007fff5fbffcb0 rsp=0x00007fff5fbffc88 
 r8=0x0000000000000008  r9=0x0000000100800000 r10=0x0000000008000000 r11=0x0000000000000206 
r12=0x00000001004a5200 r13=0x0000000000000000 r14=0x00007fff7cb27300 r15=0x0000000100a002a0 
rip=0x00007fff97580282 rfl=0x0000000000000206  cs=0x0000000000000007  fs=0x0000000000000000 
 gs=0x0000000000000000 
Extra Data:
   StopDesc:           signal SIGABRT
   AvNearNull:         False
   AvNearSP:           False
   BadBeef:            False
   Access Type:        <not an access violation>
   Registers:
   BlockMov:           False
   Weird PC:           False
   Weird SP:           False
   Suspicious Funcs:
   Illegal Insn:       False
   Huge Stack:         False
---END SUMMARY---
```

## TODO

Add NSQ support. Add docker support.

## Contributing

Fork and send a pull request to contribute code.

Report issues.

## License

BSD style, see LICENSE file for details.
