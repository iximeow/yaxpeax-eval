## yaxpeax-eval

[![crate](https://img.shields.io/crates/v/yaxpeax-eval.svg?logo=rust)](https://crates.io/crates/yaxpeax-eval)

`yaxpeax-eval` is the repo providing `yaxeval`, a tool to execute machine code with preconditions and report state at exit.

currently, `yaxeval` works by spawning a thread and executing the provided machine code on the local physical processor. there is some boring glue for architecture-dependent state setting and reporting. this means that `yaxeval` supports, or is close to supporting, whatever physical processor you would run it on.

i am interested in using qemu-user as an alternate execution backend for cross-platform emulation. `yaxeval` should be able to use qemu-user just the same for setup and reporting by using qemu's gdbserver.

## usage

if you just want to build and use it, `cargo install yaxpeax-eval` should get you started. otherwise, clone this repo and a `cargo build` will work as well. `yaxeval <x86 machine code>` is a good starting point:

```
yaxpeax-eval> ./target/release/yaxeval b878563412
loaded code...
  00007f774b497000: mov eax, 0x12345678
  00007f774b497005: 🏁 (int 0x3)
running...
  rax:   0000000000000000
   to -> 0000000012345678
  rip:   00007f774b497000
   to -> 00007f774b497006
```

initial register state is generally zeroes, with exception of `rip`, which by default points to whatever address an unrestricted `mmap` could find.

inital register values, including `rip`, can be specified explicitly:

```
yaxpeax-eval> ./target/release/yaxeval --regs rax=4,rcx=5,rip=0x123456789a,eflags=0x246 03c133c9
loaded code...
  000000123456789a: add eax, ecx
  000000123456789c: xor ecx, ecx
  000000123456789e: 🏁 (int 0x3)
running...
  rax:   0000000000000004
   to -> 0000000000000009
  rcx:   0000000000000005
   to -> 0000000000000000
  rip:   000000123456789a
   to -> 000000123456789f
```

and if the provided code disastrously crashes, `yaxeval` will try to say a bit about what occurred:

```
yaxpeax-eval> ./target/release/yaxeval --regs rax=4,rcx=5,rip=0x123456789a,eflags=0x246 0000
loaded code...
  000000123456789a: add byte [rax], al
  000000123456789c: 🏁 (int 0x3)
running...
  eflags:        00000246
   to ->         00010246
sigsegv at unexpected address: 000000123456789a
```

## aspirations

* accept some config to map memory regions other than the implicitly-initialized code region
* machine-friendly input/output formats
* mode to single-step through provided code?
