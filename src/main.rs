use clap::Parser;
use libc::pid_t;
use nix::sys::mman::{MapFlags, ProtFlags};
use nix::sys::ptrace::Request::*;
use nix::unistd::ForkResult;
use std::ffi::c_void;
use std::fs;
use std::num::NonZeroUsize;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use yaxpeax_arch::LengthedInstruction;

#[derive(Parser)]
#[clap(about, version, author)]
struct Args {
    /// file of bytes to execute
    #[clap(short, long, parse(from_os_str), conflicts_with = "code")]
    file: Option<PathBuf>,

    /// hex bytes to execute. for example, try `33c0`
    #[clap(required_unless_present = "file")]
    code: Option<String>,

    /// initial register state. registers not specified here may be initialized to random values.
    #[clap(short, long)]
    regs: Option<String>,
}

fn parse_number(v: &str) -> Result<u64, String> {
    let res = if v.starts_with("0x") {
        u64::from_str_radix(&v[2..], 16)
    } else if v.starts_with("0b") {
        u64::from_str_radix(&v[2..], 2)
    } else if v.starts_with("0o") {
        u64::from_str_radix(&v[2..], 8)
    } else {
        u64::from_str_radix(v, 10)
    };

    res.map_err(|e| format!("{}", e))
}

fn main() {
    let args = Args::parse();

    let buf: Vec<u8> = match args.code {
        Some(code) => match hex::decode(code) {
            Ok(buf) => buf,
            Err(e) => {
                eprintln!("invalid input, {}. expected a sequence of bytes as hex", e);
                return;
            }
        },
        None => {
            let name = args.file.unwrap();
            match fs::read(&name) {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("error reading {}: {}", name.display(), e);
                    return;
                }
            }
        }
    };

    let initial_rip: Option<u64> = args.regs.as_ref()
        .and_then(|regs| regs.split(",").find(|x| x.starts_with("rip=")))
        .map(|assign| {
            match assign.split("=").collect::<Vec<_>>().as_slice() {
                ["rip", value] => parse_number(value),
                [_other, _value] => Err(format!("found `rip=` but then string didn't start with `rip=`?")),
                other => Err(format!("string was not a simple reg=value format: {:?}", other))
            }
        })
        .transpose()
        .unwrap();

    // implement `initial_rip`, if present, as follows:
    // `initial_rip / 4096` is implemented by an mmap base address,
    // `initial_rip % 4096` is implemented by offsetting in that mmap ("before" initial_rip is
    // implicitly all 0)
    let required_len = initial_rip.map(|x| x as usize & 0xfff).unwrap_or(0) + buf.len() + 1;
    let rounded_len = (required_len + 0xfff) & !0xfff;

    let sync: *const AtomicBool = {
        let shared_ptr = unsafe {
            nix::sys::mman::mmap(
                None,
                NonZeroUsize::new(4096).unwrap(),
                ProtFlags::PROT_EXEC | ProtFlags::PROT_WRITE | ProtFlags::PROT_READ,
                MapFlags::MAP_SHARED | MapFlags::MAP_ANON,
                0,
                0,
            ).unwrap()
        };
        let ptr = shared_ptr as *mut AtomicBool;
        unsafe { std::ptr::write(ptr, AtomicBool::new(false)) };
        ptr as *const AtomicBool
    };

    let mut map_flags = MapFlags::MAP_SHARED | MapFlags::MAP_ANON;
    if initial_rip.is_some() {
        map_flags |= MapFlags::MAP_FIXED;
    }

    let code = unsafe {
        nix::sys::mman::mmap(
            initial_rip.map(|x| NonZeroUsize::new(x as usize - (x as usize % 0x1000)).unwrap()),
            NonZeroUsize::new(rounded_len).unwrap(),
            ProtFlags::PROT_EXEC | ProtFlags::PROT_WRITE | ProtFlags::PROT_READ,
            map_flags,
            0,
            0,
        ).unwrap()
    };

    let initial_rip = (code as u64) + initial_rip.map(|x| x & 0xfff).unwrap_or(0);

    let slice: &mut [u8] = unsafe {
        std::slice::from_raw_parts_mut(
            initial_rip as *mut u8,
            required_len
        )
    };
    (&mut slice[..buf.len()]).copy_from_slice(buf.as_slice());
    slice[buf.len()] = 0xcc;

    println!("loaded code...");
    let mut offset = 0;
    while offset < buf.len() + 1 {
        match yaxpeax_x86::long_mode::InstDecoder::default().decode_slice(&slice[offset..]) {
            Ok(inst) => {
                if offset < buf.len() {
                    println!("  {:016x}: {}", offset + initial_rip as usize, inst);
                } else {
                    println!("  {:016x}: 🏁 ({})", offset + initial_rip as usize, inst);
                }
                offset += inst.len().to_const() as usize
            }
            Err(e) => {
                println!("  {:016x}: {}", offset + initial_rip as usize, e);
                println!("    (offset {:x})", offset);
                break;
            }
        }
    }
    println!("running...");

    let target = match unsafe { nix::unistd::fork().unwrap() } {
        ForkResult::Parent { child } => PtraceEvalTarget::attach(child.as_raw(), sync),
        ForkResult::Child => unsafe { setup(sync) },
    };

    unsafe {
        target.clear_regs();
        if let Some(regs) = args.regs.as_ref() {
            target.apply_regs(regs);
        }
        target.set_rip(initial_rip);

        let regs = target.get_regs();
        let status = target.run();
    //    println!("status: {}", status);

        let exit_regs = target.get_regs();

        print_diff(&regs, &exit_regs);

        if status & 0xff == 0x7f {
            let signal = status >> 8;
            if signal == libc::SIGTRAP {
                if exit_regs.rip == (initial_rip + buf.len() as u64 + 1) {
                    // code completed normally
                } else {
                    println!("sigtrap at atypical address: {:016x}", exit_regs.rip);
                    std::process::exit(1);
                }
            } else if signal == libc::SIGSEGV {
                println!("sigsegv at unexpected address: {:016x}", exit_regs.rip);
                std::process::exit(1);
            } else {
                println!("signal {} at unexpected address: {:016x}", signal, exit_regs.rip);
            }
        } else if status <= 255 {
            println!("exited with signal: {}", status & 0xff);
            std::process::exit(1);
        } else {
            println!("unknown stop status? {}", status);
            std::process::exit(1);
        }
    }
}

fn print_diff(from: &libc::user_regs_struct, to: &libc::user_regs_struct) {
    if from.rax != to.rax {
        println!("  rax:   {:016x}", from.rax);
        println!("   to -> {:016x}", to.rax);
    }
    if from.rcx != to.rcx {
        println!("  rcx:   {:016x}", from.rcx);
        println!("   to -> {:016x}", to.rcx);
    }
    if from.rdx != to.rdx {
        println!("  rdx:   {:016x}", from.rdx);
        println!("   to -> {:016x}", to.rdx);
    }
    if from.rbx != to.rbx {
        println!("  rbx:   {:016x}", from.rbx);
        println!("   to -> {:016x}", to.rbx);
    }
    if from.rbp != to.rbp {
        println!("  rbp:   {:016x}", from.rbp);
        println!("   to -> {:016x}", to.rbp);
    }
    if from.rsp != to.rsp {
        println!("  rsp:   {:016x}", from.rsp);
        println!("   to -> {:016x}", to.rsp);
    }
    if from.rsi != to.rsi {
        println!("  rsi:   {:016x}", from.rsi);
        println!("   to -> {:016x}", to.rsi);
    }
    if from.rdi != to.rdi {
        println!("  rdi:   {:016x}", from.rdi);
        println!("   to -> {:016x}", to.rdi);
    }
    if from.r8 != to.r8 {
        println!("  r8:    {:016x}", from.r8);
        println!("   to -> {:016x}", to.r8);
    }
    if from.r9 != to.r9 {
        println!("  r9:    {:016x}", from.r9);
        println!("   to -> {:016x}", to.r9);
    }
    if from.r10 != to.r10 {
        println!("  r10:   {:016x}", from.r10);
        println!("   to -> {:016x}", to.r10);
    }
    if from.r11 != to.r11 {
        println!("  r11:   {:016x}", from.r11);
        println!("   to -> {:016x}", to.r11);
    }
    if from.r12 != to.r12 {
        println!("  r12:   {:016x}", from.r12);
        println!("   to -> {:016x}", to.r12);
    }
    if from.r13 != to.r13 {
        println!("  r13:   {:016x}", from.r13);
        println!("   to -> {:016x}", to.r13);
    }
    if from.r14 != to.r14 {
        println!("  r14:   {:016x}", from.r14);
        println!("   to -> {:016x}", to.r14);
    }
    if from.r15 != to.r15 {
        println!("  r15:   {:016x}", from.r15);
        println!("   to -> {:016x}", to.r15);
    }
    if from.rip != to.rip {
        println!("  rip:   {:016x}", from.rip);
        println!("   to -> {:016x}", to.rip);
    }
    if from.eflags != to.eflags {
        println!("  eflags:        {:08x}", from.eflags);
        println!("   to ->         {:08x}", to.eflags);
    }
}

unsafe fn setup(sync: *const AtomicBool) -> ! {
    assert_eq!(libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL), 0);
    sync.as_ref().unwrap().store(true, Ordering::SeqCst);
    loop {}
}

struct PtraceEvalTarget {
    pid: pid_t,
}

impl PtraceEvalTarget {
    fn attach(pid: pid_t, sync: *const AtomicBool) -> Self {
        // wait until the child process signals it's ready to be attached to. this solves a small
        // race where if we attach and die before the child sets `prctl(PR_SET_PDEATHSIG)`, the
        // child process can become an orphan. the default config leaves the child process in an
        // infinite loop in such a case.
        let syncref = unsafe { sync.as_ref().unwrap() };
        while !syncref.load(Ordering::SeqCst) {
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        if unsafe { libc::ptrace(PTRACE_ATTACH as u32, pid) } != 0 {
            panic!("ptrace: {}", nix::errno::errno());
        }
        if unsafe { libc::waitpid(pid, std::ptr::null_mut(), 0) } == -1 {
            panic!("waitpid: {}", nix::errno::errno());
        }

        Self { pid }
    }

    unsafe fn apply_regs(&self, regs: &str) {
        let mut state = self.get_regs();

        let parts = regs.split(",");
        for part in parts {
            let kv = part.split("=").collect::<Vec<_>>();
            match kv.as_slice() {
                [reg, value] => {
                    let value: u64 = parse_number(value).unwrap();
                    match *reg {
                        "rax" => { state.rax = value },
                        "rcx" => { state.rcx = value },
                        "rdx" => { state.rdx = value },
                        "rbx" => { state.rbx = value },
                        "rbp" => { state.rbp = value },
                        "rsp" => { state.rsp = value },
                        "rsi" => { state.rsi = value },
                        "rdi" => { state.rdi = value },
                        "r8" => { state.r8 = value },
                        "r9" => { state.r9 = value },
                        "r10" => { state.r10 = value },
                        "r11" => { state.r11 = value },
                        "r12" => { state.r12 = value },
                        "r13" => { state.r13 = value },
                        "r14" => { state.r14 = value },
                        "r15" => { state.r15 = value },
                        "eflags" => { state.eflags = value },
                        "rip" => { /* handled elsewhere */ },
                        other => { panic!("unknown register {}", other) }
                    }
                },
                other => {
                    eprintln!("register assignment was not of the form `regname=value`? {:?}", other);
                }
            }
        }

        self.set_regs(&mut state);
    }

    unsafe fn clear_regs(&self) {
        let mut regs = self.get_regs();
        regs.rax = 0;
        regs.rcx = 0;
        regs.rdx = 0;
        regs.rbx = 0;
        regs.rbp = 0;
        regs.rsp = 0;
        regs.rsi = 0;
        regs.rdi = 0;
        regs.r8 = 0;
        regs.r9 = 0;
        regs.r10 = 0;
        regs.r11 = 0;
        regs.r12 = 0;
        regs.r13 = 0;
        regs.r14 = 0;
        regs.r15 = 0;
        regs.eflags = 0;
        self.set_regs(&mut regs);
    }

    unsafe fn get_regs(&self) -> libc::user_regs_struct {
        let mut regs: libc::user_regs_struct =
            std::mem::transmute([0u8; std::mem::size_of::<libc::user_regs_struct>()]);
        if libc::ptrace(PTRACE_GETREGS as u32, self.pid, std::ptr::null_mut::<*const c_void>(), &mut regs as *mut libc::user_regs_struct) != 0 {
            panic!("ptrace(getregs): {}", nix::errno::errno());
        }

        regs
    }

    unsafe fn set_regs(&self, regs: &mut libc::user_regs_struct) {
        if libc::ptrace(PTRACE_SETREGS as u32, self.pid, std::ptr::null_mut::<*const c_void>(), regs as *mut libc::user_regs_struct) != 0 {
            panic!("ptrace(setregs): {}", nix::errno::errno());
        }
    }

    unsafe fn set_rip(&self, rip: u64) {
        let mut regs = self.get_regs();
        regs.rip = rip;
        if libc::ptrace(PTRACE_SETREGS as u32, self.pid, std::ptr::null_mut::<*const c_void>(), &mut regs as *mut libc::user_regs_struct) != 0 {
            panic!("ptrace(setregs): {}", nix::errno::errno());
        }
    }

    unsafe fn run(&self) -> i32 {
        if libc::ptrace(PTRACE_CONT as u32, self.pid, 0, 0) != 0 {
            panic!("ptrace(cont): {}", nix::errno::errno());
        }

        let mut status = 0;
        if libc::waitpid(self.pid, &mut status as *mut i32, 0) == -1 {
            panic!("waitpid: {}", nix::errno::errno());
        }
        status
    }
}
