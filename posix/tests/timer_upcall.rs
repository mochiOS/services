use std::io::Write;
use std::process::{Command, Stdio};

#[test]
fn actual_timer_body_delivers_after_scheduling_and_before_leaving_kernel_address_space() {
    let timer = include_str!("../../../core/src/interrupt/timer.rs");
    let start = timer.find("extern \"sysv64\" fn handle_timer(").unwrap();
    let end = start + timer[start..].find("\n}\n").unwrap() + 3;
    let mut program = String::from(
        r#"
thread_local! {
    static EVENTS:std::cell::RefCell<Vec<&'static str>>=const{std::cell::RefCell::new(Vec::new())};
    static PV:std::cell::Cell<bool>=const{std::cell::Cell::new(false)};
    static CPU:std::cell::Cell<usize>=const{std::cell::Cell::new(0)};
    static SWITCH:std::cell::Cell<bool>=const{std::cell::Cell::new(false)};
}
fn event(value:&'static str){EVENTS.with(|v|v.borrow_mut().push(value));}
fn send_eoi(vector:u8){assert_eq!(vector,32);event("pic");}
mod performance {pub enum CounterMetric{TimerInterrupts}pub fn increment(_:CounterMetric,count:u64){assert_eq!(count,1);crate::event("metric");}}
mod hypervisor_guest {pub fn is_active()->bool{crate::PV.with(|v|v.get())}}
mod percpu {pub fn current_cpu_id()->usize{crate::CPU.with(|v|v.get())}}
mod smp {pub fn local_apic_eoi(){crate::event("lapic");}}
mod mem {pub mod gdt {pub fn user_code_selector()->u16{0x20}pub fn user_data_selector()->u16{0x18}}}
mod task {
    pub fn scheduler_tick(user:bool)->bool{crate::event(if user{"user-tick"}else{"kernel-tick"});crate::SWITCH.with(|v|v.get())}
    pub fn schedule_and_switch(){crate::event("switch-and-resume");}
}
mod syscall {
    pub mod syscall_entry {
        pub fn kpti_enter_for_trap(user:bool)->bool {crate::event(if user{"enter-user"}else{"enter-kernel"});user}
        pub fn kpti_leave_after_trap(user:bool){crate::event(if user{"leave-user"}else{"leave-kernel"});}
    }
    pub mod upcall {
        pub fn prepare_interrupt_return(frame:&mut[u64;20]){
            crate::event("prepare");
            if frame[16]&3==3 {frame[15]=0x5555;frame[8]=0xa7;}
        }
    }
}
mod actual {
    fn advance_clock(){crate::event("clock");}
"#,
    );
    program.push_str(&timer[start..end]);
    program.push_str(r#"
pub fn run(frame:&mut[u64;20],local:bool){handle_timer(frame,local)}
}
fn main(){
    for local in [false,true] {for pv in [false,true] {for cpu in [0,1] {
        for user in [false,true] {for schedule in [false,true] {
            EVENTS.with(|v|v.borrow_mut().clear());PV.with(|v|v.set(pv));CPU.with(|v|v.set(cpu));SWITCH.with(|v|v.set(schedule));
            let mut frame=core::array::from_fn::<_,20,_>(|i|0x1000+i as u64);
            frame[16]=if user{3}else{0};
            let original=frame;
            actual::run(&mut frame,local);
            let mut expected=vec![if user{"enter-user"}else{"enter-kernel"},"metric"];
            if !local || (pv&&cpu==0) {expected.push("clock")}
            expected.push(if user{"user-tick"}else{"kernel-tick"});
            expected.push(if local{"lapic"}else{"pic"});
            if schedule {expected.push("switch-and-resume")}
            expected.push("prepare");expected.push(if user{"leave-user"}else{"leave-kernel"});
            assert_eq!(EVENTS.with(|v|v.borrow().clone()),expected);
            let mut selected=original;
            if user {selected[16]=0x23;selected[19]=0x1b;selected[15]=0x5555;selected[8]=0xa7;}
            assert_eq!(frame,selected);
        }}
    }}}
}
"#);
    let directory =
        std::env::temp_dir().join(format!("mochios-timer-upcall-{}", std::process::id()));
    std::fs::create_dir(&directory).unwrap();
    let binary = directory.join("probe");
    let mut compiler = Command::new("rustc")
        .args(["--edition=2024", "-Awarnings", "-", "-o"])
        .arg(&binary)
        .stdin(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    compiler
        .stdin
        .take()
        .unwrap()
        .write_all(program.as_bytes())
        .unwrap();
    let output = compiler.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let output = Command::new(binary).output().unwrap();
    std::fs::remove_dir_all(directory).unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn both_idt_entries_share_the_full_gpr_frame_and_clear_direction_before_rust() {
    let timer = include_str!("../../../core/src/interrupt/timer.rs");
    let save = timer
        .split("core::arch::naked_asm!(")
        .nth(1)
        .unwrap()
        .split("mov rdi, rsp")
        .next()
        .unwrap();
    let restore = timer
        .split("mov rsp, rbx")
        .nth(1)
        .unwrap()
        .split("iretq")
        .next()
        .unwrap();
    let registers = [
        "rax", "rcx", "rdx", "rbx", "rbp", "rsi", "rdi", "r8", "r9", "r10", "r11", "r12", "r13",
        "r14", "r15",
    ];
    let mut last = 0;
    for name in registers {
        let at = save.find(&format!("push {name}\"")).unwrap();
        assert!(at >= last);
        last = at;
    }
    let mut last = 0;
    for name in registers.into_iter().rev() {
        let at = restore.find(&format!("pop {name}\"")).unwrap();
        assert!(at >= last);
        last = at;
    }
    assert!(timer.find("\"cld\"").unwrap() < timer.find("\"call {handle}\"").unwrap());
    let idt = include_str!("../../../core/src/interrupt/idt.rs");
    for name in ["timer_interrupt_handler", "local_timer_interrupt_handler"] {
        assert!(idt.contains(&format!("super::timer::{name} as *const () as u64")));
    }
}
