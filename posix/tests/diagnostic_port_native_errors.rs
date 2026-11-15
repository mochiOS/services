#[allow(dead_code)]
#[path = "support/native_error_probe.rs"]
mod probe;

#[test]
fn diagnostic_and_port_entries_fail_natively_before_output_or_hardware_access() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap();
    let mut program = format!(
        r#"
#![allow(dead_code)]
extern crate self as mnu_abi;
#[path={status:?}] pub mod status;
#[path={arm_ports:?}] mod arm_ports;
use status::Error;
use capability::Capability;
use util::console;
use std::cell::{{Cell, RefCell}};
use core::fmt;
use core::fmt::Write;
const SUCCESS:u64=0;
thread_local! {{
    static ALLOWED:Cell<bool>=const{{Cell::new(true)}};
    static NATIVE_PORTS:Cell<bool>=const{{Cell::new(true)}};
    static PORTS:Cell<usize>=const{{Cell::new(0)}};
    static INPUT:RefCell<Vec<u8>>=const{{RefCell::new(Vec::new())}};
    static OUTPUT:RefCell<Vec<u8>>=const{{RefCell::new(Vec::new())}};
    static COPIES:Cell<usize>=const{{Cell::new(0)}};
    static COPY_ERROR:Cell<Option<Error>>=const{{Cell::new(None)}};
    static IRQS_OFF:Cell<bool>=const{{Cell::new(false)}};
    static LIMIT:Cell<usize>=const{{Cell::new(usize::MAX)}};
    static YIELDS:Cell<usize>=const{{Cell::new(0)}};
    static HYPER_OUTPUT:RefCell<Vec<u8>>=const{{RefCell::new(Vec::new())}};
    static HYPER_FAIL:Cell<bool>=const{{Cell::new(false)}};
    static HYPER_CALLS:Cell<usize>=const{{Cell::new(0)}};
}}
mod capability {{
    #[derive(Debug,PartialEq)] pub enum Capability{{KernelDebug}}
    pub enum KernelCapability{{PortIo}}
    pub enum KernelObjectRef{{IoPortRange{{base:u64,size:u64}}}}
    pub struct KernelAuthority{{pub object:KernelObjectRef}}
    impl KernelAuthority{{pub fn new(_:KernelCapability,object:KernelObjectRef)->Self{{Self{{object}}}}}}
}}
mod task {{
    pub fn yield_now(){{assert!(!crate::IRQS_OFF.get());crate::YIELDS.set(crate::YIELDS.get()+1);}}
    pub fn process_has_kernel_authority(pid:u64,authority:&crate::capability::KernelAuthority)->bool{{
        assert_eq!(pid,7);
        let crate::capability::KernelObjectRef::IoPortRange{{base,size}}=authority.object;
        assert!(matches!(size,1|2|4)&&base+size<=65536);
        crate::ALLOWED.get()
    }}
}}
mod syscall {{
    pub mod security {{
        pub fn current_process_id()->Option<u64>{{Some(7)}}
        pub fn caller_has_any_capability(caps:&[crate::Capability])->bool{{
            assert_eq!(caps,&[crate::Capability::KernelDebug]);crate::ALLOWED.get()
        }}
    }}
    pub fn copy_from_user_native(pointer:u64,bytes:&mut[u8])->Result<(),crate::Error>{{
        assert!(!crate::IRQS_OFF.get());crate::COPIES.set(crate::COPIES.get()+1);
        if let Some(error)=crate::COPY_ERROR.get(){{return Err(error);}}
        crate::INPUT.with_borrow(|input|bytes.copy_from_slice(&input[pointer as usize-1..pointer as usize-1+bytes.len()]));
        Ok(())
    }}
}}
mod arch {{
    pub mod memory {{pub struct VirtAddr(pub u64);impl VirtAddr{{pub fn new(value:u64)->Self{{Self(value)}}}}}}
    pub mod interrupts {{pub fn without_interrupts<R>(f:impl FnOnce()->R)->R{{
        assert!(!crate::IRQS_OFF.replace(true));let result=f();assert!(crate::IRQS_OFF.replace(false));result
    }}}}
    pub mod port_io {{
        pub unsafe fn read(port:u16,width:u64)->Result<u64,crate::Error>{{
            assert!(crate::ALLOWED.get());
            if !crate::NATIVE_PORTS.get(){{return unsafe{{crate::arm_ports::read(port,width)}};}}
            crate::PORTS.set(crate::PORTS.get()+1);Ok(match width{{1=>0x78,2=>0x5678,4=>0x12345678,_=>panic!()}})
        }}
        pub unsafe fn write(port:u16,value:u64,width:u64)->Result<(),crate::Error>{{
            assert!(crate::ALLOWED.get());assert_eq!(value,0x12345678);
            if !crate::NATIVE_PORTS.get(){{return unsafe{{crate::arm_ports::write(port,value,width)}};}}
            assert!(matches!(width,1|2|4));crate::PORTS.set(crate::PORTS.get()+1);Ok(())
        }}
    }}
}}
mod mem {{pub mod paging {{
    pub struct Physical(pub u64);impl Physical{{pub fn as_u64(&self)->u64{{self.0}}}}
    pub fn translate_addr(address:crate::arch::memory::VirtAddr)->Option<Physical>{{Some(Physical(address.0))}}
}}}}
mod hypervisor_guest {{
    pub fn is_active()->bool{{false}}
    pub fn invoke(_:crate::hypervisor::HypercallNumber,address:u64,length:u64,reserved:u64)->u64{{
        assert_eq!(reserved,0);assert!(length>0&&length<=1024);
        assert!(address%4096+length<=4096);crate::HYPER_CALLS.set(crate::HYPER_CALLS.get()+1);
        if crate::HYPER_FAIL.get(){{return u64::MAX;}}
        // Only the actual writer's retained stack buffer reaches this mock transport.
        let bytes=unsafe{{std::slice::from_raw_parts(address as *const u8,length as usize)}};
        crate::HYPER_OUTPUT.with_borrow_mut(|out|out.extend_from_slice(bytes));0
    }}
}}
mod hypervisor {{pub const HYPERCALL_SUCCESS:u64=0;pub enum HypercallNumber{{ConsoleWrite}}}}
mod util {{pub mod console {{
    pub struct Serial;
    impl Serial {{pub fn try_send_byte(&mut self,byte:u8)->bool{{
        assert!(crate::IRQS_OFF.get());
        crate::OUTPUT.with_borrow_mut(|out|{{if out.len()>=crate::LIMIT.get(){{false}}else{{out.push(byte);true}}}})
    }}}}
    pub struct SerialLock;pub static SERIAL:SerialLock=SerialLock;
    impl SerialLock{{pub fn try_lock(&self)->Option<Serial>{{assert!(crate::IRQS_OFF.get());Some(Serial)}}}}
    @DIRECT@
}}}}
"#,
        status = root.join("core/crates/abi/src/status.rs"),
        arm_ports = root.join("core/src/arch/aarch64/port_io.rs")
    );
    let source = include_str!("../../../core/src/syscall/io.rs");
    program = program.replace(
        "@DIRECT@",
        probe::between(
            include_str!("../../../core/src/util/console.rs"),
            "pub fn try_write_direct(",
            "struct HypervisorConsole",
        ),
    );
    program.push_str(&source[source.find("fn caller_has_port_io_access(").unwrap()..]);
    program.push_str(probe::between(
        include_str!("../../../core/src/util/console.rs"),
        "struct HypervisorConsole",
        "/// シリアル出力マクロ",
    ));
    program.push_str(r#"
fn reset(input:&[u8]){
    ALLOWED.set(true);INPUT.with_borrow_mut(|value|*value=input.to_vec());
    OUTPUT.with_borrow_mut(Vec::clear);COPIES.set(0);COPY_ERROR.set(None);
    LIMIT.set(usize::MAX);YIELDS.set(0);
}
fn main(){
    let text="x".repeat(8193);let mut writer=HypervisorConsole::new();
    writer.write_str(&text).unwrap();writer.flush().unwrap();
    assert_eq!(HYPER_OUTPUT.with_borrow(Clone::clone),text.as_bytes());
    assert!(HYPER_CALLS.get()>=9);assert_eq!(writer.len,0);
    HYPER_FAIL.set(true);HYPER_OUTPUT.with_borrow_mut(Vec::clear);
    let mut writer=HypervisorConsole::new();writer.write_str("failure").unwrap();
    assert_eq!(writer.flush(),Err(Error::BackingFailure));
    assert!(HYPER_OUTPUT.with_borrow(|out|out.is_empty()));HYPER_FAIL.set(false);
    reset(b"abc");assert_eq!(debug_write(1,3),3);assert_eq!(COPIES.get(),1);
    assert_eq!(OUTPUT.with_borrow(Clone::clone),b"abc");
    reset(&[0xff,0]);assert_eq!(debug_write(1,2),2);
    assert_eq!(OUTPUT.with_borrow(Clone::clone),[0xff,0]);
    reset(&[]);assert_eq!(debug_write(0,0),0);assert_eq!(COPIES.get(),0);
    for (pointer,length,error) in [(0,1,Error::InvalidAddress),(u64::MAX,1,Error::InvalidAddress),(1,4097,Error::LimitExceeded)]{
        reset(&[]);assert_eq!(debug_write(pointer,length),error.into_raw());
        assert_eq!(COPIES.get(),0);assert!(OUTPUT.with_borrow(|out|out.is_empty()));
    }
    for error in [Error::InvalidAddress,Error::NotReady,Error::BackingFailure,Error::ResourceUnavailable]{
        reset(b"abc");COPY_ERROR.set(Some(error));assert_eq!(debug_write(1,3),error.into_raw());
        assert_eq!(COPIES.get(),1);assert!(OUTPUT.with_borrow(|out|out.is_empty()));
    }
    reset(b"abc");ALLOWED.set(false);assert_eq!(debug_write(1,3),Error::AccessDenied.into_raw());
    assert_eq!(COPIES.get(),0);assert!(OUTPUT.with_borrow(|out|out.is_empty()));
    reset(&[0x61;64]);LIMIT.set(35);assert_eq!(debug_write(1,64),35);
    assert_eq!(OUTPUT.with_borrow(Vec::len),35);assert_eq!(YIELDS.get(),1);
    reset(b"abc");LIMIT.set(0);assert_eq!(debug_write(1,3),Error::NotReady.into_raw());
    for native in [false,true]{NATIVE_PORTS.set(native);for allowed in [false,true]{ALLOWED.set(allowed);
        for width in [0,1,2,3,4,8]{for port in [0x1234,65532,65534,65535,65536,u64::MAX]{
            let before=PORTS.get();let input=port_in(port,width);let output=port_out(port,0x12345678,width);
            let admitted=allowed&&matches!(width,1|2|4)&&port.checked_add(width).is_some_and(|end|end<=65536);
            if !admitted{assert_eq!(input,Error::AccessDenied.into_raw());assert_eq!(output,input);assert_eq!(PORTS.get(),before);}
            else if !native{assert_eq!(input,Error::Unsupported.into_raw());assert_eq!(output,input);assert_eq!(PORTS.get(),before);}
            else{assert_eq!(input,match width{1=>0x78,2=>0x5678,_=>0x12345678});assert_eq!(output,0);assert_eq!(PORTS.get(),before+2);}
        }}
    }}
}
"#);
    probe::run(&program);
}
