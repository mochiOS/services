//! Execute the native sample's file self-test with controlled Handle I/O.
#[allow(dead_code)]
#[path = "support/native_error_probe.rs"]
mod probe;

#[test]
fn native_sample_checks_native_handle_failures_and_never_uses_failed_open_results() {
    let mut program = probe::program();
    program.push_str(
        r#"
use std::cell::RefCell;
use mnu_abi::status::Error;
const FS_TEST_SIZE:usize=64;
const INIT_FS_TEST_PATH:&str="/fixture";
static FS_TEST_WRITE_BUF:[u8;FS_TEST_SIZE]=[0x55;FS_TEST_SIZE];
static mut FS_TEST_READ_BUF:[u8;FS_TEST_SIZE]=[0;FS_TEST_SIZE];
struct State{
    first_open:u64,ro_open:u64,wo_open:u64,closed_error:u64,access_error:u64,
    opens:Vec<u64>,closes:Vec<u64>,writes:usize,reads:usize,seeks:usize,closed:bool,
}
impl Default for State{
    fn default()->Self{Self{
        first_open:37,ro_open:38,wo_open:39,closed_error:Error::InvalidArgument.into_raw(),
        access_error:Error::AccessDenied.into_raw(),
        opens:Vec::new(),closes:Vec::new(),writes:0,reads:0,seeks:0,closed:false,
    }}
}
thread_local!{static STATE:RefCell<State>=RefCell::new(State::default());}
fn file_open(path:&str,flags:u64)->u64 {
    assert_eq!(path,INIT_FS_TEST_PATH);
    STATE.with_borrow_mut(|s|{
        s.opens.push(flags);
        match s.opens.len(){
            1=>{assert_eq!(flags,0o2|0o100|0o1000);s.first_open},
            2=>{assert_eq!(flags,0);s.ro_open},
            3=>{assert_eq!(flags,0o1|0o100);s.wo_open},
            _=>panic!("unexpected repeated open"),
        }
    })
}
fn file_write(handle:u64,bytes:&[u8])->u64 {
    STATE.with_borrow_mut(|s|{
        s.writes+=1;
        match handle{
            37=>{assert!(!s.closed);assert_eq!(bytes,[0x55;FS_TEST_SIZE]);FS_TEST_SIZE as u64},
            38=>s.access_error,
            _=>panic!("a failed open result must not become an I/O handle"),
        }
    })
}
fn file_read(handle:u64,bytes:&mut[u8])->u64 {
    STATE.with_borrow_mut(|s|{
        s.reads+=1;
        match handle {
            37 if !s.closed=>{bytes.fill(0x55);FS_TEST_SIZE as u64},
            37=>s.closed_error,
            39=>s.access_error,
            _=>panic!("unexpected read"),
        }
    })
}
fn file_close(handle:u64)->u64 {
    STATE.with_borrow_mut(|s|{
        assert!(!s.closes.contains(&handle),"reference must not close twice");
        s.closes.push(handle);if handle==37{s.closed=true;}
    });0
}
fn file_seek(handle:u64,offset:u64,basis:u64)->u64 {
    assert_eq!((handle,offset,basis),(37,0,0));
    STATE.with_borrow_mut(|s|s.seeks+=1);0
}
fn get_ticks()->u64{1}
fn write_line(_:&str){}
fn format_line(_: &str,_:u64,_:u64,_:f64)->String{String::new()}
fn bytes_eq(a:&[u8],b:&[u8])->bool{a==b}
"#,
    );
    program.push_str(probe::between(
        include_str!("../../../core/examples/user/src/lib.rs"),
        "fn fileio_self_test(",
        "\nfn plugkit_ipc_self_test(",
    ));
    program.push_str(
        r#"
fn main(){
    assert!(fileio_self_test(),"native Handle failures are not POSIX FD errno");
    STATE.with_borrow(|s|{
        assert_eq!(s.closes,[37,38,39]);assert_eq!((s.writes,s.reads,s.seeks),(2,3,1));
    });
    for first_open in [
        0,u32::MAX as u64+1,Error::AccessDenied.into_raw(),
        Error::InvalidArgument.into_raw(),Error::ResourceUnavailable.into_raw(),
        Error::NotReady.into_raw(),Error::NotFound.into_raw(),
        (-9_i64) as u64,(-2_i64) as u64,(-5_i64) as u64,
    ]{
        STATE.set(State{first_open,..State::default()});
        assert!(!fileio_self_test());
        STATE.with_borrow(|s|{
            assert_eq!(s.opens.len(),1);assert!(s.closes.is_empty());
            assert_eq!((s.writes,s.reads,s.seeks),(0,0,0));
        });
    }
    for (closed_error,access_error) in [
        ((-9_i64) as u64,Error::AccessDenied.into_raw()),
        (Error::InvalidArgument.into_raw(),(-13_i64) as u64),
        (0,Error::AccessDenied.into_raw()),
    ]{
        STATE.set(State{closed_error,access_error,..State::default()});
        assert!(!fileio_self_test(),"legacy/error-shaped values cannot prove native enforcement");
    }
    for raw in [0,u32::MAX as u64+1,Error::AccessDenied.into_raw(),(-2_i64) as u64]{
        for readonly in [false,true]{
            STATE.set(if readonly{State{ro_open:raw,..State::default()}}
                else{State{wo_open:raw,..State::default()}});
            assert!(!fileio_self_test());
            STATE.with_borrow(|s|{
                assert_eq!(s.opens.len(),if readonly{2}else{3});
                assert_eq!(s.closes,if readonly{vec![37]}else{vec![37,38]});
            });
        }
    }
}
"#,
    );
    probe::run(&program);
}
