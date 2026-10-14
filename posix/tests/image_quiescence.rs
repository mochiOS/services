use std::io::Write;
use std::process::{Command, Stdio};

fn item<'a>(source: &'a str, declaration: &str) -> &'a str {
    let start = source.find(declaration).unwrap();
    let body = start + source[start..].find('{').unwrap();
    let mut depth = 0;
    for (offset, byte) in source[body..].bytes().enumerate() {
        match byte {
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    return &source[start..body + offset + 1];
                }
            }
            _ => {}
        }
    }
    panic!("unterminated {declaration}")
}

#[test]
fn production_image_holds_wait_for_cpu_handoff_and_preserve_other_stop_reasons() {
    let threads = include_str!("../../../core/src/task/thread.rs");
    let scheduler = include_str!("../../../core/src/task/scheduler.rs");
    let thread_ops = [
        "pub fn suspend(&mut self)",
        "pub fn resume(&mut self)",
        "pub fn is_scheduling_suspended(&self)",
    ]
    .map(|name| item(threads, name))
    .join("\n");
    let queue_ops = [
        "pub(super) fn hold_image_siblings(",
        "pub(super) fn release_image_hold(",
        "pub fn suspend_process(",
        "pub fn resume_process(",
    ]
    .map(|name| item(threads, name))
    .join("\n");
    let scheduler_ops = [
        "pub(crate) struct ImageQuiescence {",
        "pub(crate) fn quiesce_image_siblings(",
        "impl Drop for ImageQuiescence {",
    ]
    .map(|name| item(scheduler, name))
    .join("\n");
    // Compile the actual production hold, resume and quiescence code. Only
    // scheduler CPU handoff and unrelated Thread/queue fields are controlled.
    let program = format!(
        r#"
#![allow(dead_code)]
use std::sync::{{Mutex, MutexGuard, OnceLock}};
use std::sync::atomic::{{AtomicU64, AtomicUsize, Ordering}};
static REFERENCES:AtomicU64=AtomicU64::new(0);
static YIELDS:AtomicUsize=AtomicUsize::new(0);
mod percpu {{ pub fn thread_is_cpu_referenced(id:u64)->bool {{
    super::REFERENCES.load(super::Ordering::SeqCst) & (1 << id) != 0
}} }}
mod task {{
    use super::*;
    pub type ProcessId=u64;
    #[derive(Clone, Copy, PartialEq, Eq, Debug)] pub struct ThreadId(pub u64);
    impl ThreadId {{ pub fn as_u64(&self)->u64 {{ self.0 }} }}
    #[derive(Clone, Copy, PartialEq, Eq)] pub enum ThreadState {{ Ready, Running, Blocked, Terminated }}
    pub struct Thread {{ id:ThreadId, process:u64, pub state:ThreadState,
        pub scheduling_suspended:bool, pub image_held:bool }}
    impl Thread {{
        pub fn id(&self)->ThreadId {{ self.id }}
        pub fn process_id(&self)->u64 {{ self.process }}
        pub fn state(&self)->ThreadState {{ self.state }}
        {thread_ops}
    }}
    pub struct ThreadQueue {{ pub threads:[Option<Thread>;6],pub ready_bitmap:u64 }}
    impl ThreadQueue {{
        pub const MAX_THREADS:usize=6;
        pub fn slot_index(&self,id:ThreadId)->Option<usize> {{
            self.threads.iter().position(|thread|thread.as_ref().is_some_and(|thread|thread.id()==id))
        }}
        {queue_ops}
    }}
    pub mod thread {{ pub type ThreadQueue=super::ThreadQueue; }}
    static QUEUE:OnceLock<Mutex<ThreadQueue>>=OnceLock::new();
    pub struct GlobalQueue;
    impl GlobalQueue {{ pub fn lock(&self)->MutexGuard<'_,ThreadQueue> {{ QUEUE.get().unwrap().lock().unwrap() }} }}
    pub static THREAD_QUEUE:GlobalQueue=GlobalQueue;
    pub fn reset() {{
        let make=|id,process,state|Some(Thread{{id:ThreadId(id),process,state,scheduling_suspended:false,image_held:false}});
        let queue=ThreadQueue{{threads:[make(1,7,ThreadState::Running),make(2,7,ThreadState::Ready),
            make(3,9,ThreadState::Ready),make(4,7,ThreadState::Blocked),make(5,7,ThreadState::Terminated),None],ready_bitmap:6}};
        if let Some(current)=QUEUE.get() {{ *current.lock().unwrap()=queue; }} else {{ let _=QUEUE.set(Mutex::new(queue)); }}
    }}
    pub mod scheduler {{
        use super::{{ThreadId,THREAD_QUEUE}};
        fn yield_now() {{
            let queue=THREAD_QUEUE.lock();
            assert!(!queue.threads[0].as_ref().unwrap().image_held);
            assert!(!queue.threads[2].as_ref().unwrap().image_held);
            for slot in [1,3,4] {{ assert!(queue.threads[slot].as_ref().unwrap().image_held); }}
            super::super::REFERENCES.store(0,super::super::Ordering::SeqCst);
            super::super::YIELDS.fetch_add(1,super::super::Ordering::Relaxed);
        }}
        {scheduler_ops}
    }}
}}
use task::*;
fn main() {{
    for mode in 0..4 {{
        reset();
        REFERENCES.store(if mode==0 {{ (1<<2)|(1<<5) }} else {{ 1<<5 }},Ordering::SeqCst);
        YIELDS.store(0,Ordering::Relaxed);
        if mode==1 {{ THREAD_QUEUE.lock().suspend_process(7); }}
        let hold=scheduler::quiesce_image_siblings(7,ThreadId(1));
        assert_eq!(YIELDS.load(Ordering::Relaxed),1); // includes terminated CPU handoff
        {{
            let mut queue=THREAD_QUEUE.lock();
            assert_eq!(queue.ready_bitmap,4);
            if mode==1 {{ queue.resume_process(7); assert_eq!(queue.ready_bitmap,4); }}
            if mode==2 {{ queue.suspend_process(7); }}
            if mode==3 {{ queue.threads[3].as_mut().unwrap().state=ThreadState::Ready; }}
        }}
        drop(hold);
        let queue=THREAD_QUEUE.lock();
        assert!(!queue.threads[1].as_ref().unwrap().image_held);
        assert_eq!(queue.ready_bitmap,match mode {{ 2=>4,3=>14,_=>6 }});
        assert_eq!(queue.threads[1].as_ref().unwrap().scheduling_suspended,mode==2);
    }}
    reset();
    REFERENCES.store(0,Ordering::SeqCst);
    let failed:Result<(),()>=(||{{let _hold=scheduler::quiesce_image_siblings(7,ThreadId(1));Err(())}})();
    assert_eq!(failed,Err(()));
    assert_eq!(THREAD_QUEUE.lock().ready_bitmap,6);
}}
"#
    );
    let directory =
        std::env::temp_dir().join(format!("mochios-image-quiescence-{}", std::process::id()));
    std::fs::create_dir(&directory).unwrap();
    let executable = directory.join("probe");
    let mut compile = Command::new("rustc")
        .args(["--edition=2024", "--crate-name=image_quiescence", "-", "-o"])
        .arg(&executable)
        .stdin(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    compile
        .stdin
        .take()
        .unwrap()
        .write_all(program.as_bytes())
        .unwrap();
    let result = compile.wait_with_output().unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let executed = Command::new(executable).output().unwrap();
    std::fs::remove_dir_all(directory).unwrap();
    assert!(
        executed.status.success(),
        "{}",
        String::from_utf8_lossy(&executed.stderr)
    );
}
