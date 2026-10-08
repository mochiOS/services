use std::cell::Cell;
use std::time::Duration;

std::thread_local! {
    static THREAD_VALUE: Cell<u32> = const { Cell::new(0) };
}

fn main() {
    THREAD_VALUE.set(7);
    let child = std::thread::spawn(|| {
        assert_eq!(THREAD_VALUE.get(), 0);
        THREAD_VALUE.set(41);
        std::thread::sleep(Duration::from_millis(2));
        THREAD_VALUE.get() + 1
    });

    assert_eq!(child.join().expect("child thread panicked"), 42);
    assert_eq!(THREAD_VALUE.get(), 7);
    println!("rust-thread-lifecycle: pass");
}
