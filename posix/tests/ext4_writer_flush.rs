//! Compile the actual writer trait for each sync/async and Rc/Arc variant.
#![allow(dead_code)]
extern crate alloc;
mod error {
    pub type BoxedError = Box<dyn std::error::Error + Send + Sync>;
}
#[path = "../../../services/third_party/ext4plus/src/writer.rs"]
mod writer;
use std::sync::atomic::{AtomicUsize, Ordering};
use writer::Ext4Write;

struct Counter(AtomicUsize);

#[cfg_attr(
    all(not(feature = "sync"), feature = "multi-threaded"),
    async_trait::async_trait
)]
#[cfg_attr(all(not(feature = "sync"), not(feature = "multi-threaded")), async_trait::async_trait(?Send))]
impl Ext4Write for Counter {
    #[cfg(feature = "sync")]
    fn write(&self, _: u64, _: &[u8]) -> Result<(), error::BoxedError> {
        Ok(())
    }
    #[cfg(not(feature = "sync"))]
    async fn write(&self, _: u64, _: &[u8]) -> Result<(), error::BoxedError> {
        Ok(())
    }
    #[cfg(feature = "sync")]
    fn flush(&self) -> Result<(), error::BoxedError> {
        self.0.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }
    #[cfg(not(feature = "sync"))]
    async fn flush(&self) -> Result<(), error::BoxedError> {
        self.0.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }
}

struct WriteOnly;
#[cfg_attr(
    all(not(feature = "sync"), feature = "multi-threaded"),
    async_trait::async_trait
)]
#[cfg_attr(all(not(feature = "sync"), not(feature = "multi-threaded")), async_trait::async_trait(?Send))]
impl Ext4Write for WriteOnly {
    #[cfg(feature = "sync")]
    fn write(&self, _: u64, _: &[u8]) -> Result<(), error::BoxedError> {
        Ok(())
    }
    #[cfg(not(feature = "sync"))]
    async fn write(&self, _: u64, _: &[u8]) -> Result<(), error::BoxedError> {
        Ok(())
    }
}

#[cfg(not(feature = "sync"))]
fn complete<T>(future: impl std::future::Future<Output = T>) -> T {
    let mut future = std::pin::pin!(future);
    let mut context = std::task::Context::from_waker(std::task::Waker::noop());
    match future.as_mut().poll(&mut context) {
        std::task::Poll::Ready(value) => value,
        std::task::Poll::Pending => panic!("memory-only test barrier should complete immediately"),
    }
}

#[test]
fn missing_barrier_is_an_error_not_an_implicit_success() {
    #[cfg(feature = "sync")]
    assert!(WriteOnly.flush().is_err());
    #[cfg(not(feature = "sync"))]
    assert!(complete(WriteOnly.flush()).is_err());
}

#[test]
fn shared_writer_delegates_each_flush_to_the_actual_backend() {
    #[cfg(feature = "multi-threaded")]
    let writer = std::sync::Arc::new(Counter(AtomicUsize::new(0)));
    #[cfg(not(feature = "multi-threaded"))]
    let writer = std::rc::Rc::new(Counter(AtomicUsize::new(0)));
    for expected in 1..=3 {
        #[cfg(feature = "sync")]
        writer.flush().unwrap();
        #[cfg(not(feature = "sync"))]
        complete(writer.flush()).unwrap();
        assert_eq!(writer.0.load(Ordering::Relaxed), expected);
    }
}

#[test]
fn ipc_sync_paths_do_not_flush_a_hardcoded_data_partition() {
    let source = include_str!("../../../services/filesystem/src/main.rs");
    let provider = source
        .split("fn handle_provider_request(")
        .nth(1)
        .unwrap()
        .split("\n}\n")
        .next()
        .unwrap();
    assert!(!provider.contains("partition"));
    assert!(provider.contains(".provider_sync(header.object_id)"));
    assert!(source.contains("protocol::OP_SYNC_HANDLE => service.sync_handle(header, open_id)"));
    assert!(!source.contains("&& partition.flush()"));
}
