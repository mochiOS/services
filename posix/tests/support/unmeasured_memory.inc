// CPU/lifecycle fixtures do not model VM roots. An unmeasured memory source
// must remain unavailable; these fixtures never claim successful RAM metrics.
mod mem {
    pub mod residency {
        pub struct Snapshot { pub current_bytes: u64, pub peak_bytes: u64 }
    }
    pub mod residency_native {
        #[derive(Debug)]
        pub struct ProcessStats;
        impl ProcessStats {
            pub fn new() -> Self { Self }
            pub fn snapshot(&self) -> Option<super::residency::Snapshot> { None }
        }
    }
}
