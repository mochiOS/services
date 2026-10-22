//! Placement hints do not create a userspace heap or reserve address ranges.
#[allow(dead_code)]
#[path = "support/native_error_probe.rs"]
mod probe;

#[test]
fn moving_the_native_cursor_cannot_change_accounted_mapping_bytes() {
    let source = include_str!("../../../core/src/task/process.rs");
    let mut program = String::from(
        r#"
struct Region(u64);
impl Region { fn len(&self) -> u64 { self.0 } }
struct Process {
    mapping_cursor: u64,
    stack_bottom: u64,
    stack_top: u64,
    memory_regions: Vec<Region>,
    dma_buffers: Vec<Region>,
}
impl Process {
"#,
    );
    program.push_str(probe::between(
        source,
        "    pub fn mapping_cursor(",
        "    pub fn dma_end(",
    ));
    program.push_str(probe::between(
        source,
        "    pub fn mapped_memory_bytes(",
        "    pub fn set_stack_bottom(",
    ));
    program.push_str(
        r#"
}
fn main() {
    let mut process = Process {
        mapping_cursor: 0,
        stack_bottom: 0x10000,
        stack_top: 0x11000,
        memory_regions: vec![Region(8192)],
        dma_buffers: vec![Region(4096)],
    };
    assert_eq!(process.mapping_cursor(), 0);
    for cursor in [4096, 0x80000000, 1 << 46, u64::MAX] {
        process.set_mapping_cursor(cursor);
        assert_eq!(process.mapping_cursor(), cursor);
        assert_eq!(process.mapped_memory_bytes(), 16384);
    }
    process.memory_regions.clear();
    assert_eq!(process.mapped_memory_bytes(), 8192);
    process.stack_top = process.stack_bottom;
    assert_eq!(process.mapped_memory_bytes(), 4096);
    process.dma_buffers.clear();
    assert_eq!(process.mapped_memory_bytes(), 0);
    process.memory_regions.push(Region(u64::MAX));
    process.dma_buffers.push(Region(4096));
    assert_eq!(process.mapped_memory_bytes(), u64::MAX);
}
"#,
    );
    probe::run(&program);
}

#[test]
fn native_placement_randomization_accepts_zero_entropy_pages_without_wrapping() {
    let source = include_str!("../../../core/src/syscall/process.rs");
    let mut program = String::from(
        r#"
mod task {
    pub struct ProcessId(pub u64);
    impl ProcessId { pub fn as_u64(&self) -> u64 { self.0 } }
}
mod cpu { pub fn boot_entropy_u64() -> u64 { 0xdead_beef } }
mod interrupt { pub mod timer { pub fn get_ticks() -> u64 { 99 } } }
"#,
    );
    program.push_str(probe::between(
        source,
        "#[inline]\nfn aslr_mix64(",
        "#[inline]\nfn page_align_up(",
    ));
    program.push_str(
        r#"
fn main() {
    for pid in [1, 77, u64::MAX] {
        assert_eq!(randomized_mapping_base(task::ProcessId(pid), 0x10000, 0), 0x10000);
        assert_eq!(randomized_mapping_base(task::ProcessId(pid), 0x10000, 1), 0x10000);
        let value = randomized_mapping_base(task::ProcessId(pid), 0x10000, 256);
        assert!(value >= 0x10000 && value < 0x110000);
        assert_eq!(value & 4095, 0);
        assert_eq!(randomized_mapping_base(task::ProcessId(pid), u64::MAX, u64::MAX), u64::MAX);
    }
}
"#,
    );
    probe::run(&program);
}

#[test]
fn kernel_images_have_no_program_break_or_implicit_heap_policy() {
    for source in [
        include_str!("../../../core/src/task/process.rs"),
        include_str!("../../../core/src/mem/address_space.rs"),
        include_str!("../../../core/src/syscall/process.rs"),
        include_str!("../../../core/src/syscall/exec.rs"),
        include_str!("../../../core/src/config.rs"),
        include_str!("../../../core/examples/fs/rootfs/config/kernel.conf"),
    ] {
        for removed in [
            "heap_start",
            "heap_end",
            "brk_heap",
            "heap_pre_mapped",
            "heap_map_size",
        ] {
            assert!(!source.contains(removed), "kernel retained {removed}");
        }
    }
    let exec = include_str!("../../../core/src/syscall/exec.rs");
    let replace = probe::between(exec, "fn replace_current_process_image(", "///");
    assert!(replace.contains("process.set_mapping_cursor(0)"));
    let runtime_heap = include_str!("../../../user/crates/newlib-runtime/src/heap.rs");
    assert!(runtime_heap.contains("memory_limit.map("));
    assert!(runtime_heap.contains("current_break"));
}
