use std::collections::BTreeMap;
use std::sync::{LazyLock, Mutex, MutexGuard};

const BASE: u64 = 0x10000;
const KSTACK_PAGE_BYTES: usize = 4096;
const KSTACK_SLOT_RESERVED: u8 = 255;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct KernelStackSlot {
    user_page_table: u64,
    requested_bytes: u32,
    mapped_pages: u8,
    sampled: bool,
}
const ORIGINAL: KernelStackSlot = KernelStackSlot {
    user_page_table: 4096,
    requested_bytes: 12288,
    mapped_pages: 3,
    sampled: true,
};
struct Spin<T>(Mutex<T>);
impl<T> Spin<T> {
    const fn new(value: T) -> Self {
        Self(Mutex::new(value))
    }
    fn lock(&self) -> MutexGuard<'_, T> {
        self.0.lock().unwrap()
    }
}
static KSTACK_SLOTS: Spin<[KernelStackSlot; 1]> = Spin::new([ORIGINAL]);
static SERIAL: Mutex<()> = Mutex::new(());
#[derive(Default)]
struct Backend {
    maps: BTreeMap<(u64, u64), u64>,
    fail_map: Option<u64>,
    fail_translate: Option<u64>,
    detached: Vec<u64>,
}
static BACKEND: LazyLock<Mutex<Backend>> = LazyLock::new(|| Mutex::new(Backend::default()));
#[derive(Clone, Copy)]
struct VirtAddr(u64);
impl VirtAddr {
    fn new(address: u64) -> Self {
        Self(address)
    }
}
struct Physical(u64);
impl Physical {
    fn as_u64(&self) -> u64 {
        self.0
    }
}
mod mem {
    pub mod paging {
        pub(crate) fn translate_addr(address: crate::VirtAddr) -> Option<crate::Physical> {
            (crate::BACKEND.lock().unwrap().fail_translate != Some(address.0))
                .then_some(crate::Physical(address.0 + 0x100000))
        }
    }
}
mod audit {
    pub enum AuditEventKind {
        Quarantine,
    }
    pub fn log(_: AuditEventKind, _: &str) {
        panic!("unexpected quarantine");
    }
}
fn stack_slot_index(base: u64) -> Option<usize> {
    (base == BASE).then_some(0)
}
fn map_stack_page_in_user_table(table: u64, address: u64, physical: u64) -> bool {
    let mut backend = BACKEND.lock().unwrap();
    if backend.fail_map == Some(address) {
        return false;
    }
    assert!(backend.maps.insert((table, address), physical).is_none());
    true
}
fn unmap_stack_from_table(table: u64, base: u64, count: usize) -> bool {
    let mut backend = BACKEND.lock().unwrap();
    backend.detached.push(table);
    for index in 0..count {
        assert!(
            backend
                .maps
                .remove(&(table, base + index as u64 * 4096))
                .is_some()
        );
    }
    true
}
#[path = "../../../core/src/task/thread/stack_image.rs"]
mod production;

fn reset() -> MutexGuard<'static, ()> {
    let serial = SERIAL.lock().unwrap();
    *KSTACK_SLOTS.lock() = [ORIGINAL];
    let mut backend = BACKEND.lock().unwrap();
    *backend = Backend::default();
    for index in 0..3 {
        backend
            .maps
            .insert((4096, BASE + index * 4096), BASE + index * 4096 + 0x100000);
    }
    serial
}
fn assert_original() {
    assert_eq!(KSTACK_SLOTS.lock()[0], ORIGINAL);
    let backend = BACKEND.lock().unwrap();
    assert_eq!(backend.maps.len(), 3);
    assert!(backend.maps.keys().all(|&(table, _)| table == 4096));
    assert!(!backend.detached.contains(&4096));
}

#[test]
fn partial_mapping_and_translation_failures_never_detach_the_running_stack() {
    for mode in 0..2 {
        for page in 0..3 {
            let _serial = reset();
            {
                let mut backend = BACKEND.lock().unwrap();
                let address = Some(BASE + page * 4096);
                if mode == 0 {
                    backend.fail_map = address;
                } else {
                    backend.fail_translate = address;
                }
            }
            assert!(production::prepare_kernel_stack_user_table(BASE, 8192).is_none());
            assert_original();
        }
    }
}

#[test]
fn later_preparation_failure_drops_only_the_new_alias_and_restores_stack_ownership() {
    let _serial = reset();
    let failed: Result<(), u64> = (|| {
        let _prepared = production::prepare_kernel_stack_user_table(BASE, 8192).unwrap();
        assert_eq!(KSTACK_SLOTS.lock()[0].user_page_table, 4096);
        assert_eq!(KSTACK_SLOTS.lock()[0].mapped_pages, KSTACK_SLOT_RESERVED);
        assert_eq!(BACKEND.lock().unwrap().maps.len(), 6);
        Err(mnu_abi::status::Error::BackingFailure.into_raw()) // A borrowed-PTE transaction can still fail here.
    })();
    assert_eq!(failed, Err(mnu_abi::status::Error::BackingFailure.into_raw()));
    assert_original();
}

#[test]
fn commit_alone_detaches_old_aliases_and_publishes_new_owner() {
    let _serial = reset();
    let prepared = production::prepare_kernel_stack_user_table(BASE, 8192).unwrap();
    assert!(!BACKEND.lock().unwrap().detached.contains(&4096));
    prepared.commit();
    assert_eq!(
        KSTACK_SLOTS.lock()[0],
        KernelStackSlot {
            user_page_table: 8192,
            ..ORIGINAL
        }
    );
    let backend = BACKEND.lock().unwrap();
    assert_eq!(backend.maps.len(), 3);
    assert!(backend.maps.keys().all(|&(table, _)| table == 8192));
    assert_eq!(backend.detached, [4096]);
}

#[test]
fn invalid_or_busy_stack_targets_leave_ownership_and_mappings_unchanged() {
    let _serial = reset();
    for (base, target) in [(BASE, 0), (BASE, 8193), (BASE, 4096), (BASE + 1, 8192)] {
        assert!(production::prepare_kernel_stack_user_table(base, target).is_none());
        assert_original();
    }
    KSTACK_SLOTS.lock()[0].mapped_pages = KSTACK_SLOT_RESERVED;
    assert!(production::prepare_kernel_stack_user_table(BASE, 8192).is_none());
}

#[test]
fn exec_completes_fallible_revocation_under_reversible_quiescence_before_retirement() {
    let source = include_str!("../../../core/src/syscall/exec.rs");
    let body = source
        .split("fn replace_current_process_image(")
        .nth(1)
        .unwrap()
        .split("pub fn process_image_replace_syscall(")
        .next()
        .unwrap();
    let prepare = body.find("prepare_kernel_stack_user_table(").unwrap();
    let hold = body
        .find("quiesce_image_siblings(pid, current_tid)")
        .unwrap();
    let release = body
        .find("release_process_borrowed_mappings(pid)?")
        .unwrap();
    let retire = body
        .find("retire_image_siblings(pid, current_tid)")
        .unwrap();
    let stack_commit = body.find("stack_mapping.commit()").unwrap();
    let image_commit = body.find("process.set_page_table(new_pt_phys)").unwrap();
    let resume = body.find("drop(quiescence)").unwrap();
    assert!(
        prepare < hold
            && hold < release
            && release < retire
            && retire < stack_commit
            && stack_commit < image_commit
            && image_commit < resume
    );
    assert!(!body[retire..].contains("return Err("));
}
