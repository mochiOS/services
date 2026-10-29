use mochios_posix_client::elf_mapping::{Backend, Error, Installation, Phase, Plan, Range};
use std::{
    cell::{Cell, RefCell},
    rc::Rc,
};
#[path = "support/interpreter_fixture.rs"]
mod fixture;
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[path = "support/elf_mapping_vm.rs"]
mod vm;

#[derive(Default)]
struct State {
    calls: usize,
    fail: Vec<usize>,
    retained: Option<Range>,
    populated: Vec<Range>,
    writes: Vec<(u64, Vec<u8>)>,
    permissions: Vec<(Range, u64)>,
    released: Vec<Range>,
}
thread_local! { static CRITICAL: Cell<u32> = const {Cell::new(0)}; }
#[derive(Clone)]
struct Mock(Rc<RefCell<State>>);
impl Mock {
    fn operation(&self) -> Result<(), usize> {
        let mut s = self.0.borrow_mut();
        s.calls += 1;
        if s.fail.contains(&s.calls) {
            Err(s.calls)
        } else {
            Ok(())
        }
    }
}
impl Backend for Mock {
    type Error = usize;
    fn critical<T>(f: impl FnOnce() -> T) -> T {
        CRITICAL.set(CRITICAL.get() + 1);
        let r = f();
        CRITICAL.set(CRITICAL.get() - 1);
        r
    }
    fn reserve(&self, range: Range) -> Result<(), usize> {
        assert!(CRITICAL.get() > 0);
        self.operation()?;
        assert!(self.0.borrow_mut().retained.replace(range).is_none());
        Ok(())
    }
    fn populate(&self, range: Range) -> Result<(), usize> {
        assert_eq!(CRITICAL.get(), 0);
        let owned = self.0.borrow().retained.unwrap();
        assert!(
            range.address >= owned.address
                && range.address + range.length <= owned.address + owned.length
        );
        self.0.borrow_mut().populated.push(range);
        self.operation()
    }
    fn write(&self, address: u64, bytes: &[u8]) -> Result<(), usize> {
        assert_eq!(CRITICAL.get(), 0);
        assert!(
            self.0.borrow().permissions.is_empty(),
            "no executable page before all LOAD bytes are present"
        );
        self.0.borrow_mut().writes.push((address, bytes.to_vec()));
        self.operation()
    }
    fn protect(&self, range: Range, access: u64) -> Result<(), usize> {
        assert_ne!(access & 6, 6);
        self.0.borrow_mut().permissions.push((range, access));
        self.operation()
    }
    fn release(&self, range: Range) -> Result<(), usize> {
        assert!(CRITICAL.get() > 0);
        self.operation()?;
        let mut s = self.0.borrow_mut();
        assert_eq!(s.retained.take(), Some(range));
        s.released.push(range);
        Ok(())
    }
}
fn mock(fail: Vec<usize>) -> (Mock, Rc<RefCell<State>>) {
    let state = Rc::new(RefCell::new(State {
        fail,
        ..Default::default()
    }));
    (Mock(state.clone()), state)
}

#[test]
fn reserves_full_span_and_keeps_holes_inaccessible_until_all_loads_are_ready() {
    let mut source = fixture::image(false, false, true);
    fixture::put64(&mut source, 24, 0x2000);
    assert!(mochios_posix_client::elf_launch::Image::parse(&source).is_err());
    let plan = Plan::new(&source, 0x20000000).unwrap();
    assert_eq!(
        plan.range(),
        Range {
            address: 0x20000000,
            length: 0x103000
        }
    );
    let (backend, state) = mock(vec![]);
    let mut owner = Installation::new(backend);
    assert_eq!(owner.seal(), Err(Error::State));
    owner.stage(plan).unwrap();
    assert_eq!(owner.phase(), Phase::Staged);
    assert_eq!(owner.retained(), Some(plan.range()));
    assert_eq!(owner.stage(plan), Err(Error::State));
    owner.seal().unwrap();
    assert_eq!(owner.phase(), Phase::Sealed);
    assert_eq!(owner.seal(), Err(Error::State));
    state
        .borrow()
        .populated
        .iter()
        .for_each(|r| assert!(r.address == 0x20000000 || r.address == 0x20003000));
    assert_eq!(
        state.borrow().writes,
        [
            (0x20000000, source[..0x1200].to_vec()),
            (0x20003000, source[0x2000..0x2100].to_vec())
        ]
    );
    assert_eq!(
        state
            .borrow()
            .permissions
            .iter()
            .map(|(_, p)| *p)
            .collect::<Vec<_>>(),
        [5, 3]
    );
    owner.release().unwrap();
    assert_eq!(owner.phase(), Phase::Closed);
    assert_eq!(owner.retained(), None);
    drop(owner);
    assert_eq!(state.borrow().released, [plan.range()]);
}

#[test]
fn every_partial_populate_copy_or_seal_failure_releases_the_entire_reservation() {
    let source = fixture::image(false, false, true);
    let plan = Plan::new(&source, 0x20000000).unwrap();
    // reserve, populate, write, populate, write, protect, protect.
    for step in 1..=7 {
        let (backend, state) = mock(vec![step]);
        let mut owner = Installation::new(backend);
        let result = owner.stage(plan).and_then(|()| owner.seal());
        assert_eq!(result, Err(Error::Native(step)));
        assert_eq!(owner.phase(), Phase::Failed);
        assert_eq!(owner.retained(), None);
        assert_eq!(owner.stage(plan), Err(Error::State));
        assert_eq!(owner.seal(), Err(Error::State));
        drop(owner);
        let s = state.borrow();
        assert!(s.retained.is_none());
        assert_eq!(
            s.released,
            if step == 1 {
                vec![]
            } else {
                vec![plan.range()]
            }
        );
        if step <= 5 {
            assert!(s.permissions.is_empty());
        }
    }
}

#[test]
fn cleanup_errors_retain_ownership_and_failed_explicit_release_revokes_ready_state() {
    let source = fixture::image(false, false, true);
    let plan = Plan::new(&source, 0x20000000).unwrap();
    let (backend, state) = mock(vec![2, 3]);
    let mut owner = Installation::new(backend);
    assert_eq!(
        owner.stage(plan),
        Err(Error::Cleanup {
            operation: 2,
            release: 3
        })
    );
    assert_eq!(owner.retained(), Some(plan.range()));
    assert_eq!(owner.phase(), Phase::Failed);
    owner.release().unwrap();
    drop(owner);
    assert_eq!(state.borrow().released, [plan.range()]);
    let (backend, state) = mock(vec![8]);
    let mut owner = Installation::new(backend);
    owner.stage(plan).unwrap();
    owner.seal().unwrap();
    assert_eq!(owner.release(), Err(8));
    assert_eq!(owner.retained(), Some(plan.range()));
    assert_eq!(owner.phase(), Phase::Failed);
    drop(owner);
    assert_eq!(state.borrow().released, [plan.range()]);
}

#[test]
fn commit_publishes_ownership_before_callbacks_resume_and_releases_input_lifetime() {
    let (backend, state) = mock(vec![8]);
    let mut installed = None;
    {
        let source = fixture::image(false, false, true);
        let plan = Plan::new(&source, 0x20000000).unwrap();
        let mut owner = Installation::new(backend);
        assert_eq!(owner.commit(|_| panic!("not sealed")), Err(Error::State));
        owner.stage(plan).unwrap();
        assert_eq!(owner.commit(|_| panic!("not sealed")), Err(Error::State));
        owner.seal().unwrap();
        owner
            .commit(|mapping| {
                assert!(CRITICAL.get() > 0);
                assert!(mapping.is_ready());
                installed = Some(mapping);
            })
            .unwrap();
        assert_eq!(owner.phase(), Phase::Closed);
        assert_eq!(owner.retained(), None);
        assert_eq!(owner.commit(|_| panic!("replay")), Err(Error::State));
        drop(owner);
    }
    let mut mapping = installed.unwrap();
    assert!(mapping.is_ready());
    assert_eq!(mapping.release(), Err(8));
    assert!(!mapping.is_ready());
    assert!(mapping.retained().is_some());
    drop(mapping);
    assert_eq!(state.borrow().released.len(), 1);
}

#[test]
fn rejects_interpreters_bad_bias_and_invalid_loads_before_native_operations() {
    assert!(Plan::new(&fixture::image(true, false, true), 0x20000000).is_err());
    assert!(Plan::new(&fixture::image(false, true, true), 0x20000000).is_err());
    for bias in [0, 1, u64::MAX, 0x800000000000] {
        assert!(Plan::new(&fixture::image(false, false, true), bias).is_err());
    }
    for (at, value) in [
        (64 + 32, u64::MAX),
        (64 + 40, 1),
        (64 + 48, 3),
        (64 + 56 + 16, 0x100),
        (64 + 56 + 40, u64::MAX),
    ] {
        let mut source = fixture::image(false, false, true);
        fixture::put64(&mut source, at, value);
        assert!(Plan::new(&source, 0x20000000).is_err());
    }
    let source = fixture::image(false, false, true);
    let (backend, state) = mock(vec![]);
    let mut owner = Installation::new(backend);
    owner.release().unwrap();
    assert_eq!(
        owner.stage(Plan::new(&source, 0x20000000).unwrap()),
        Err(Error::State)
    );
    drop(owner);
    assert_eq!(state.borrow().calls, 0);
}
