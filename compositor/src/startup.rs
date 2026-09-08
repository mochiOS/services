use mochi_user_platform as platform;

pub(crate) fn check<T>(stage: &str, action: impl FnOnce() -> Result<T, u32>) -> Result<T, u32> {
    trace(stage, action, |stage, result| {
        let phase = if result.is_none() { "enter" } else { "return" };
        platform::logger::write_status_fmt(format_args!(
            "compositor.service: startup stage={} phase={} status={}\n",
            stage, phase, result.unwrap_or(0),
        ))
        .map_err(|error| crate::protocol::errno_status(error.errno().unwrap_or(mochi_user_syscall::EIO)))
    })
}

pub(crate) fn required<T>(stage: &str, action: impl FnOnce() -> Result<T, u32>) -> T {
    check(stage, action).unwrap_or_else(|status| platform::process::exit(u64::from(status)))
}

fn trace<T>(
    stage: &str,
    action: impl FnOnce() -> Result<T, u32>,
    mut record: impl FnMut(&str, Option<u32>) -> Result<(), u32>,
) -> Result<T, u32> {
    // Recording must not become another startup dependency.
    let _ = record(stage, None);
    let result = action();
    let _ = record(stage, Some(result.as_ref().err().copied().unwrap_or(0)));
    result
}

#[cfg(test)]
mod tests {
    use super::trace;
    use core::cell::RefCell;

    #[test]
    fn records_enter_before_action_and_preserves_failure() {
        let events = RefCell::new(Vec::new());
        let result: Result<(), u32> = trace("present", || {
            assert_eq!(*events.borrow(), vec![None]);
            Err(5)
        }, |_, value| { events.borrow_mut().push(value); Ok(()) });
        assert_eq!(result, Err(5));
        assert_eq!(*events.borrow(), vec![None, Some(5)]);
    }

    #[test]
    fn recording_failure_does_not_block_startup_or_replace_errno() {
        assert_eq!(trace("input", || Ok(42), |_, _| Err(11)), Ok(42));
        assert_eq!(trace::<()>("input", || Err(5), |_, _| Err(11)), Err(5));
    }
}
