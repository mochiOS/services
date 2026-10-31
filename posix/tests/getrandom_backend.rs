use mochios_posix_client::{
    newlib_errno::{EACCES, EAGAIN, EINTR, EIO},
    random::getrandom02::fill_using,
};

#[test]
fn interrupted_and_partial_entropy_keeps_only_the_unfilled_slice() {
    let mut destination = [0; 600];
    let mut requests = Vec::new();
    let mut written = 0;
    fill_using(&mut destination, |remaining| {
        requests.push(remaining.len());
        if requests.len() == 2 {
            return Err(EINTR);
        }
        let count = remaining.len().min(100);
        for byte in &mut remaining[..count] {
            *byte = (written % 251 + 1) as u8;
            written += 1;
        }
        Ok(count)
    })
    .unwrap();
    assert_eq!(requests, [256, 156, 156, 56, 256, 156, 56, 88]);
    assert_eq!(written, 600);
    for (index, byte) in destination.iter().enumerate() {
        assert_eq!(*byte, (index % 251 + 1) as u8);
    }
}

#[test]
fn empty_entropy_does_not_call_the_source() {
    fill_using(&mut [], |_| panic!("empty source request")).unwrap();
}

#[test]
fn permission_and_not_ready_errors_are_not_retried_or_replaced() {
    for errno in [EACCES, EAGAIN, EIO] {
        let mut requests = 0;
        let mut bytes = [0x5a; 20];
        let error = fill_using(&mut bytes, |_| {
            requests += 1;
            Err(errno)
        })
        .unwrap_err();
        assert_eq!(error.raw_os_error(), Some(errno));
        assert_eq!(requests, 1);
        assert_eq!(bytes, [0x5a; 20]);
    }
}

#[test]
fn zero_or_oversized_transfers_fail_without_inventing_entropy() {
    for count in [0, 21] {
        let mut requests = 0;
        let mut bytes = [0x5a; 20];
        let error = fill_using(&mut bytes, |_| {
            requests += 1;
            Ok(count)
        })
        .unwrap_err();
        assert_eq!(error.raw_os_error(), Some(EIO));
        assert_eq!(requests, 1);
        assert_eq!(bytes, [0x5a; 20]);
    }
}

#[test]
fn failure_after_a_completed_chunk_stops_before_the_next_chunk() {
    let mut requests = 0;
    let mut bytes = [0x5a; 700];
    assert_eq!(
        fill_using(&mut bytes, |remaining| {
            requests += 1;
            if requests == 2 {
                return Err(EACCES);
            }
            remaining.fill(0xab);
            Ok(remaining.len())
        })
        .unwrap_err()
        .raw_os_error(),
        Some(EACCES)
    );
    assert_eq!(requests, 2);
    assert_eq!(&bytes[..256], &[0xab; 256]);
    assert_eq!(&bytes[256..], &[0x5a; 444]);
}

#[test]
fn invalid_errno_is_not_reported_as_an_os_error() {
    for errno in [0, -1, i32::MIN] {
        assert_eq!(
            fill_using(&mut [0; 1], |_| Err(errno))
                .unwrap_err()
                .raw_os_error(),
            None
        );
    }
}
