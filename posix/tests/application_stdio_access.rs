#[path = "../../../applications/terminal/src/stdio_access.rs"]
mod production;
use mochi_user_platform::handle::{HANDLE_RIGHT_READ as READ, HANDLE_RIGHT_WRITE as WRITE};

#[test]
fn read_write_stdio_survives_dup2_style_terminal_setup_without_inventing_access() {
    for extra in [0, libc::O_NONBLOCK, libc::O_APPEND] {
        assert_eq!(
            production::data_rights(libc::O_RDWR | extra, READ).unwrap(),
            READ | WRITE
        );
        assert_eq!(
            production::data_rights(libc::O_RDWR | extra, WRITE).unwrap(),
            READ | WRITE
        );
        assert_eq!(
            production::data_rights(libc::O_RDONLY | extra, READ).unwrap(),
            READ
        );
        assert_eq!(
            production::data_rights(libc::O_WRONLY | extra, WRITE).unwrap(),
            WRITE
        );
        assert_eq!(
            production::data_rights(libc::O_RDONLY | extra, WRITE)
                .unwrap_err()
                .raw_os_error(),
            Some(libc::EACCES)
        );
        assert_eq!(
            production::data_rights(libc::O_WRONLY | extra, READ)
                .unwrap_err()
                .raw_os_error(),
            Some(libc::EACCES)
        );
    }
    assert_eq!(
        production::data_rights(libc::O_ACCMODE, READ)
            .unwrap_err()
            .raw_os_error(),
        Some(libc::EINVAL)
    );
}
