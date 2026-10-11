const EIO: i32 = 5;
const EFBIG: i32 = 27;

/// Completes a bounded positioned transfer without touching a sequential cursor.
/// The callback receives the completed prefix, absolute position and remaining
/// length. Errors after progress return that progress, never discard it.
pub fn transfer(
    offset: u64,
    length: usize,
    zero_is_error: bool,
    mut operation: impl FnMut(usize, u64, usize) -> Result<usize, i32>,
) -> Result<usize, i32> {
    let length_u64 = u64::try_from(length).map_err(|_| EFBIG)?;
    offset.checked_add(length_u64).ok_or(EFBIG)?;
    let mut done = 0usize;
    while done < length {
        let remaining = length - done;
        let count = match operation(done, offset + done as u64, remaining) {
            Ok(count) if count <= remaining => count,
            Ok(_) => return Err(EIO),
            Err(error) if done == 0 => return Err(error),
            Err(_) => return Ok(done),
        };
        if count == 0 {
            return if zero_is_error && done == 0 {
                Err(EIO)
            } else {
                Ok(done)
            };
        }
        done += count;
    }
    Ok(done)
}
