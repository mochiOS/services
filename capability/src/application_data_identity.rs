//! Filesystem policy belongs to the broker, not to the kernel or request body.
use mochi_user_platform::syscall::ThreadSecurityContext;
fn component(bytes: &[u8]) -> Option<&str> {
    let value = core::str::from_utf8(bytes).ok()?;
    (!value.is_empty()
        && value.len() <= 128
        && !matches!(value, "." | "..")
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-')))
    .then_some(value)
}
pub fn namespace(
    context: &ThreadSecurityContext,
    uid: u32,
    generation: u64,
) -> Option<[String; 7]> {
    if generation == 0 || !matches!(context.provenance, 1..=3) {
        return None;
    }
    let package = component(context.package_id.get(..context.package_id_len as usize)?)?;
    let developer = component(
        context
            .developer_id
            .get(..context.developer_id_len as usize)?,
    )?;
    let key: String = context
        .subject_key_id
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    Some([
        "libraries".into(),
        "applications".into(),
        package.into(),
        "users".into(),
        format!("{uid}-{generation}"),
        "private".into(),
        format!("{}-{key}-{developer}", context.provenance),
    ])
}
#[cfg(test)]
mod tests {
    use super::*;
    fn identity() -> ThreadSecurityContext {
        let mut context = ThreadSecurityContext::default();
        let package = b"org.example.editor";
        let developer = b"org.example";
        context.package_id[..package.len()].copy_from_slice(package);
        context.package_id_len = package.len() as u16;
        context.developer_id[..developer.len()].copy_from_slice(developer);
        context.developer_id_len = developer.len() as u16;
        context.provenance = 2;
        context
    }
    #[test]
    fn app_publisher_account_and_incarnation_have_distinct_directories() {
        let mut context = identity();
        let original = namespace(&context, 501, 17).unwrap();
        assert_eq!(original[2], "org.example.editor");
        assert_ne!(Some(original.clone()), namespace(&context, 502, 17));
        assert_ne!(Some(original.clone()), namespace(&context, 501, 18));
        context.subject_key_id[0] = 1;
        assert_ne!(Some(original.clone()), namespace(&context, 501, 17));
        context = identity();
        context.provenance = 3;
        assert_ne!(Some(original.clone()), namespace(&context, 501, 17));
        context = identity();
        context.package_id[0] = b'x';
        assert_ne!(Some(original.clone()), namespace(&context, 501, 17));
        context = identity();
        context.developer_id[0] = b'x';
        assert_ne!(Some(original), namespace(&context, 501, 17));
    }
    #[test]
    fn malformed_or_unmeasured_identity_never_becomes_a_path() {
        let mut context = identity();
        assert!(namespace(&context, 501, 0).is_none());
        context.provenance = 0;
        assert!(namespace(&context, 501, 17).is_none());
        context = identity();
        context.package_id[0] = b'/';
        assert!(namespace(&context, 501, 17).is_none());
        context = identity();
        context.developer_id_len = u16::MAX;
        assert!(namespace(&context, 501, 17).is_none());
    }
}
