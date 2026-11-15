//! Execute production error-handling functions with controlled transport calls.
use std::io::Write;
use std::process::{Command, Stdio};

pub fn between<'a>(source: &'a str, start: &str, end: &str) -> &'a str {
    let start = source.find(start).unwrap();
    let end = start + source[start..].find(end).unwrap();
    &source[start..end]
}

/// Select a formatted top-level production definition independently of the
/// next item or module layout. Visibility is local to the host probe crate.
pub fn definition(source: &str, declaration: &str) -> String {
    let declaration = declaration.strip_suffix('(').unwrap_or(declaration);
    let declaration_start = source
        .match_indices(declaration)
        .find(|(at, _)| {
            source[at + declaration.len()..]
                .chars()
                .next()
                .is_none_or(|next| !next.is_ascii_alphanumeric() && next != '_')
        })
        .map(|(at, _)| at)
        .expect(declaration);
    let mut start = source[..declaration_start]
        .rfind('\n')
        .map_or(0, |at| at + 1);
    // Retain derives/attributes belonging to the definition.
    while start != 0 {
        let previous_end = start - 1;
        let previous_start = source[..previous_end].rfind('\n').map_or(0, |at| at + 1);
        let line = source[previous_start..previous_end].trim();
        if line.starts_with("#[") || line.starts_with("///") {
            start = previous_start;
        } else {
            break;
        }
    }
    let line_end = source[declaration_start..]
        .find('\n')
        .map_or(source.len(), |at| declaration_start + at);
    let end = if source[declaration_start..line_end]
        .trim_end()
        .ends_with(';')
    {
        line_end
    } else {
        declaration_start
            + source[declaration_start..]
                .find("\n}")
                .expect("top-level definition end")
            + 2
    };
    source[start..end].replace("pub(super)", "pub(crate)")
}

pub fn program() -> String {
    let syscall = include_str!("../../../../user/crates/syscall/src/lib.rs");
    let mut program =
        String::from("#![allow(dead_code)]\nextern crate alloc;\nmod mnu_abi {pub mod status {\n");
    program.push_str(include_str!("../../../../core/crates/abi/src/status.rs"));
    program.push_str(
        "}\n}\nmod mochi_user_syscall {\npub use crate::mnu_abi::status::Error as NativeError;\n",
    );
    program.push_str(between(
        syscall,
        "#[derive(Clone, Copy, Debug, PartialEq, Eq)]",
        "#[derive(Clone, Copy, Debug, PartialEq, Eq)]\npub struct RawSyscallResult",
    ));
    for line in include_str!("../../../../user/crates/syscall/src/compatibility_status.rs").lines()
    {
        if line.starts_with("pub const E") && line.contains(": u64 = (-") {
            program.push_str(line);
            program.push('\n');
        }
    }
    program.push_str("}\nuse mochi_user_syscall::*;\nmod mochios_posix_protocol {\n");
    constants(
        &mut program,
        include_str!("../../../../user/crates/posix-protocol/src/lib.rs"),
        &["STATUS_ENOTDIR", "STATUS_EISDIR"],
    );
    program.push_str("}\n");
    program
}

pub fn constants(program: &mut String, source: &str, names: &[&str]) {
    for name in names {
        let suffix = format!("const {name}:");
        program.push_str(source.lines().find(|line| line.contains(&suffix)).unwrap());
        program.push('\n');
    }
}

/// Use the production x86 FP adapter and register image in host fixtures.
/// The extra context code may inspect private reserved bytes in that module.
pub fn kernel_fp_modules(root: &std::path::Path, extra_context: &str, upcalls: bool) -> String {
    let context = include_str!("../../../../core/src/arch/x86_64/context.rs");
    let fp = between(context, "const FXSAVE_AREA_SIZE:", "/// CPU コンテキスト");
    let diagnostic = definition(
        include_str!("../../../../core/src/util/process_diagnostics.rs"),
        "pub struct Exception",
    );
    let upcalls = if upcalls {
        format!(
            "#[path={:?}]pub mod upcall;\n",
            root.join("core/src/arch/x86_64/upcall.rs")
        )
    } else {
        String::new()
    };
    format!(
        "mod arch {{pub mod context {{{fp}\n{extra_context}\n}}\n#[path={:?}]pub mod exception;\n#[path={:?}]pub mod fp;\n{upcalls}}}\nmod util {{pub mod process_diagnostics {{{diagnostic}\n}}}}\n",
        root.join("core/src/arch/x86_64/exception.rs"),
        root.join("core/src/arch/x86_64/fp.rs")
    )
}

pub fn kernel_abi(root: &std::path::Path) -> String {
    format!(
        "extern crate self as mnu_abi;\n#[path={:?}]mod abi;pub use abi::*;\n",
        root.join("core/crates/abi/src/lib.rs")
    )
}

struct Temporary(std::path::PathBuf);
impl Drop for Temporary {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

pub fn run(program: &str) {
    run_with(program, None, None);
}

pub fn run_with_toolchain(program: &str, toolchain: &str) {
    run_with(program, Some(toolchain), None);
}

pub fn run_with_cfg(program: &str, cfg: &str) {
    run_with(program, None, Some(cfg));
}

fn run_with(program: &str, toolchain: Option<&str>, cfg: Option<&str>) {
    let temporary = Temporary(std::env::temp_dir().join(format!(
        "mochios-native-error-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    )));
    std::fs::create_dir(&temporary.0).unwrap();
    let binary = temporary.0.join("probe");
    let mut command = match toolchain {
        Some(toolchain) => {
            let mut command = Command::new("rustup");
            command.args(["run", toolchain, "rustc"]);
            command
        }
        None => Command::new("rustc"),
    };
    if let Some(cfg) = cfg {
        command.arg("--cfg").arg(cfg);
    }
    let mut compiler = command
        .args(["--edition=2024", "-", "-o"])
        .arg(&binary)
        .stdin(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    compiler
        .stdin
        .take()
        .unwrap()
        .write_all(program.as_bytes())
        .unwrap();
    let output = compiler.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let output = Command::new(binary).output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

/// The real native/peer distinction, shared by controlled transport fixtures.
pub fn operation_error() -> String {
    let source = include_str!("../../../../core/src/result.rs");
    format!(
        "mod result {{ use crate::mnu_abi; {} {} {} }}\nuse result::OperationError;\n",
        definition(source, "enum OperationError"),
        definition(source, "impl OperationError {"),
        definition(
            source,
            "impl From<mnu_abi::status::Error> for OperationError {"
        )
    )
}

/// Normal-return ownership model for transport fixtures. Forced retirement is
/// checked separately against task::operation; these fixtures do not schedule.
pub fn operation_scope() -> &'static str {
    r#"
mod task { pub mod operation {
    pub struct Scope<T>(Vec<T>);
    impl<T> Scope<T> {
        pub fn with<R>(value:T,body:impl FnOnce(&T)->R)->Result<R,crate::mnu_abi::status::Error>{let held=Self::new(value)?;Ok(body(&held))}
        pub fn new(value:T)->Result<Self,crate::mnu_abi::status::Error>{
            let mut values=Vec::new();
            values.try_reserve_exact(1).map_err(|_|crate::mnu_abi::status::Error::ResourceUnavailable)?;
            values.push(value);Ok(Self(values))
        }
    }
    impl<T> core::ops::Deref for Scope<T>{type Target=T;fn deref(&self)->&T{&self.0[0]}}
    impl<T> core::ops::DerefMut for Scope<T>{fn deref_mut(&mut self)->&mut T{&mut self.0[0]}}
}}
"#
}

pub fn prepared_launch() -> String {
    let source = include_str!("../../../../core/src/syscall/exec/launch.rs");
    [
        definition(source, "struct LaunchSecurity"),
        definition(source, "struct PreparedLaunch"),
    ]
    .join("\n")
    .replace("super::Inherited", "crate::Inherited")
}
