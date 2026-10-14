use std::{fs, path::Path, process::Command};

struct Temporary(std::path::PathBuf);
impl Drop for Temporary {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn execute(command: &mut Command) -> Vec<u8> {
    let output = command.output().unwrap();
    assert!(
        output.status.success(),
        "{command:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    output.stdout
}

fn block<'a>(source: &'a str, marker: &str) -> &'a str {
    let start = source
        .find(marker)
        .unwrap_or_else(|| panic!("missing {marker}"));
    let open = start + source[start..].find('{').unwrap();
    let mut depth = 0;
    for (offset, byte) in source[open..].bytes().enumerate() {
        match byte {
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    return &source[start..=open + offset];
                }
            }
            _ => (),
        }
    }
    panic!("unclosed {marker}")
}

fn conditional<'a>(source: &'a str, item: &str) -> &'a str {
    let position = source.find(item).unwrap();
    let start = source[..position].rfind("cfg_if! {").unwrap();
    block(&source[start..], "cfg_if! {")
}

fn definition(source: &str, name: &str) -> Option<String> {
    let prefix = format!("pub const {name}: ");
    let lines: Vec<_> = source.lines().collect();
    let index = lines
        .iter()
        .position(|line| line.trim_start().starts_with(&prefix))?;
    let mut result = String::new();
    if index != 0 && lines[index - 1].trim_start().starts_with("#[cfg(") {
        result.push_str(lines[index - 1]);
        result.push('\n');
    }
    result.push_str(lines[index]);
    result.push('\n');
    Some(result)
}

#[test]
fn generated_rust_socket_abi_and_control_helpers_match_actual_c_headers() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap();
    let library = root.join("libraries/libc");
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let temp = Temporary(std::env::temp_dir().join(format!(
        "mochios-rust-socket-{}-{nonce}",
        std::process::id()
    )));
    fs::create_dir(&temp.0).unwrap();
    let generator = temp.0.join("generator");
    execute(
        Command::new("rustc")
            .arg(library.join("build.rs"))
            .args(["--edition=2021", "-o"])
            .arg(&generator),
    );
    execute(
        Command::new(&generator)
            .env("CARGO_MANIFEST_DIR", &library)
            .env("OUT_DIR", &temp.0),
    );
    let generated = fs::read_to_string(temp.0.join("newlib_mod.rs")).unwrap();
    let platform = fs::read_to_string(library.join("newlib/mochios.rs")).unwrap();
    let common = fs::read_to_string(library.join("src/unix/mod.rs")).unwrap();
    let c_source = include_str!("rust_socket_abi.c");
    let mut local_constants = String::new();
    let mut inherited_constants = String::new();
    for rest in c_source.split("VALUE(").skip(1) {
        let name = rest.split(')').next().unwrap();
        if name == "name" {
            continue;
        }
        if let Some(value) = definition(&platform, name) {
            local_constants.push_str(&value);
        }
        if !["PF_INET6", "SO_ERROR"].contains(&name) {
            if let Some(value) = definition(&generated, name) {
                inherited_constants.push_str(&value);
            }
        }
    }
    // Compile the generator's real conditional declarations in their parent
    // scope. An upstream item hiding the target's glob re-export must fail the
    // comparison, even if the target module itself contains the correct value.
    inherited_constants.push_str(conditional(&generated, "pub const PF_INET6:"));
    inherited_constants.push_str(conditional(&generated, "pub const SO_ERROR:"));
    let mut structures = String::new();
    for name in ["sockaddr", "sockaddr_un", "msghdr", "cmsghdr"] {
        structures.push_str(block(&platform, &format!("pub struct {name} {{")));
        structures.push('\n');
    }
    let mut functions = String::new();
    for name in ["sendmsg", "recvmsg", "accept4"] {
        let start = platform.find(&format!("pub fn {name}(")).unwrap();
        let end = start + platform[start..].find(';').unwrap() + 1;
        functions.push_str(&platform[start..end]);
    }
    let helper_start = platform.find("const fn cmsg_align(").unwrap();
    let helper_end = platform[helper_start..]
        .find("pub const EAI_AGAIN:")
        .unwrap()
        + helper_start;
    let rust = format!(
        r#"
#![allow(non_camel_case_types, non_snake_case, unused_imports, dead_code)]
type c_int = i32; type c_uint = u32; type c_char = i8; type c_uchar = u8;
type size_t = usize; type ssize_t = isize; type c_void = core::ffi::c_void;
#[macro_use] #[path = {macros:?}] mod macros;
s! {{ {iovec} }}
pub type socklen_t = u32;
mod target {{
    use super::*;
    {family}
    {inherited_constants}
    mod mochios {{
        use super::*;
        s! {{ {structures} }}
        {local_constants}
        {helpers}
        extern "C" {{ {functions} }}
    }}
    pub use self::mochios::*;
}}
use target::*;
{probe}
"#,
        macros = library.join("src/macros.rs"),
        iovec = block(&common, "pub struct iovec {"),
        family = conditional(&generated, "pub type sa_family_t = u16;"),
        helpers = &platform[helper_start..helper_end],
        probe = include_str!("rust_socket_abi.inc"),
    );
    let source = temp.0.join("probe.rs");
    fs::write(&source, rust).unwrap();
    let binary = temp.0.join("rust-probe");
    execute(
        Command::new("rustc")
            .arg(&source)
            .args([
                "--edition=2021",
                "--cfg",
                "target_os=\"mochios\"",
                "-Aexplicit_builtin_cfgs_in_flags",
                "-o",
            ])
            .arg(&binary),
    );
    let rust_output = execute(&mut Command::new(binary));
    let binary = temp.0.join("c-probe");
    execute(
        Command::new("cc")
            .args([
                "-std=c11",
                "-O2",
                "-Wall",
                "-Wextra",
                "-Werror",
                "-fsanitize=undefined",
                "-I",
            ])
            .arg(root.join("user/libc-port/include"))
            .arg(root.join("services/posix/tests/rust_socket_abi.c"))
            .arg("-o")
            .arg(&binary),
    );
    let c_output = execute(&mut Command::new(binary));
    let rust = String::from_utf8(rust_output).unwrap();
    let c = String::from_utf8(c_output).unwrap();
    for (index, (rust, c)) in rust.lines().zip(c.lines()).enumerate() {
        assert_eq!(rust, c, "Rust/C socket ABI case {index}");
    }
    assert_eq!(rust.lines().count(), c.lines().count());

    let other = format!(
        r#"
#![allow(non_camel_case_types, dead_code)]
type c_int = i32;
#[macro_use] #[path = {macros:?}] mod macros;
{family}
{cloexec}
{inherited_constants}
fn main() {{ println!("{{}} {{}} {{}} {{}}", core::mem::size_of::<sa_family_t>(), PF_INET6, SO_ERROR, SOCK_CLOEXEC); }}
"#,
        macros = library.join("src/macros.rs"),
        family = conditional(&generated, "pub type sa_family_t = u16;"),
        cloexec = conditional(&generated, "pub const O_CLOEXEC:"),
    );
    fs::write(&source, other).unwrap();
    for (target, expected) in [
        ("other", "1 23 4103 524288\n"),
        ("horizon", "2 23 4105 524288\n"),
        ("espidf", "1 10 4103 262144\n"),
    ] {
        let binary = temp.0.join(target);
        execute(
            Command::new("rustc")
                .arg(&source)
                .args(["--edition=2021", "--cfg"])
                .arg(format!("target_os=\"{target}\""))
                .args(["-Aexplicit_builtin_cfgs_in_flags", "-o"])
                .arg(&binary),
        );
        assert_eq!(
            execute(&mut Command::new(binary)),
            expected.as_bytes(),
            "non-mochiOS platform {target}"
        );
    }
}
