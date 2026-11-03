//! Real account/group C APIs and a real target Vim, through ordinary exec.
#[cfg(target_os = "mochios")]
#[path = "../../../applications/terminal/src/model.rs"]
mod model;
#[cfg(target_os = "mochios")]
#[path = "../../../applications/terminal/src/native_launch.rs"]
mod native_launch;
#[cfg(target_os = "mochios")]
#[path = "../../../applications/terminal/src/pending_input.rs"]
mod pending_input;
#[cfg(target_os = "mochios")]
#[path = "../../../applications/terminal/src/settings.rs"]
mod settings;
#[cfg(target_os = "mochios")]
#[path = "../../../applications/terminal/src/stdio_access.rs"]
mod stdio_access;
#[cfg(target_os = "mochios")]
#[path = "../../../applications/terminal/src/transport.rs"]
mod transport;
#[cfg(target_os = "mochios")]
#[path = "vim/pty.rs"]
mod pty;

#[cfg(not(target_os = "mochios"))]
fn main() {
    eprintln!("native-vim: requires mochiOS");
}

#[cfg(target_os = "mochios")]
fn main() {
    use mochios_file_publication::PrivateDirectory;
    use std::{fs, path::Path, process::Command};
    unsafe extern "C" {
        fn mochi_passwd_probe() -> i32;
        fn mochi_groups_probe() -> i32;
    }
    unsafe {
        libc::alarm(180);
        assert_eq!(mochi_passwd_probe(), 0);
        assert_eq!(mochi_groups_probe(), 0);
    }
    let version = Command::new("/system/bin/vim")
        .arg("--version")
        .output()
        .unwrap();
    assert!(version.status.success(), "Vim version failed: {version:?}");
    let version = String::from_utf8(version.stdout).unwrap();
    assert!(
        version.contains("VIM - Vi IMproved 9.2") && version.contains("+multi_byte"),
        "{version}"
    );
    println!("native-vim: PASS actual Vim 9.2 and multibyte support");
    let directory = PrivateDirectory::new_in(Path::new("/tmp"), "vim342").unwrap();
    let script = directory.path().join("test.vim");
    fs::write(
        &script,
        r#"
set nocompatible encoding=utf-8 noswapfile nomore
scriptencoding utf-8
call assert_true(localtime() > 0)
let started = reltime()
sleep 20m
call assert_true(reltimefloat(reltime(started)) >= 0.01)
let target = $MOCHIOS_VIM_TEST_DIR . '/document.txt'
execute 'edit ' . fnameescape(target)
set fileencoding=utf-8
call setline(1, ['mochiOS Vim', '日本語の編集', 'before'])
write!
bwipeout!
execute 'edit ' . fnameescape(target)
execute "normal! Gccafter\<Esc>"
call assert_equal('after', getline(3))
normal! u
call assert_equal('before', getline(3))
execute "normal! \<C-R>"
call assert_equal('after', getline(3))
write!
bwipeout!
execute 'edit ' . fnameescape(target)
call assert_equal(['mochiOS Vim', '日本語の編集', 'after'], getline(1, '$'))
call assert_equal(2, search('日本語', 'w'))
syntax on
setfiletype c
call assert_true(exists('g:syntax_on'))
call assert_true(isdirectory($VIMRUNTIME))
if !empty(v:errors)
  call writefile(v:errors, $MOCHIOS_VIM_TEST_DIR . '/errors')
  cquit 7
endif
quit!
"#,
    )
    .unwrap();
    let log = directory.path().join("vim.log");
    let result = Command::new("/system/bin/vim")
        .args(["-Nu", "NONE", "-n", "-i", "NONE", "-es"])
        .arg(format!("-V1{}", log.display()))
        .arg("-S")
        .arg(&script)
        .env("MOCHIOS_VIM_TEST_DIR", directory.path())
        .output()
        .unwrap();
    if !result.status.success() {
        println!("Vim stdout: {}", String::from_utf8_lossy(&result.stdout));
        println!("Vim stderr: {}", String::from_utf8_lossy(&result.stderr));
        println!("Vim log: {}", fs::read_to_string(&log).unwrap_or_default());
        println!(
            "Vim assertions: {}",
            fs::read_to_string(directory.path().join("errors")).unwrap_or_default()
        );
        panic!("Vim script failed: {}", result.status);
    }
    assert_eq!(
        fs::read_to_string(directory.path().join("document.txt")).unwrap(),
        "mochiOS Vim\n日本語の編集\nafter\n"
    );
    println!(
        "native-vim: PASS edit undo redo search UTF-8 save reopen and installed syntax runtime"
    );
    pty::run(directory.path());
    fs::remove_dir_all(directory.path()).unwrap();
    drop(directory);
    unsafe {
        libc::alarm(0);
    }
    println!("native-vim: PASS cleanup");
}
