#[path = "../../../binaries/msh/src/command.rs"]
mod production;
use std::ffi::OsStr;
#[test]
fn a_bare_program_stays_eligible_for_shared_path_search_and_arguments_are_not_reparsed() {
    let arguments = [
        "one two".to_owned(),
        "--literal".to_owned(),
        "日本語".to_owned(),
    ];
    for program in ["clang", "./main", "/system/bin/ls"] {
        let command = production::create(program, &arguments, "42", "interactive");
        assert_eq!(command.get_program(), OsStr::new(program));
        assert_eq!(
            command.get_args().collect::<Vec<_>>(),
            arguments.iter().map(OsStr::new).collect::<Vec<_>>()
        );
        let environment = command.get_envs().collect::<Vec<_>>();
        assert!(environment.contains(&(
            OsStr::new("MOCHI_EXECUTABLE_PATH"),
            Some(OsStr::new(program))
        )));
        assert!(
            environment.contains(&(OsStr::new("MOCHI_SHELL_ENDPOINT"), Some(OsStr::new("42"))))
        );
        assert!(environment.contains(&(
            OsStr::new("MOCHI_PROMPT_MODE"),
            Some(OsStr::new("interactive"))
        )));
        assert_eq!(
            environment.len(),
            3,
            "PATH/HOME remain inherited rather than cleared or replaced"
        );
    }
}

#[test]
fn an_explicit_path_override_is_preserved_by_the_standard_spawn_builder() {
    let mut command = production::create("tool", &[], "42", "deny");
    command.env("PATH", "/home/testuser/bin:");
    assert!(
        command
            .get_envs()
            .any(|(key, value)| key == "PATH" && value == Some(OsStr::new("/home/testuser/bin:")))
    );
    assert_eq!(command.get_program(), OsStr::new("tool"));
}
