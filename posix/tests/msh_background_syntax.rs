#[path = "../../../binaries/msh/src/syntax.rs"]
mod production;
#[test]
fn background_operator_is_only_an_unquoted_terminator_and_cannot_hide_more_commands() {
    let parsed = production::parse_pipeline("echo 'a&b' | cat &").unwrap();
    assert!(parsed.background);
    assert_eq!(parsed.commands.len(), 2);
    assert_eq!(parsed.commands[0].argv, ["echo", "a&b"]);
    assert!(!production::parse_pipeline("echo \\&").unwrap().background);
    for invalid in ["&", "echo & cat", "echo && cat", "echo | &"] {
        assert!(production::parse_pipeline(invalid).is_err(), "{invalid}");
    }
}
