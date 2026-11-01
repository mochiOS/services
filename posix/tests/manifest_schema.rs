//! One TOML grammar/schema for build tools and userspace execution consumers.
use mochios_package_manifest::{ParseError, parse_manifest_checked as parse};
use std::path::{Path, PathBuf};

const HEADER: &str = "[package]\nid = \"org.example.main\"\nname = \"main\"\nversion = \"1\"\n";

#[test]
fn standard_strings_arrays_and_comments_have_one_interpretation() {
    let text = format!(
        "{HEADER}\n[[binary]]\npath = 'main'\nrequires = [\n\"\\u006eet.connect\", # comment\n'net.listen',\n]\n"
    );
    let manifest = parse(&text).unwrap();
    assert_eq!(manifest.binaries[0].requires, ["net.connect", "net.listen"]);
    let platform = mochi_user_platform::package::parse_manifest(&text).unwrap();
    assert_eq!(platform.binaries[0].requires, manifest.binaries[0].requires);
    let text = format!("{HEADER}\n[[binary]]\npath = \"main\"\nrequires = [\"x,y#z\"]\n");
    assert_eq!(parse(&text).unwrap().binaries[0].requires, ["x,y#z"]);
}

#[test]
fn duplicate_keys_ambiguous_aliases_and_malformed_escapes_are_rejected() {
    for suffix in [
        "id = \"org.other.main\"\n",
        "\n[[binary]]\npath = \"main\"\nrequires = []\nrequires = [\"net.connect\"]\n",
        "\n[[binary]]\npath = \"main\"\nrequires = [\"net.\\qconnect\"]\n",
        "\n[package]\nid = \"org.other.main\"\n",
    ] {
        assert_eq!(
            parse(&format!("{HEADER}{suffix}")).unwrap_err(),
            ParseError::Syntax
        );
    }
    for suffix in [
        "vendor = \"one\"\ndeveloper = \"two\"\n",
        "\n[[binary]]\npath = \"main\"\nentry = \"other\"\n",
        "\n[[binary]]\npath = \"main\"\nrequires = [\"net.connect\",\"net.connect\"]\n",
    ] {
        assert_eq!(
            parse(&format!("{HEADER}{suffix}")).unwrap_err(),
            ParseError::Schema
        );
    }
}

#[test]
fn wrong_types_and_unfinished_or_control_character_requirements_fail_closed() {
    for suffix in [
        "\n[[binary]]\npath = \"main\"\nrequires = \"net.connect\"\n",
        "\n[[binary]]\npath = \"main\"\nrequires = [\"net.connect\",17]\n",
        "\n[[binary]]\npath = \"main\"\nrequires = [\"\"]\n",
        "\n[[binary]]\npath = \"main\"\nrequires = [\"net.\\nconnect\"]\n",
        "\n[[binary]]\npath = 17\n",
        "\n[[binary]]\npath = \"main\"\napi_version = -1\n",
        "\n[[binary]]\npath = \"main\"\napi_version = true\n",
    ] {
        assert_eq!(
            parse(&format!("{HEADER}{suffix}")).unwrap_err(),
            ParseError::Schema
        );
    }
    assert_eq!(
        parse(&format!(
            "{HEADER}\n[[binary]]\nrequires = [\"net.connect\"\n"
        ))
        .unwrap_err(),
        ParseError::Syntax
    );
    assert_eq!(
        parse(&"x".repeat(mochios_package_manifest::MAX_MANIFEST_LEN + 1)).unwrap_err(),
        ParseError::TooLarge
    );
    let deeply_nested = format!("{HEADER}extra = {}0{}\n", "[".repeat(512), "]".repeat(512));
    assert_eq!(parse(&deeply_nested).unwrap_err(), ParseError::Syntax);
}

#[test]
fn legacy_entry_and_driver_fields_use_the_same_typed_schema() {
    let legacy = "[service]\nid='org.example.main'\nname='main'\nversion='1'\nentry='/system/bin/main'\n[capabilities]\nrequires=['net.connect']\n";
    let manifest = parse(legacy).unwrap();
    assert_eq!(manifest.binaries[0].path, "/system/bin/main");
    assert_eq!(manifest.binaries[0].requires, ["net.connect"]);
    let driver = format!(
        "{HEADER}\n[[binary]]\npath = '/driver'\nkind = 'driver'\napi_version = 1\nmatch_vendor_id = '0x1234'\n"
    );
    let manifest = parse(&driver).unwrap();
    assert_eq!(manifest.binaries[0].api_version, Some(1));
    assert_eq!(
        manifest.binaries[0].match_vendor_id.as_deref(),
        Some("0x1234")
    );
}

fn collect(directory: &Path, output: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(directory).unwrap() {
        let entry = entry.unwrap();
        let kind = entry.file_type().unwrap();
        if kind.is_dir() {
            let name = entry.file_name();
            if !matches!(
                name.to_str(),
                Some("out" | "target" | "node_modules" | ".git")
            ) {
                collect(&entry.path(), output);
            }
        } else if kind.is_file() && entry.file_name() == "manifest.toml" {
            output.push(entry.path());
        }
    }
}

#[test]
fn actual_os_manifests_are_accepted_by_the_shared_schema() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let mut files = Vec::new();
    // CExt has a separate [cext] ABI manifest, not a package declaration.
    for directory in ["services", "applications", "binaries", "drivers"] {
        collect(&root.join(directory), &mut files);
    }
    let mut failed = Vec::new();
    for path in &files {
        let text = std::fs::read_to_string(path).unwrap();
        if let Err(error) = parse(&text) {
            failed.push((path, error));
        }
    }
    assert!(files.len() > 25, "source manifest corpus must not be empty");
    assert!(
        failed.is_empty(),
        "shared schema rejected OS manifests: {failed:?}"
    );
}

#[test]
#[ignore = "requires MOCHIOS_TEST_MANIFEST_ROOT with a staged OS package tree"]
fn installed_package_manifests_use_the_same_schema() {
    let root = PathBuf::from(std::env::var_os("MOCHIOS_TEST_MANIFEST_ROOT").unwrap());
    let mut files = Vec::new();
    collect(&root, &mut files);
    assert!(
        files.len() > 25,
        "installed package corpus must not be empty"
    );
    for path in &files {
        let text = std::fs::read_to_string(path).unwrap();
        assert!(
            parse(&text).is_ok(),
            "installed manifest rejected: {path:?}"
        );
    }
    println!(
        "shared schema accepted {} installed package manifests",
        files.len()
    );
}
