//! Real msign CLI admission, exact embedded bytes and failed-output ownership.
use mochios_elf_signature::{MAX_MANIFEST_LEN, verify_image};
use mochios_file_publication::PrivateDirectory;
use std::{fs, path::PathBuf, process::Command};

#[path = "support/signed_elf.rs"]
mod fixture;

#[test]
#[ignore = "requires MOCHIOS_TEST_MSIGN; run explicitly"]
fn signer_embeds_exact_declarations_and_preserves_output_on_invalid_metadata() {
    let msign = PathBuf::from(std::env::var_os("MOCHIOS_TEST_MSIGN").unwrap());
    let directory = PrivateDirectory::new_in(&std::env::temp_dir(), "manifest-cli326").unwrap();
    let root = directory.path();
    let input = root.join("input.elf");
    let output = root.join("output.elf");
    let manifest = root.join("manifest with spaces.toml");
    fs::write(&input, fixture::unsigned()).unwrap();
    let declaration = "[package]\nid = \"org.example.main\"\nname = \"main\"\nversion = \"1\"\n[[binary]]\npath = \"main\"\nrequires = [\"net.connect\"]\n";
    fs::write(&manifest, declaration).unwrap();
    let sign = || {
        Command::new(&msign)
            .args(["elf", "sign"])
            .arg(&input)
            .arg("--adhoc")
            .arg("--manifest")
            .arg(&manifest)
            .arg("--output")
            .arg(&output)
            .output()
            .unwrap()
    };
    let result = sign();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let signed = fs::read(&output).unwrap();
    let evidence = verify_image(&signed, None, &Default::default()).unwrap();
    assert_eq!(evidence.manifest(), Some(declaration));
    // The embedded declaration remains authoritative after its input sidecar
    // changes or disappears. No reopen is needed by the common verifier.
    fs::remove_file(&manifest).unwrap();
    assert_eq!(
        verify_image(&signed, None, &Default::default())
            .unwrap()
            .manifest(),
        Some(declaration)
    );
    assert!(!sign().status.success());
    for invalid in [
        b"broken = [".to_vec(),
        vec![0xff],
        vec![b'x'; MAX_MANIFEST_LEN + 1],
        b"x = \"a\0b\"".to_vec(),
    ] {
        fs::write(&manifest, invalid).unwrap();
        assert!(!sign().status.success());
        assert_eq!(fs::read(&output).unwrap(), signed);
    }
    fs::remove_file(&manifest).unwrap();
    std::os::unix::fs::symlink(&input, &manifest).unwrap();
    assert!(!sign().status.success());
    assert_eq!(fs::read(&output).unwrap(), signed);
    fs::remove_file(&manifest).unwrap();
    fs::write(&manifest, declaration).unwrap();
    let saved_manifest = fs::read(&manifest).unwrap();
    assert!(
        !Command::new(&msign)
            .args(["elf", "sign"])
            .arg(&input)
            .args(["--adhoc", "--manifest"])
            .arg(&manifest)
            .arg("--output")
            .arg(&manifest)
            .status()
            .unwrap()
            .success()
    );
    assert_eq!(fs::read(&manifest).unwrap(), saved_manifest);
    // A second metadata or signature pass must fail before publishing output.
    fs::write(&input, &signed).unwrap();
    assert!(!sign().status.success());
    assert_eq!(fs::read(&output).unwrap(), signed);
    assert!(fs::read_dir(root).unwrap().all(|e| {
        !e.unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with(".mochios-")
    }));
}
