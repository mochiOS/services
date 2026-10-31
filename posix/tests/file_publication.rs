use mochios_file_publication::PrivateDirectory;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::{fs, io::Write};

fn parent() -> PrivateDirectory {
    PrivateDirectory::new_in(&std::env::temp_dir(), "publication-test").unwrap()
}

#[test]
fn staged_bytes_are_private_until_publication_and_cleanup_keeps_the_output() {
    let parent = parent();
    let output = parent.path().join("output");
    fs::write(&output, b"previous").unwrap();
    let directory = PrivateDirectory::new_in(parent.path(), "stage").unwrap();
    let staged_path = directory.path().to_owned();
    let mut file = directory.create_file("new").unwrap();
    #[cfg(unix)]
    {
        assert_eq!(
            fs::metadata(directory.path()).unwrap().permissions().mode() & 0o077,
            0
        );
        assert_eq!(file.metadata().unwrap().permissions().mode() & 0o177, 0);
    }
    file.write_all(b"new contents").unwrap();
    assert_eq!(fs::read(&output).unwrap(), b"previous");
    assert!(directory.create_file("new").is_err());
    directory.publish("new", &file, &output).unwrap();
    drop(file);
    drop(directory);
    assert!(!staged_path.exists());
    assert_eq!(fs::read(output).unwrap(), b"new contents");
}

#[test]
fn abandoned_or_failed_output_does_not_replace_the_previous_file() {
    let parent = parent();
    let output = parent.path().join("output");
    fs::write(&output, b"previous").unwrap();
    let stage;
    {
        let directory = PrivateDirectory::new_in(parent.path(), "stage").unwrap();
        stage = directory.path().to_owned();
        let mut file = directory.create_file("partial").unwrap();
        file.write_all(b"partial").unwrap();
        assert!(directory.publish("missing", &file, &output).is_err());
    }
    assert!(!stage.exists());
    assert_eq!(fs::read(output).unwrap(), b"previous");
}

#[test]
fn invalid_names_cannot_escape_the_staging_directory() {
    let parent = parent();
    for prefix in ["", "../escape", "/absolute", "dot.name", "bad\\name"] {
        assert!(PrivateDirectory::new_in(parent.path(), prefix).is_err());
    }
    let directory = PrivateDirectory::new_in(parent.path(), "stage").unwrap();
    let file = directory.create_file("owned").unwrap();
    for name in ["", ".", "..", "../outside", "/absolute", "bad\\name"] {
        assert!(directory.create_file(name).is_err());
        assert!(
            directory
                .publish(name, &file, &parent.path().join("output"))
                .is_err()
        );
    }
    assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 1);
}

#[test]
fn publish_failure_leaves_destination_and_source_owned() {
    let parent = parent();
    let output = parent.path().join("output-directory");
    fs::create_dir(&output).unwrap();
    let directory = PrivateDirectory::new_in(parent.path(), "stage").unwrap();
    let mut file = directory.create_file("new").unwrap();
    file.write_all(b"new").unwrap();
    assert!(directory.publish("new", &file, &output).is_err());
    assert!(output.is_dir());
    assert_eq!(fs::read(directory.path().join("new")).unwrap(), b"new");
    let invalid_parent = parent.path().join("file");
    fs::write(&invalid_parent, b"file").unwrap();
    assert!(PrivateDirectory::new_in(&invalid_parent, "stage").is_err());
}

#[test]
#[cfg(unix)]
fn an_owned_descriptor_can_publish_without_reopening_removed_read_permissions() {
    let parent = parent();
    let directory = PrivateDirectory::new_in(parent.path(), "stage").unwrap();
    let mut file = directory.create_file("new").unwrap();
    file.write_all(b"owned").unwrap();
    file.set_permissions(fs::Permissions::from_mode(0)).unwrap();
    let destination = parent.path().join("output");
    directory.publish("new", &file, &destination).unwrap();
    assert_eq!(
        fs::metadata(&destination).unwrap().permissions().mode() & 0o777,
        0
    );
    file.set_permissions(fs::Permissions::from_mode(0o600))
        .unwrap();
    assert_eq!(fs::read(destination).unwrap(), b"owned");
}

#[test]
#[cfg(unix)]
fn publication_rejects_a_descriptor_for_another_file() {
    let parent = parent();
    let directory = PrivateDirectory::new_in(parent.path(), "stage").unwrap();
    let first = directory.create_file("first").unwrap();
    directory.create_file("second").unwrap();
    assert!(
        directory
            .publish("second", &first, &parent.path().join("output"))
            .is_err()
    );
    assert!(!parent.path().join("output").exists());
    assert!(directory.path().join("second").exists());
}
