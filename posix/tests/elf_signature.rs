//! Existing v1 wire/bounds/tamper tests against the production shared codec.
extern crate alloc;
include!("../../../user/crates/elf-signature/src/codec.rs");

#[cfg(test)]
mod tests {
    use super::*;

    struct Resolver(VerifyingKey);
    impl PublicKeyResolver for Resolver {
        fn resolve(&self, key_id: &[u8; 32]) -> Result<Option<VerifyingKey>> {
            let own: [u8; 32] = Sha256::digest(self.0.to_bytes()).into();
            Ok((own == *key_id).then_some(self.0))
        }
    }

    fn fixture() -> Vec<u8> {
        let shstr = b"\0.shstrtab\0.text\0";
        let mut elf = vec![0u8; 0x100];
        elf[..4].copy_from_slice(ELF_MAGIC);
        elf[4] = 2;
        elf[5] = 1;
        elf[6] = 1;
        put_u16(&mut elf, 16, ET_EXEC);
        put_u16(&mut elf, 18, 62);
        put_u32(&mut elf, 20, 1);
        put_u64(&mut elf, 24, 0x80);
        put_u16(&mut elf, 52, 64);
        put_u16(&mut elf, 58, 64);
        elf[0x80..0x84].copy_from_slice(&[0x90, 0x90, 0xc3, 0]);
        elf[0x90..0x90 + shstr.len()].copy_from_slice(shstr);
        let table = 0x100;
        elf.resize(table + 3 * 64, 0);
        put_u64(&mut elf, 40, table as u64);
        put_u16(&mut elf, 60, 3);
        put_u16(&mut elf, 62, 1);
        put_u32(&mut elf, table + 64, 1);
        put_u32(&mut elf, table + 68, SHT_STRTAB);
        put_u64(&mut elf, table + 64 + 24, 0x90);
        put_u64(&mut elf, table + 64 + 32, shstr.len() as u64);
        put_u64(&mut elf, table + 64 + 48, 1);
        put_u32(&mut elf, table + 128, 11);
        put_u32(&mut elf, table + 132, 1);
        put_u64(&mut elf, table + 128 + 24, 0x80);
        put_u64(&mut elf, table + 128 + 32, 4);
        put_u64(&mut elf, table + 128 + 48, 16);
        elf
    }

    #[test]
    fn adhoc_round_trip_and_tamper_detection() {
        let signed = sign_adhoc(&fixture()).unwrap();
        let decoded = decode(&signed).unwrap();
        assert_eq!(decoded.kind, SignatureKind::AdHoc);
        assert_eq!(decoded.digest_algorithm, DIGEST_SHA256);
        assert_eq!(decoded.signature_algorithm, SIGNATURE_NONE);
        assert_eq!(decoded.flags, 0);
        assert_eq!(decoded.key_id, [0; 32]);
        assert_eq!(decoded.signature, [0; 64]);
        assert_eq!(verify(&signed, None).unwrap().kind, SignatureKind::AdHoc);
        let mut tampered = signed.clone();
        tampered[0x80] ^= 1;
        assert!(
            verify(&tampered, None)
                .unwrap_err()
                .to_string()
                .contains("digest mismatch")
        );
        assert!(
            sign_adhoc(&signed)
                .unwrap_err()
                .to_string()
                .contains("already contains")
        );
    }

    #[test]
    fn keyed_round_trip_is_fail_closed_and_binds_key_id() {
        let key = SigningKey::from_bytes(&[7u8; 32]);
        let signed = sign_ed25519(&fixture(), &key).unwrap();
        assert!(
            verify(&signed, None)
                .unwrap_err()
                .to_string()
                .contains("public key is required")
        );
        let verified = verify(&signed, Some(&Resolver(key.verifying_key()))).unwrap();
        assert_eq!(verified.kind, SignatureKind::Ed25519);
        assert_eq!(
            verified.key_id.unwrap(),
            Sha256::digest(key.verifying_key().to_bytes()).as_slice()
        );
        let wrong = SigningKey::from_bytes(&[8u8; 32]).verifying_key();
        assert!(
            verify(&signed, Some(&Resolver(wrong)))
                .unwrap_err()
                .to_string()
                .contains("unresolved")
        );
    }

    #[test]
    fn malformed_unknown_version_and_signature_tampering_are_rejected() {
        let key = SigningKey::from_bytes(&[9u8; 32]);
        let signed = sign_ed25519(&fixture(), &key).unwrap();
        let record = locate_record(&signed).unwrap().unwrap();
        let descriptor = record.digest_file_offset - DIGEST_OFFSET;
        let mut version = signed.clone();
        version[descriptor + 8] = 2;
        assert!(
            verify(&version, Some(&Resolver(key.verifying_key())))
                .unwrap_err()
                .to_string()
                .contains("unsupported ELF signature version")
        );
        let mut signature = signed.clone();
        signature[record.signature_file_offset] ^= 1;
        assert!(verify(&signature, Some(&Resolver(key.verifying_key()))).is_err());
        let mut malformed = signed;
        put_u64(&mut malformed, 40, u64::MAX);
        assert!(verify(&malformed, None).is_err());
    }

    #[test]
    fn duplicate_note_is_rejected_even_when_two_headers_reference_one_note() {
        let signed = sign_adhoc(&fixture()).unwrap();
        let parsed = parse_elf(&signed).unwrap();
        let signature_section = parsed
            .sections
            .iter()
            .find(|section| section.section_type == SHT_NOTE)
            .unwrap();
        let old_table = read_u64(&signed, 40).unwrap() as usize;
        let old_count = read_u16(&signed, 60).unwrap() as usize;
        let mut duplicate = signed.clone();
        pad_to(&mut duplicate, 8).unwrap();
        let new_table = duplicate.len();
        duplicate.extend_from_slice(&signed[old_table..old_table + old_count * 64]);
        duplicate.extend_from_slice(
            &signed[signature_section.raw_offset..signature_section.raw_offset + 64],
        );
        put_u64(&mut duplicate, 40, new_table as u64);
        put_u16(&mut duplicate, 60, (old_count + 1) as u16);
        assert!(
            verify(&duplicate, None)
                .unwrap_err()
                .to_string()
                .contains("duplicate")
        );
    }

    #[test]
    fn two_physical_signature_notes_are_rejected() {
        let signed = sign_adhoc(&fixture()).unwrap();
        let parsed = parse_elf(&signed).unwrap();
        let signature_section = parsed
            .sections
            .iter()
            .find(|section| section.section_type == SHT_NOTE)
            .unwrap();
        let old_table = read_u64(&signed, 40).unwrap() as usize;
        let old_count = read_u16(&signed, 60).unwrap() as usize;
        let note = signed
            [signature_section.offset..signature_section.offset + signature_section.size]
            .to_vec();

        let mut duplicate = signed.clone();
        pad_to(&mut duplicate, 4).unwrap();
        let second_note = duplicate.len();
        duplicate.extend_from_slice(&note);
        pad_to(&mut duplicate, 8).unwrap();
        let new_table = duplicate.len();
        duplicate.extend_from_slice(&signed[old_table..old_table + old_count * 64]);
        let second_header = duplicate.len();
        duplicate.extend_from_slice(
            &signed[signature_section.raw_offset
                ..signature_section.raw_offset + ELF64_SECTION_HEADER_LEN],
        );
        put_u64(&mut duplicate, second_header + 24, second_note as u64);
        put_u64(&mut duplicate, 40, new_table as u64);
        put_u16(&mut duplicate, 60, (old_count + 1) as u16);

        assert!(
            verify(&duplicate, None)
                .unwrap_err()
                .to_string()
                .contains("duplicate")
        );
    }

    #[test]
    fn signing_message_layout_and_little_endian_flags_are_fixed() {
        let key_id = [0x55; 32];
        let digest = [0xaa; 32];
        let message = signing_message(
            KIND_ED25519,
            DIGEST_SHA256,
            SIGNATURE_ED25519,
            0x0102_0304,
            &key_id,
            &digest,
        );
        assert_eq!(message.len(), 96);
        assert_eq!(&message[..25], b"mochios-elf-signature-v1\0");
        assert_eq!(
            &message[25..28],
            &[KIND_ED25519, DIGEST_SHA256, SIGNATURE_ED25519]
        );
        assert_eq!(&message[28..32], &[0x04, 0x03, 0x02, 0x01]);
        assert_eq!(&message[32..64], &key_id);
        assert_eq!(&message[64..96], &digest);
    }

    #[test]
    fn unknown_algorithm_flags_and_invalid_note_length_are_rejected() {
        let signed = sign_adhoc(&fixture()).unwrap();
        let record = locate_record(&signed).unwrap().unwrap();
        let descriptor = record.digest_file_offset - DIGEST_OFFSET;

        let mut algorithm = signed.clone();
        algorithm[descriptor + 11] = 0xff;
        assert!(
            decode(&algorithm)
                .unwrap_err()
                .to_string()
                .contains("unsupported ELF digest algorithm")
        );

        let mut flags = signed.clone();
        flags[descriptor + 14] = 1;
        assert!(
            decode(&flags)
                .unwrap_err()
                .to_string()
                .contains("unsupported ELF signature flags")
        );

        let note_header = descriptor - NOTE_NAME.len() - 12;
        let mut length = signed;
        put_u32(&mut length, note_header + 4, (DESCRIPTOR_LEN - 1) as u32);
        assert!(
            decode(&length)
                .unwrap_err()
                .to_string()
                .contains("descriptor length")
        );
    }

    #[test]
    fn sectionless_signing_constraint_is_explicit() {
        let mut elf = fixture();
        put_u64(&mut elf, 40, 0);
        put_u16(&mut elf, 58, 0);
        put_u16(&mut elf, 60, 0);
        put_u16(&mut elf, 62, 0);
        elf.truncate(0x100);
        assert!(
            sign_adhoc(&elf)
                .unwrap_err()
                .to_string()
                .contains("requires a Section Header Table")
        );
    }
}
