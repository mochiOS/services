//! Native-only test payload: query every grant, call POSIX, report identity.
//! All selectors, capability names and wire bytes come from the public APIs.
use mochi_user_syscall::SyscallNumber as S;
use mochios_posix_protocol as posix;

pub const REPORT_KEY: u64 = u64::from_le_bytes(*b"STND0329");
pub const REQUEST_ID: u64 = 329;
pub const CONTEXT_BYTES: usize = core::mem::size_of::<mnu_abi::ThreadSecurityContext>();
pub const REPORT_BYTES: usize = CONTEXT_BYTES + posix::HEADER_LEN + posix::SESSION_INFO_LEN;
const ENTRY: u64 = 0x401000;

#[derive(Default)]
struct Code {
    bytes: Vec<u8>,
    failures: Vec<usize>,
    addresses: Vec<(usize, Vec<u8>)>,
}

impl Code {
    fn immediate(&mut self, opcode: &[u8], value: u32) {
        self.bytes.extend_from_slice(opcode);
        self.bytes.extend_from_slice(&value.to_le_bytes());
    }
    fn wide(&mut self, opcode: &[u8], value: u64) {
        self.bytes.extend_from_slice(opcode);
        self.bytes.extend_from_slice(&value.to_le_bytes());
    }
    fn data_address(&mut self, opcode: &[u8], bytes: &[u8]) {
        let offset = self.bytes.len() + opcode.len();
        self.wide(opcode, 0);
        self.addresses.push((offset, bytes.to_vec()));
    }
    fn syscall(&mut self, selector: S) {
        self.immediate(&[0xb8], selector as u32);
        self.bytes.extend_from_slice(&[0x0f, 0x05]);
    }
    fn branch(&mut self, condition: u8) {
        self.bytes.extend_from_slice(&[0x0f, condition]);
        self.failures.push(self.bytes.len());
        self.bytes.extend_from_slice(&[0; 4]);
    }
    fn zero(&mut self) {
        self.bytes.extend_from_slice(&[0x48, 0x85, 0xc0]); // test rax, rax
        self.branch(0x85); // jne fail
    }
    fn count(&mut self, length: usize) {
        self.immediate(&[0x3d], length as u32); // cmp eax, length
        self.branch(0x85);
    }
    fn launch_handle(&mut self, key: u64) {
        self.wide(&[0x48, 0xbf], key); // mov rdi, key
        self.syscall(S::LaunchHandleGet);
        self.bytes.extend_from_slice(&[0x48, 0x85, 0xc0]);
        self.branch(0x8e); // jle fail (zero or a tagged native error)
    }
    fn exit(&mut self, status: u32) {
        self.immediate(&[0xbf], status);
        self.syscall(S::ProcessExit);
        self.bytes.extend_from_slice(&[0x0f, 0x0b]);
    }
    fn finish(mut self) -> Vec<u8> {
        let failure = self.bytes.len();
        self.exit(99);
        for offset in self.failures {
            let displacement = i32::try_from(failure as isize - (offset + 4) as isize).unwrap();
            self.bytes[offset..offset + 4].copy_from_slice(&displacement.to_le_bytes());
        }
        for (offset, data) in self.addresses {
            let address = ENTRY + self.bytes.len() as u64;
            self.bytes[offset..offset + 8].copy_from_slice(&address.to_le_bytes());
            self.bytes.extend_from_slice(&data);
        }
        self.bytes
    }
}

pub fn unsigned() -> Vec<u8> {
    let mut code = Code::default();
    code.immediate(&[0x48, 0x81, 0xec], 1024); // sub rsp, 1024
    code.launch_handle(REPORT_KEY);
    code.bytes.extend_from_slice(&[0x41, 0x89, 0xc4]); // mov r12d, eax
    for capability in mnu_abi::capability::CAPABILITIES {
        code.data_address(&[0x48, 0xbf], capability.name.as_bytes());
        code.immediate(&[0xbe], capability.name.len() as u32);
        code.syscall(S::CapQuery);
        code.zero();
    }
    code.bytes
        .extend_from_slice(&[0x31, 0xff, 0x48, 0x89, 0xe6]); // edi=0; rsi=rsp
    code.immediate(&[0xba], CONTEXT_BYTES as u32);
    code.syscall(S::GetThreadSecurityContext);
    code.zero();
    code.launch_handle(posix::CONTROL_HANDLE_KEY);
    code.bytes.extend_from_slice(&[0x89, 0xc7]); // mov edi, eax
    let mut request = [0; posix::HEADER_LEN];
    posix::encode(
        posix::Header {
            opcode: posix::OP_SESSION_INFO,
            request_id: REQUEST_ID,
            ..Default::default()
        },
        &[],
        &mut request,
    )
    .unwrap();
    code.data_address(&[0x48, 0xbe], &request); // mov rsi, request
    code.immediate(&[0xba], request.len() as u32);
    code.immediate(&[0x4c, 0x8d, 0x94, 0x24], CONTEXT_BYTES as u32); // lea r10, [rsp+context]
    code.immediate(&[0x41, 0xb8], (REPORT_BYTES - CONTEXT_BYTES) as u32);
    code.syscall(S::IpcCall);
    code.count(REPORT_BYTES - CONTEXT_BYTES);
    code.bytes
        .extend_from_slice(&[0x44, 0x89, 0xe7, 0x48, 0x89, 0xe6]); // edi=r12d; rsi=rsp
    code.immediate(&[0xba], REPORT_BYTES as u32);
    code.syscall(S::HandleWrite);
    code.count(REPORT_BYTES);
    code.exit(37);
    let code = code.finish();
    let mut elf = super::signed_elf::unsigned();
    elf.resize(0x1000, 0);
    elf.extend_from_slice(&code);
    elf[24..32].copy_from_slice(&ENTRY.to_le_bytes());
    elf[32..40].copy_from_slice(&64u64.to_le_bytes());
    elf[54..56].copy_from_slice(&56u16.to_le_bytes());
    elf[56..58].copy_from_slice(&1u16.to_le_bytes());
    elf[64..68].copy_from_slice(&1u32.to_le_bytes());
    elf[68..72].copy_from_slice(&5u32.to_le_bytes());
    elf[80..88].copy_from_slice(&0x400000u64.to_le_bytes());
    let length = elf.len() as u64;
    elf[96..104].copy_from_slice(&length.to_le_bytes());
    elf[104..112].copy_from_slice(&length.to_le_bytes());
    elf[112..120].copy_from_slice(&4096u64.to_le_bytes());
    let text = 0x100 + 2 * 64;
    elf[text + 24..text + 32].copy_from_slice(&0x1000u64.to_le_bytes());
    elf[text + 32..text + 40].copy_from_slice(&(code.len() as u64).to_le_bytes());
    elf
}
