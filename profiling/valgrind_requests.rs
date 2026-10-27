const MEMCHECK_TOOL_BASE: u64 = (b'M' as u64) << 24 | (b'C' as u64) << 16;
const MAKE_MEM_UNDEFINED: u64 = MEMCHECK_TOOL_BASE + 1;
const MAKE_MEM_DEFINED: u64 = MEMCHECK_TOOL_BASE + 2;

#[cfg(all(target_arch = "aarch64", target_os = "linux"))]
fn client_request(request: u64, address: usize, length: usize) {
    let arguments: [u64; 6] = [request, address as u64, length as u64, 0, 0, 0];
    let mut result: u64 = 0;
    unsafe {
        std::arch::asm!(
            "ror x12, x12, #3",
            "ror x12, x12, #13",
            "ror x12, x12, #51",
            "ror x12, x12, #61",
            "orr x10, x10, x10",
            inout("x3") result,
            in("x4") arguments.as_ptr(),
            out("x12") _,
            options(nostack),
        );
    }
    std::hint::black_box(result);
}

#[cfg(all(target_arch = "x86_64", target_os = "linux"))]
fn client_request(request: u64, address: usize, length: usize) {
    let arguments: [u64; 6] = [request, address as u64, length as u64, 0, 0, 0];
    let mut result: u64 = 0;
    unsafe {
        std::arch::asm!(
            "rol rdi, 3",
            "rol rdi, 13",
            "rol rdi, 61",
            "rol rdi, 51",
            "xchg rbx, rbx",
            inout("rdx") result,
            in("rax") arguments.as_ptr(),
            out("rdi") _,
            options(nostack),
        );
    }
    std::hint::black_box(result);
}

#[cfg(not(all(
    any(target_arch = "aarch64", target_arch = "x86_64"),
    target_os = "linux"
)))]
fn client_request(_request: u64, _address: usize, _length: usize) {}

pub fn classify(bytes: &mut [u8]) {
    client_request(MAKE_MEM_UNDEFINED, bytes.as_ptr() as usize, bytes.len());
}

pub fn declassify(bytes: &[u8]) {
    client_request(MAKE_MEM_DEFINED, bytes.as_ptr() as usize, bytes.len());
}
