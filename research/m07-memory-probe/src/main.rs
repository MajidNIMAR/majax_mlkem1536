//! Measurement-only native stack watermark and requested Rust allocation probe.
//! Unsafe code is confined to this separate executable, never the KEM crate.
#![deny(unsafe_op_in_unsafe_fn)]
#[cfg(not(all(
    target_arch = "x86_64",
    any(target_os = "windows", target_os = "linux")
)))]
compile_error!("The M07 native probe is restricted to x86-64 Windows and Linux.");

use kem1536::dev_kem as r1;
use serde_json::json;
use shake::{ExtendableOutput, Shake256, Update, XofReader};
use std::alloc::{GlobalAlloc, Layout, System};
use std::hint::black_box;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, AtomicUsize, Ordering::SeqCst};
use zeroize::Zeroizing;

const STACK_BYTES: usize = 1024 * 1024;
const SEARCH_BYTES: usize = 256 * 1024;
const TOP_MARGIN: usize = 512;
const SLOTS: usize = 128;
static ACTIVE: AtomicBool = AtomicBool::new(false);
static POINTERS: [AtomicUsize; SLOTS] = [const { AtomicUsize::new(0) }; SLOTS];
static SIZES: [AtomicUsize; SLOTS] = [const { AtomicUsize::new(0) }; SLOTS];
static ALLOC: AtomicU64 = AtomicU64::new(0);
static ZEROED: AtomicU64 = AtomicU64::new(0);
static REALLOC: AtomicU64 = AtomicU64::new(0);
static DEALLOC: AtomicU64 = AtomicU64::new(0);
static FAILED: AtomicU64 = AtomicU64::new(0);
static FOREIGN: AtomicU64 = AtomicU64::new(0);
static OVERFLOW: AtomicU64 = AtomicU64::new(0);
static REQUESTED: AtomicU64 = AtomicU64::new(0);
static LIVE: AtomicI64 = AtomicI64::new(0);
static PEAK: AtomicU64 = AtomicU64::new(0);

struct CountingAllocator;
#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;

#[inline(always)]
fn change_live(delta: i64) {
    let now = LIVE.fetch_add(delta, SeqCst) + delta;
    if now < 0 {
        OVERFLOW.fetch_add(1, SeqCst);
    } else {
        PEAK.fetch_max(now as u64, SeqCst);
    }
}
#[inline(always)]
fn register(pointer: *mut u8, size: usize) {
    if pointer.is_null() {
        FAILED.fetch_add(1, SeqCst);
        return;
    }
    for index in 0..SLOTS {
        if POINTERS[index].load(SeqCst) == 0 {
            SIZES[index].store(size, SeqCst);
            POINTERS[index].store(pointer as usize, SeqCst);
            change_live(size as i64);
            return;
        }
    }
    OVERFLOW.fetch_add(1, SeqCst);
}
#[inline(always)]
fn unregister(pointer: *mut u8) {
    for index in 0..SLOTS {
        if POINTERS[index].load(SeqCst) == pointer as usize {
            change_live(-(SIZES[index].load(SeqCst) as i64));
            POINTERS[index].store(0, SeqCst);
            return;
        }
    }
    FOREIGN.fetch_add(1, SeqCst);
}

// The probe has one native worker and a parent blocked in join. No logging,
// allocation or mutex is used by these hooks. Only allocation *requests* count.
unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let pointer = unsafe { System.alloc(layout) };
        if ACTIVE.load(SeqCst) {
            ALLOC.fetch_add(1, SeqCst);
            REQUESTED.fetch_add(layout.size() as u64, SeqCst);
            register(pointer, layout.size());
        }
        pointer
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let pointer = unsafe { System.alloc_zeroed(layout) };
        if ACTIVE.load(SeqCst) {
            ZEROED.fetch_add(1, SeqCst);
            REQUESTED.fetch_add(layout.size() as u64, SeqCst);
            register(pointer, layout.size());
        }
        pointer
    }
    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        if ACTIVE.load(SeqCst) {
            DEALLOC.fetch_add(1, SeqCst);
            unregister(pointer);
        }
        unsafe { System.dealloc(pointer, layout) };
    }
    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        let new_pointer = unsafe { System.realloc(pointer, layout, size) };
        if ACTIVE.load(SeqCst) {
            REALLOC.fetch_add(1, SeqCst);
            REQUESTED.fetch_add(size as u64, SeqCst);
            if new_pointer.is_null() {
                FAILED.fetch_add(1, SeqCst);
            } else {
                unregister(pointer);
                register(new_pointer, size);
            }
        }
        new_pointer
    }
}

#[derive(Default)]
struct Outputs {
    keypair: Option<(r1::EncapsulationKey, r1::DecapsulationKey)>,
    encapsulated: Option<(r1::Ciphertext, r1::SharedSecret)>,
    shared: Option<r1::SharedSecret>,
    public: Option<Result<r1::EncapsulationKey, r1::Error>>,
    private: Option<Result<r1::DecapsulationKey, r1::Error>>,
}
struct Inputs {
    ek: r1::EncapsulationKey,
    dk: r1::DecapsulationKey,
    c: r1::Ciphertext,
    altered: r1::Ciphertext,
    expected: r1::SharedSecret,
    rejected: Zeroizing<[u8; 32]>,
    private_bytes: Zeroizing<Vec<u8>>,
    bad_public: Vec<u8>,
    bad_private: Zeroizing<Vec<u8>>,
}
type Callback = unsafe extern "C" fn(*mut Job<'_>) -> bool;
#[derive(Default)]
struct Measurement {
    touched: usize,
    searched: usize,
    saturated: bool,
    known_written: usize,
    allocation_calls: u64,
    zeroed_calls: u64,
    realloc_calls: u64,
    dealloc_calls: u64,
    failed_calls: u64,
    foreign_frees: u64,
    tracker_overflow: u64,
    requested: u64,
    retained: i64,
    peak: u64,
}
struct Job<'a> {
    input: &'a Inputs,
    bytes: &'a [u8],
    callback: Callback,
    outputs: Outputs,
    pattern: u8,
    measurement: Measurement,
    ok: bool,
    error: u32,
    stack_reference: usize,
    calibration_low: usize,
    expected_calibration_size: usize,
}

#[inline(never)]
unsafe extern "C" fn noop(_: *mut Job<'_>) -> bool {
    black_box(());
    true
}
#[inline(never)]
unsafe extern "C" fn keygen(job: *mut Job<'_>) -> bool {
    let job = unsafe { &mut *job };
    match r1::keygen() {
        Ok(pair) => {
            job.outputs.keypair = Some(black_box(pair));
            true
        }
        Err(_) => false,
    }
}
#[inline(never)]
unsafe extern "C" fn encaps(job: *mut Job<'_>) -> bool {
    let job = unsafe { &mut *job };
    match r1::encapsulate(black_box(&job.input.ek)) {
        Ok(pair) => {
            job.outputs.encapsulated = Some(black_box(pair));
            true
        }
        Err(_) => false,
    }
}
#[inline(never)]
unsafe extern "C" fn decaps(job: *mut Job<'_>) -> bool {
    let job = unsafe { &mut *job };
    job.outputs.shared = Some(black_box(r1::decapsulate(&job.input.dk, &job.input.c)));
    true
}
#[inline(never)]
unsafe extern "C" fn reject(job: *mut Job<'_>) -> bool {
    let job = unsafe { &mut *job };
    job.outputs.shared = Some(black_box(r1::decapsulate(
        &job.input.dk,
        &job.input.altered,
    )));
    true
}
#[inline(never)]
unsafe extern "C" fn import_public(job: *mut Job<'_>) -> bool {
    let job = unsafe { &mut *job };
    job.outputs.public = Some(black_box(r1::EncapsulationKey::from_bytes(job.bytes)));
    true
}
#[inline(never)]
unsafe extern "C" fn import_private(job: *mut Job<'_>) -> bool {
    let job = unsafe { &mut *job };
    job.outputs.private = Some(black_box(r1::DecapsulationKey::from_bytes(job.bytes)));
    true
}
#[inline(never)]
unsafe extern "C" fn calibration<const SIZE: usize>(job: *mut Job<'_>) -> bool {
    let mut bytes = [0_u8; SIZE];
    for index in 0..SIZE {
        unsafe { bytes.as_mut_ptr().add(index).write_volatile(0x3c) };
    }
    unsafe { (*job).calibration_low = bytes.as_ptr() as usize };
    black_box(&bytes);
    true
}

#[inline(always)]
fn begin_allocations() {
    for index in 0..SLOTS {
        POINTERS[index].store(0, SeqCst);
        SIZES[index].store(0, SeqCst);
    }
    for counter in [
        &ALLOC, &ZEROED, &REALLOC, &DEALLOC, &FAILED, &FOREIGN, &OVERFLOW, &REQUESTED, &PEAK,
    ] {
        counter.store(0, SeqCst);
    }
    LIVE.store(0, SeqCst);
    ACTIVE.store(true, SeqCst);
}

/// All local frame space is allocated by the prologue before RSP is observed.
/// Paint/scan are volatile inline loops and never invoke memset or a helper.
#[inline(never)]
unsafe fn measure(job: &mut Job<'_>) {
    job.ok = unsafe { (job.callback)(job) }; // Warm runtime/provider paths first.
    job.outputs = Outputs::default(); // Warm-up outputs are dropped before paint.
    job.calibration_low = 0;
    let Some((low, high)) = native::bounds() else {
        job.error = 1;
        return;
    };
    let reference: usize;
    unsafe {
        std::arch::asm!("mov {}, rsp", out(reg) reference, options(nostack, preserves_flags))
    };
    if reference <= low + 8192 || reference >= high {
        job.error = 2;
        return;
    }
    let bottom = reference.saturating_sub(SEARCH_BYTES).max(low + 8192);
    let top = reference - TOP_MARGIN;
    if top <= bottom || !native::writable(bottom, top) {
        job.error = 3;
        return;
    }
    job.stack_reference = reference;
    for address in bottom..top {
        unsafe { (address as *mut u8).write_volatile(job.pattern) };
    }
    begin_allocations();
    let actual_ok = unsafe { (job.callback)(job) };
    job.ok = job.ok && actual_ok;
    ACTIVE.store(false, SeqCst);
    let mut first = top;
    for address in bottom..top {
        if unsafe { (address as *const u8).read_volatile() } != job.pattern {
            first = address;
            break;
        }
    }
    let known_written = if job.expected_calibration_size == 0 {
        if job.calibration_low != 0 {
            job.error = 4;
            return;
        }
        0
    } else {
        if job.calibration_low < bottom || job.calibration_low >= top {
            job.error = 4;
            return;
        }
        let depth = reference - job.calibration_low;
        if depth < job.expected_calibration_size {
            job.error = 4;
            return;
        }
        depth
    };
    job.measurement = Measurement {
        touched: if first == top { 0 } else { reference - first },
        searched: top - bottom,
        saturated: first == bottom,
        known_written,
        allocation_calls: ALLOC.load(SeqCst),
        zeroed_calls: ZEROED.load(SeqCst),
        realloc_calls: REALLOC.load(SeqCst),
        dealloc_calls: DEALLOC.load(SeqCst),
        failed_calls: FAILED.load(SeqCst),
        foreign_frees: FOREIGN.load(SeqCst),
        tracker_overflow: OVERFLOW.load(SeqCst),
        requested: REQUESTED.load(SeqCst),
        retained: LIVE.load(SeqCst),
        peak: PEAK.load(SeqCst),
    };
}

#[cfg(target_os = "windows")]
mod native {
    use super::*;
    use std::ffi::c_void;
    #[repr(C)]
    struct MemoryInfo {
        base: *mut c_void,
        allocation_base: *mut c_void,
        allocation_protect: u32,
        partition: u16,
        padding: u16,
        region_size: usize,
        state: u32,
        protect: u32,
        kind: u32,
        padding2: u32,
    }
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn CreateThread(
            attributes: *mut c_void,
            size: usize,
            start: unsafe extern "system" fn(*mut c_void) -> u32,
            argument: *mut c_void,
            flags: u32,
            id: *mut u32,
        ) -> *mut c_void;
        fn WaitForSingleObject(handle: *mut c_void, milliseconds: u32) -> u32;
        fn CloseHandle(handle: *mut c_void) -> i32;
        fn GetCurrentThreadStackLimits(low: *mut usize, high: *mut usize);
        fn VirtualQuery(address: *const c_void, buffer: *mut MemoryInfo, length: usize) -> usize;
    }
    unsafe extern "system" fn start(argument: *mut c_void) -> u32 {
        unsafe { measure(&mut *(argument as *mut Job<'_>)) };
        0
    }
    pub fn run(job: &mut Job<'_>) {
        unsafe {
            let handle = CreateThread(
                std::ptr::null_mut(),
                STACK_BYTES,
                start,
                job as *mut _ as *mut c_void,
                0,
                std::ptr::null_mut(),
            );
            assert!(!handle.is_null(), "native thread creation failed");
            let waited = WaitForSingleObject(handle, u32::MAX);
            if waited != 0 {
                std::process::abort();
            } // Job may still be borrowed by the worker.
            let closed = CloseHandle(handle);
            assert_ne!(closed, 0, "native thread close failed");
        }
    }
    pub fn bounds() -> Option<(usize, usize)> {
        let (mut low, mut high) = (0, 0);
        unsafe { GetCurrentThreadStackLimits(&mut low, &mut high) };
        (low < high).then_some((low, high))
    }
    pub fn writable(mut low: usize, high: usize) -> bool {
        while low < high {
            let mut info = std::mem::MaybeUninit::<MemoryInfo>::zeroed();
            let size = unsafe {
                VirtualQuery(
                    low as *const c_void,
                    info.as_mut_ptr(),
                    std::mem::size_of::<MemoryInfo>(),
                )
            };
            if size != std::mem::size_of::<MemoryInfo>() {
                return false;
            }
            let info = unsafe { info.assume_init() };
            if info.state != 0x1000
                || info.protect & 0x101 != 0
                || info.protect & (0x04 | 0x08 | 0x40 | 0x80) == 0
            {
                return false;
            }
            let next = (info.base as usize).saturating_add(info.region_size);
            if next <= low {
                return false;
            }
            low = next;
        }
        true
    }
}

#[cfg(target_os = "linux")]
mod native {
    use super::*;
    use std::ffi::c_void;
    extern "C" fn start(argument: *mut c_void) -> *mut c_void {
        unsafe { measure(&mut *(argument as *mut Job<'_>)) };
        std::ptr::null_mut()
    }
    pub fn run(job: &mut Job<'_>) {
        unsafe {
            let mut attributes = std::mem::MaybeUninit::<libc::pthread_attr_t>::uninit();
            assert_eq!(libc::pthread_attr_init(attributes.as_mut_ptr()), 0);
            let mut attributes = attributes.assume_init();
            assert_eq!(
                libc::pthread_attr_setstacksize(&mut attributes, STACK_BYTES),
                0
            );
            let mut thread = std::mem::MaybeUninit::<libc::pthread_t>::uninit();
            let created = libc::pthread_create(
                thread.as_mut_ptr(),
                &attributes,
                start,
                job as *mut _ as *mut c_void,
            );
            let destroyed = libc::pthread_attr_destroy(&mut attributes);
            assert_eq!(created, 0, "native thread creation failed");
            let joined = libc::pthread_join(thread.assume_init(), std::ptr::null_mut());
            if joined != 0 {
                std::process::abort();
            } // Never unwind while a worker may still own Job.
            assert_eq!(destroyed, 0);
        }
    }
    pub fn bounds() -> Option<(usize, usize)> {
        unsafe {
            let mut attributes = std::mem::MaybeUninit::<libc::pthread_attr_t>::uninit();
            if libc::pthread_getattr_np(libc::pthread_self(), attributes.as_mut_ptr()) != 0 {
                return None;
            }
            let mut attributes = attributes.assume_init();
            let mut address = std::ptr::null_mut();
            let mut size = 0;
            let result = libc::pthread_attr_getstack(&attributes, &mut address, &mut size);
            let destroyed = libc::pthread_attr_destroy(&mut attributes);
            if result != 0 || destroyed != 0 {
                return None;
            }
            Some((address as usize, (address as usize).checked_add(size)?))
        }
    }
    pub fn writable(_: usize, _: usize) -> bool {
        true
    } // Bounds are the native pthread-owned usable stack.
}

fn inputs() -> Inputs {
    let (ek, dk) = r1::keygen().expect("input key generation failed");
    let (c, expected) = r1::encapsulate(&ek).expect("input encapsulation failed");
    assert!(r1::decapsulate(&dk, &c).matches(&expected));
    let mut bad = c.as_bytes().to_vec();
    bad[0] = 255;
    bad[1] |= 31;
    let altered = r1::Ciphertext::from_bytes(&bad).expect("ciphertext import failed");
    let private_bytes = dk.to_bytes();
    let mut h = Shake256::default();
    h.update(b"KEM1536-DEV-Q7681-R1\0");
    h.update(b"J\0");
    h.update(&private_bytes[r1::PRIVATE_KEY_BYTES - 32..]);
    h.update(altered.as_bytes());
    let mut rejected = Zeroizing::new([0; 32]);
    h.finalize_xof().read(&mut rejected[..]);
    assert!(r1::decapsulate(&dk, &altered).as_bytes() == &*rejected);
    assert!(expected.as_bytes() != &*rejected);
    let mut bad_public = ek.as_bytes().to_vec();
    bad_public[0] = 255;
    bad_public[1] |= 31;
    let mut bad_private = dk.to_bytes();
    bad_private[r1::PRIVATE_KEY_BYTES - 64] ^= 1;
    Inputs {
        ek,
        dk,
        c,
        altered,
        expected,
        rejected,
        private_bytes,
        bad_public,
        bad_private,
    }
}

fn validate(operation: &str, job: &Job<'_>) {
    match operation {
        "keygen" => {
            let (ek, dk) = job.outputs.keypair.as_ref().expect("missing key pair");
            let (c, s) = r1::encapsulate(ek).expect("keypair validation failed");
            assert!(r1::decapsulate(dk, &c).matches(&s));
        }
        "encaps" => {
            let (c, s) = job
                .outputs
                .encapsulated
                .as_ref()
                .expect("missing encapsulation");
            assert!(r1::decapsulate(&job.input.dk, c).matches(s));
        }
        "decaps_valid" => assert!(job
            .outputs
            .shared
            .as_ref()
            .expect("missing secret")
            .matches(&job.input.expected)),
        "decaps_reject" => assert!(
            job.outputs
                .shared
                .as_ref()
                .expect("missing secret")
                .as_bytes()
                == &*job.input.rejected
        ),
        "import_public_valid" => {
            let ek = job
                .outputs
                .public
                .as_ref()
                .expect("missing public import")
                .as_ref()
                .expect("public import failed");
            assert!(ek.as_bytes() == job.input.ek.as_bytes());
        }
        "import_private_valid" => {
            let dk = job
                .outputs
                .private
                .as_ref()
                .expect("missing private import")
                .as_ref()
                .expect("private import failed");
            assert!(r1::decapsulate(dk, &job.input.c).matches(&job.input.expected));
        }
        "import_public_noncanonical" => assert!(matches!(
            job.outputs.public,
            Some(Err(r1::Error::NoncanonicalEncoding))
        )),
        "import_private_hash" => assert!(matches!(
            job.outputs.private,
            Some(Err(r1::Error::InconsistentPrivateKey))
        )),
        "import_public_short" => assert!(matches!(
            job.outputs.public,
            Some(Err(r1::Error::InvalidLength))
        )),
        "import_private_short" => assert!(matches!(
            job.outputs.private,
            Some(Err(r1::Error::InvalidLength))
        )),
        _ => (),
    }
}

fn main() {
    let samples: usize = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "3".to_owned())
        .parse()
        .expect("sample count");
    assert!((1..=1000).contains(&samples));
    let inputs = inputs();
    let operations: [(&str, Callback, &[u8]); 14] = [
        ("noop", noop, &[]),
        ("calibration_8192", calibration::<8192>, &[]),
        ("calibration_32768", calibration::<32768>, &[]),
        ("calibration_65536", calibration::<65536>, &[]),
        ("keygen", keygen, &[]),
        ("encaps", encaps, &[]),
        ("decaps_valid", decaps, &[]),
        ("decaps_reject", reject, &[]),
        ("import_public_valid", import_public, inputs.ek.as_bytes()),
        (
            "import_private_valid",
            import_private,
            &inputs.private_bytes,
        ),
        (
            "import_public_noncanonical",
            import_public,
            &inputs.bad_public,
        ),
        ("import_private_hash", import_private, &inputs.bad_private),
        (
            "import_public_short",
            import_public,
            &inputs.ek.as_bytes()[..7],
        ),
        (
            "import_private_short",
            import_private,
            &inputs.private_bytes[..7],
        ),
    ];
    for (operation, callback, bytes) in operations {
        for pattern in [0xa5, 0x5a] {
            for sample in 0..samples {
                let mut job = Job {
                    input: &inputs,
                    bytes,
                    callback,
                    outputs: Outputs::default(),
                    pattern,
                    measurement: Measurement::default(),
                    ok: false,
                    error: 0,
                    stack_reference: 0,
                    calibration_low: 0,
                    expected_calibration_size: match operation {
                        "calibration_8192" => 8192,
                        "calibration_32768" => 32768,
                        "calibration_65536" => 65536,
                        _ => 0,
                    },
                };
                native::run(&mut job);
                let m = &job.measurement;
                assert!(job.ok && job.error == 0, "native measurement failed");
                assert!(
                    !m.saturated
                        && m.tracker_overflow == 0
                        && m.foreign_frees == 0
                        && m.failed_calls == 0
                        && m.retained >= 0,
                    "measurement overflow, saturation or allocation-accounting failure"
                );
                assert!(
                    m.known_written == 0 || m.touched >= m.known_written,
                    "stack calibration was underestimated"
                );
                validate(operation, &job); // Tracking is disabled; returned owners still live.
                println!(
                    "{}",
                    json!({"schema":1,"profile":r1::PROFILE,"operation":operation,"sample":sample,
                    "paint_pattern":pattern,"native_stack_size_requested":STACK_BYTES,"paint_top_margin_bytes":TOP_MARGIN,
                    "paint_search_bytes":m.searched,"touched_stack_high_water_bytes":m.touched,
                    "known_written_calibration_depth_bytes":m.known_written,"saturated":m.saturated,
                    "calibration_written_array_bytes":job.expected_calibration_size,
                    "alloc_calls":m.allocation_calls,"alloc_zeroed_calls":m.zeroed_calls,"realloc_calls":m.realloc_calls,
                    "dealloc_calls":m.dealloc_calls,"allocation_failures":m.failed_calls,"foreign_deallocations":m.foreign_frees,
                    "tracker_overflows":m.tracker_overflow,"total_requested_bytes":m.requested,
                    "retained_requested_bytes_at_api_return":m.retained,"peak_live_requested_bytes":m.peak,
                    "functional_validation":true,"secrets_printed":false})
                );
                // Returned objects are dropped here, after capture and validation.
            }
        }
    }
}
