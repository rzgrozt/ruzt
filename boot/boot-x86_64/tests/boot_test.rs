use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

#[path = "support/ivshmem.rs"]
#[cfg(target_os = "linux")]
mod ivshmem;

// Firmware boot under TCG is sensitive to several guests competing on a
// small CI runner. Keep independent image builds parallel.
static QEMU_SLOT: Mutex<()> = Mutex::new(());

const BOOT_TIMEOUT: Duration = Duration::from_secs(90);
const ACTION_TIMEOUT: Duration = Duration::from_secs(30);
const GUEST_TIMEOUT: Duration =
    Duration::from_secs(BOOT_TIMEOUT.as_secs() + ACTION_TIMEOUT.as_secs() + 5);

fn qemu_slot() -> MutexGuard<'static, ()> {
    QEMU_SLOT.lock().unwrap_or_else(PoisonError::into_inner)
}

#[test]
fn test_kernel_boots_and_schedules_blocking_ipc() {
    let temp = tempfile::tempdir().expect("Failed to create boot test directory");
    let disk_image = build_image(temp.path(), "qemu-smoke-test", Services::None);
    let serial = run_smoke_test(&disk_image, &["-machine", "pc,acpi=off"]);
    assert_markers(
        &serial,
        &[
            "Ruzt booting...",
            "EXCEPTION: BREAKPOINT",
            "Breakpoint returned cleanly.",
            "8259 PIC interrupt routing enabled",
            "thread A ticking",
            "thread B ticking",
            "ipc_test_receiver: got message: Hello, IPC!",
            "ipc_test_sender: message sent successfully",
        ],
    );
}

#[test]
fn test_bios_starts_secondary_cpus_and_delivers_ipis() {
    let temp = tempfile::tempdir().expect("create SMP test directory");
    let disk_image = build_image(temp.path(), "qemu-smoke-test,qemu-smp-test", Services::None);
    let serial = run_smoke_test(&disk_image, &["-smp", "4"]);
    assert_markers(
        &serial,
        &[
            "Local APIC and I/O APIC interrupt routing enabled",
            "SMP APIC 1 online and acknowledged a wake IPI",
            "SMP APIC 2 online and acknowledged a wake IPI",
            "SMP APIC 3 online and acknowledged a wake IPI",
            "SMP initialized 3 secondary CPUs",
            "SMP TLB shootdown replaced a translation cached on every secondary",
            "SMP TLB shootdown reclaimed page tables active on the secondaries",
            "SMP scheduler migrated a saved worker and reaped all worker stacks",
            "SMP heap released a CPU-local allocation after migration",
            "SMP IPC registered a waiter and completed a cross-CPU rendezvous",
            "SMP LAPIC probe distinguished pending and idle boot CPU vectors",
            "ipc_test_sender: message sent successfully",
        ],
    );
}

#[test]
fn test_double_fault_uses_an_emergency_stack_even_with_serial_locked() {
    let temp = tempfile::tempdir().expect("create double-fault test directory");
    let disk = build_image(temp.path(), "qemu-double-fault-test", Services::None);
    let serial = run_smoke_test(&disk, &[]);
    assert_markers(
        &serial,
        &[
            "testing double fault with an unmapped stack",
            "EXCEPTION: DOUBLE FAULT (0x0)",
            "double fault entered the emergency stack while the serial lock was held",
        ],
    );
}

#[test]
fn test_uefi_boots_user_services_with_a_randomized_kernel() {
    let temp = tempfile::tempdir().expect("create UEFI test directory");
    let disk = build_firmware_image(
        temp.path(),
        "qemu-rootsrv-test,qemu-kaslr-test,qemu-smp-test",
        Services::PciInterruptConsole,
        true,
    );
    let (code, vars) = [
        (
            "/usr/share/OVMF/OVMF_CODE_4M.fd",
            "/usr/share/OVMF/OVMF_VARS_4M.fd",
        ),
        (
            "/usr/share/edk2/x64/OVMF_CODE.4m.fd",
            "/usr/share/edk2/x64/OVMF_VARS.4m.fd",
        ),
    ]
    .into_iter()
    .map(|(code, vars)| (Path::new(code), Path::new(vars)))
    .find(|(code, vars)| code.is_file() && vars.is_file())
    .expect("install the OVMF code and variables template");
    let mut addresses = [0; 2];
    for (index, address) in addresses.iter_mut().enumerate() {
        let serial_path = temp.path().join(format!("serial-{index}.log"));
        let [first, code_arg, second, vars_arg] =
            boot_x86_64::ovmf_drives(code, vars, &temp.path().join(format!("vars-{index}.fd")))
                .expect("copy OVMF variables");
        let isolated = index == 0;
        let mut devices = vec![
            "-machine",
            "q35",
            "-smp",
            "4",
            "-cpu",
            "max",
            &first,
            &code_arg,
            &second,
            &vars_arg,
            "-device",
            "edu,addr=3",
        ];
        if isolated {
            devices.extend(["-device", "intel-iommu,caching-mode=on,intremap=on"]);
        }
        #[cfg(target_os = "linux")]
        let msix =
            isolated.then(|| ivshmem::Fixture::new(temp.path()).expect("create MSI-X fixture"));
        #[cfg(target_os = "linux")]
        if let Some(fixture) = &msix {
            devices.extend(fixture.options());
        }
        let mut guest = start_guest_with_devices(&disk, &serial_path, &devices);
        #[cfg(target_os = "linux")]
        let _peer = msix
            .as_ref()
            .map(|fixture| drive_msix(fixture, &mut guest.child, &serial_path));
        let serial = wait_for_serial(
            &mut guest.child,
            &serial_path,
            "rootsrv thread waiting for keyboard IRQ",
            Instant::now() + BOOT_TIMEOUT,
        );
        assert_markers(
            &serial,
            &[
                "x86 supervisor protection (SMEP=true, SMAP=true)",
                "Breakpoint returned cleanly.",
                "Local APIC and I/O APIC interrupt routing enabled",
                "SMP initialized 3 secondary CPUs",
                "SMP TLB shootdown replaced a translation cached on every secondary",
                "SMP TLB shootdown reclaimed page tables active on the secondaries",
                "SMP scheduler migrated a saved worker and reaped all worker stacks",
                "SMP heap released a CPU-local allocation after migration",
                "SMP IPC registered a waiter and completed a cross-CPU rendezvous",
                "SMP LAPIC probe distinguished pending and idle boot CPU vectors",
                "KPTI user root excludes the kernel heap and physmap",
                "SMP user IPC crossed CPUs",
                "rootsrv: console write acknowledged over IPC",
                "rootsrv: framebuffer tile drawn",
            ],
        );
        assert!(!serial.contains("virtual_address_offset"), "{serial}");
        assert!(
            !serial.contains("VT-d DMA translation unavailable"),
            "{serial}"
        );
        if isolated {
            assert!(serial.lines().any(|line| {
                line.starts_with("SMP device IRQ ") && line.contains(" delivered to a user task on CPU ")
            }), "No device IRQ crossed to a user task on another CPU:\n{serial}");
            assert_markers(
                &serial,
                &[
                    "VT-d queued invalidation enabled",
                    "VT-d DMA translation enabled with an empty root table",
                    "VT-d I/O APIC interrupt remapping enabled",
                    "rootsrv: delegated UART IRQ delivered, re-armed and reclaimed",
                    "rootsrv: cleared firmware-enabled PCI bus mastering before delegation",
                    "rootsrv: PCI INTx delivered, re-armed, revoked and reclaimed",
                    "rootsrv: delegated DMA round trip, revocation and reclamation verified",
                    "rootsrv: PCI MSI delivered, coalesced, revoked and reclaimed",
                    "rootsrv: PCI BAR mapped, delegated read-only, revoked and reclaimed",
                    #[cfg(target_os = "linux")]
                    "rootsrv: MSI-X table protected and both vectors reclaimed",
                ],
            );
        } else {
            assert!(
                serial.contains("rootsrv: refused to delegate a firmware-enabled PCI bus master"),
                "{serial}"
            );
        }
        *address = breakpoint_address(&serial);
        monitor(&mut guest.child, "sendkey spc");
        wait_for_serial(
            &mut guest.child,
            &serial_path,
            "rootsrv: Space key received",
            Instant::now() + ACTION_TIMEOUT,
        );
        monitor(&mut guest.child, "quit");
        assert!(guest.child.wait().expect("wait for UEFI guest").success());
    }
    assert_ne!(
        addresses[0], addresses[1],
        "a second boot reused the kernel load address"
    );
}

fn breakpoint_address(serial: &str) -> u64 {
    let address = serial
        .lines()
        .find_map(|line| {
            line.strip_prefix("EXCEPTION: BREAKPOINT @ VirtAddr(0x")
                .and_then(|suffix| suffix.strip_suffix(')'))
        })
        .expect("the UEFI fixture reports its relocated breakpoint");
    let address = u64::from_str_radix(address, 16).expect("read the relocated breakpoint address");
    assert!((0xffff_8000_0000_0000..0xffff_ff80_0000_0000).contains(&address));
    address
}

#[test]
fn test_rootsrv_updates_the_framebuffer_from_keyboard_input() {
    let temp = tempfile::tempdir().expect("Failed to create boot test directory");
    let disk_image = build_image(temp.path(), "qemu-rootsrv-test", Services::Console);
    let serial_path = temp.path().join("serial.log");
    let mut vm = start_guest_with_devices(&disk_image, &serial_path, &["-device", "edu"]);

    wait_for_serial(
        &mut vm.child,
        &serial_path,
        "rootsrv thread waiting for keyboard IRQ",
        Instant::now() + BOOT_TIMEOUT,
    );
    let deadline = Instant::now() + ACTION_TIMEOUT;
    let initial_image = temp.path().join("before.ppm");
    assert_tile_color(&mut vm.child, &initial_image, [0x8a, 0xb4, 0xff], deadline);
    monitor(&mut vm.child, "sendkey spc");
    let serial = wait_for_serial(
        &mut vm.child,
        &serial_path,
        "rootsrv: Space key received",
        deadline,
    );
    let updated_image = temp.path().join("after.ppm");
    assert_tile_color(&mut vm.child, &updated_image, [0x7f, 0xe3, 0xc4], deadline);
    monitor(&mut vm.child, "quit");
    assert!(vm.child.wait().expect("Failed to wait for QEMU").success());
    assert_markers(
        &serial,
        &[
            "rootsrv process created, entering user mode...",
            "consoled process created, entering user mode...",
            "Hello from ring 3, rootsrv alive.",
        ],
    );
    assert_markers(
        &serial,
        &[
            "Breakpoint returned cleanly.",
            "Local APIC and I/O APIC interrupt routing enabled",
            "rootsrv process created, entering user mode...",
            "rootsrv: delegated UART IRQ delivered, re-armed and reclaimed",
            "rootsrv: PCI BAR mapped, delegated read-only, revoked and reclaimed",
            "rootsrv: moved capability revoked transitively",
            "Hello from ring 3, rootsrv alive.",
            "rootsrv: console write acknowledged over IPC",
            "rootsrv: wait selected both console notification and reply",
            "rootsrv: console endpoint rights verified",
            "rootsrv: notification transferred and revoked across capability spaces",
            "rootsrv: shared frame mapped read-only by console and unmapped on revocation",
            "rootsrv: console allocation and mapping revoked through its Untyped budget",
            "rootsrv: Untyped budget enforced and reclaimed after revocation",
            "rootsrv: both delegated budgets reclaimed",
            "rootsrv: timed wait and sleep woke at monotonic deadlines",
            "rootsrv: nested capability lookup, revocation and budgets verified",
            "rootsrv: anonymous memory rolled back and reused zeroed",
            "rootsrv: aligned allocation grew the runtime heap",
            "rootsrv: framebuffer tile drawn",
            "rootsrv: press Space to test keyboard input",
            "rootsrv thread waiting for keyboard IRQ",
            "rootsrv: Space key received",
        ],
    );
}

#[test]
fn test_timer_preempts_cpu_bound_user_code() {
    verify_user_preemption(&["-cpu", "max"], false);
}

#[test]
#[ignore = "requires KVM with host CET support"]
fn test_cet_under_kvm() {
    verify_user_preemption(&["-accel", "kvm", "-cpu", "host"], true);
}

#[test]
#[ignore = "requires KVM with host CET support"]
fn test_cet_under_kvm_smp() {
    let temp = tempfile::tempdir().expect("create CET SMP test directory");
    let disk = build_image(
        temp.path(),
        "qemu-rootsrv-test,qemu-hardening-test,qemu-smp-test",
        Services::Console,
    );
    let serial_path = temp.path().join("serial.log");
    let mut vm = start_guest_with_devices(
        &disk,
        &serial_path,
        &["-accel", "kvm", "-cpu", "host", "-smp", "4"],
    );
    let serial = wait_for_serial(
        &mut vm.child,
        &serial_path,
        "rootsrv thread waiting for keyboard IRQ",
        Instant::now() + BOOT_TIMEOUT,
    );
    assert_cet(&serial);
    assert_markers(
        &serial,
        &[
            "SMP initialized 3 secondary CPUs",
            "SMP scheduler migrated a saved worker and reaped all worker stacks",
            "SMP user IPC crossed CPUs",
            "rootsrv: console write acknowledged over IPC",
        ],
    );
}

fn assert_cet(serial: &str) {
    assert_markers(
        serial,
        &[
            "x86 CET supervisor IBT enabled: true",
            "x86 CET user shadow stacks enabled: true",
            "kernel: syscall saved an active user shadow stack",
        ],
    );
}

fn verify_user_preemption(devices: &[&str], require_cet: bool) {
    let temp = tempfile::tempdir().expect("Failed to create boot test directory");
    let disk_image = build_image(
        temp.path(),
        "qemu-rootsrv-test,qemu-hardening-test",
        Services::CpuBoundConsole,
    );
    let serial_path = temp.path().join("serial.log");
    let mut vm = start_guest_with_devices(&disk_image, &serial_path, devices);
    let boot_deadline = Instant::now() + BOOT_TIMEOUT;
    wait_for_serial(
        &mut vm.child,
        &serial_path,
        "consoled: reply followed by CPU-bound loop",
        boot_deadline,
    );
    let serial = wait_for_serial(
        &mut vm.child,
        &serial_path,
        "rootsrv thread waiting for keyboard IRQ",
        boot_deadline,
    );
    if require_cet {
        assert_cet(&serial);
    }
    assert_markers(
        &serial,
        &[
            "x86 supervisor protection (SMEP=true, SMAP=true)",
            "Local APIC and I/O APIC interrupt routing enabled",
            "KPTI user root excludes the kernel heap and physmap",
            "consoled: syscall preserved user AC and DF",
            "consoled: reply followed by CPU-bound loop",
        ],
    );
    // A timer can interrupt either user program's serial output, including
    // while the console is setting up the syscall probe.
    assert!(
        serial.contains("kernel: timer entry cleared user AC"),
        "Timer entry did not report clearing user AC:\n{serial}"
    );
    assert_markers(
        &serial,
        &[
            "rootsrv: timed wait and sleep woke at monotonic deadlines",
            "rootsrv: syscall copy checked both pages before writing",
        ],
    );
    monitor(&mut vm.child, "nmi");
    wait_for_serial(
        &mut vm.child,
        &serial_path,
        "KPTI resumed an NMI that interrupted user mode",
        Instant::now() + ACTION_TIMEOUT,
    );
    monitor(&mut vm.child, "sendkey spc");
    wait_for_serial(
        &mut vm.child,
        &serial_path,
        "rootsrv: Space key received",
        Instant::now() + ACTION_TIMEOUT,
    );
    monitor(&mut vm.child, "quit");
    assert!(vm.child.wait().expect("Failed to wait for QEMU").success());
}

#[derive(Clone, Copy)]
enum Services {
    None,
    Console,
    PciInterruptConsole,
    CpuBoundConsole,
    FaultingConsole,
    ExitingConsole,
}

#[test]
fn test_vtd_isolates_and_reclaims_delegated_dma() {
    let temp = tempfile::tempdir().expect("create VT-d test directory");
    let disk_image = build_image(
        temp.path(),
        "qemu-vtd-test,qemu-rootsrv-test",
        Services::PciInterruptConsole,
    );
    let serial_path = temp.path().join("serial.log");
    let devices = [
        "-machine",
        "q35",
        "-device",
        "intel-iommu,caching-mode=on,intremap=on",
        "-device",
        "edu,addr=3",
    ];
    #[cfg(target_os = "linux")]
    let msix = ivshmem::Fixture::new(temp.path()).expect("create MSI-X fixture");
    #[cfg(target_os = "linux")]
    let devices = {
        let mut options = devices.to_vec();
        options.extend(msix.options());
        options
    };
    let mut guest = start_guest_with_devices(&disk_image, &serial_path, &devices);
    #[cfg(target_os = "linux")]
    let _peer = drive_msix(&msix, &mut guest.child, &serial_path);
    let serial = wait_for_serial(
        &mut guest.child,
        &serial_path,
        "rootsrv: press Space to test keyboard input",
        Instant::now() + BOOT_TIMEOUT,
    );
    assert_markers(
        &serial,
        &[
            "VT-d queued invalidation enabled",
            "VT-d DMA translation enabled with an empty root table",
            "VT-d I/O APIC interrupt remapping enabled",
            "VT-d rejected an unassigned EDU DMA request",
            "rootsrv: delegated UART IRQ delivered, re-armed and reclaimed",
            "rootsrv: PCI INTx delivered, re-armed, revoked and reclaimed",
            "rootsrv: delegated DMA round trip, revocation and reclamation verified",
            "rootsrv: PCI MSI delivered, coalesced, revoked and reclaimed",
            "rootsrv: PCI BAR mapped, delegated read-only, revoked and reclaimed",
            #[cfg(target_os = "linux")]
            "rootsrv: MSI-X table protected and both vectors reclaimed",
        ],
    );
    monitor(&mut guest.child, "sendkey spc");
    wait_for_serial(
        &mut guest.child,
        &serial_path,
        "rootsrv: Space key received",
        Instant::now() + ACTION_TIMEOUT,
    );
    monitor(&mut guest.child, "quit");
    assert!(guest.child.wait().expect("wait for VT-d guest").success());
}

#[cfg(target_os = "linux")]
fn drive_msix(
    fixture: &ivshmem::Fixture,
    child: &mut Child,
    serial: &Path,
) -> std::os::unix::net::UnixStream {
    let deadline = Instant::now() + BOOT_TIMEOUT;
    let peer = fixture
        .connect(child, deadline)
        .expect("connect MSI-X fixture");
    wait_for_serial(child, serial, "consoled: MSI-X vectors armed", deadline);
    fixture.trigger(1).expect("interrupt vector 1");
    wait_for_serial(child, serial, "consoled: MSI-X vector 1 received", deadline);
    fixture.trigger(0).expect("interrupt vector 0");
    peer
}

#[test]
fn test_user_fault_closes_ipc_and_keeps_the_other_process_running() {
    assert_console_shutdown_isolated(
        Services::FaultingConsole,
        "instruction exception",
        "fault vector 6",
    );
}

#[test]
fn test_user_exit_closes_ipc_and_keeps_the_other_process_running() {
    assert_console_shutdown_isolated(Services::ExitingConsole, "exit status 23", "exit status 23");
}

fn assert_console_shutdown_isolated(services: Services, reason: &str, observed_status: &str) {
    let temp = tempfile::tempdir().expect("Failed to create boot test directory");
    let disk_image = build_image(temp.path(), "qemu-rootsrv-test", services);
    let serial_path = temp.path().join("serial.log");
    let mut vm = start_guest(&disk_image, &serial_path);
    wait_for_serial(
        &mut vm.child,
        &serial_path,
        "rootsrv thread waiting for keyboard IRQ",
        Instant::now() + BOOT_TIMEOUT,
    );
    monitor(&mut vm.child, "sendkey spc");
    let serial = wait_for_serial(
        &mut vm.child,
        &serial_path,
        "rootsrv: Space key received",
        Instant::now() + ACTION_TIMEOUT,
    );
    monitor(&mut vm.child, "quit");
    assert!(vm.child.wait().expect("Failed to wait for QEMU").success());
    assert_markers(
        &serial,
        &[
            "consoled: delegated scratch and anonymous page mapped",
            "consoled: runtime heap recovered after budget exhaustion",
            &format!("user process consoled terminated: {reason}"),
            "reaped user process consoled",
            "rootsrv: both delegated budgets reclaimed",
            "rootsrv: console disconnected",
            &format!("rootsrv: reaped console reported {observed_status}"),
            "rootsrv: console address-space budget reclaimed",
            "rootsrv: restarting console with fresh endpoints",
            "consoled process created, entering user mode...",
            "rootsrv: restarted console acknowledged IPC",
            "consoled: delegated scratch and anonymous page mapped",
            "consoled: runtime heap recovered after budget exhaustion",
            &format!("user process consoled terminated: {reason}"),
            "reaped user process consoled",
            &format!("rootsrv: reaped console reported {observed_status}"),
            "rootsrv: console address-space budget reclaimed",
            "rootsrv thread waiting for keyboard IRQ",
            "rootsrv: Space key received",
        ],
    );
}

fn build_image(temp: &Path, kernel_feature: &str, services: Services) -> PathBuf {
    build_firmware_image(temp, kernel_feature, services, false)
}

fn build_firmware_image(
    temp: &Path,
    kernel_feature: &str,
    services: Services,
    uefi: bool,
) -> PathBuf {
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let kernel_dir = workspace.join("kernel/ruzt-kernel");
    let build_dir = temp.join("target");
    let debug_dir = build_dir.join("x86_64-unknown-none/debug");

    let programs = match services {
        Services::None => &[][..],
        _ => &["rootsrv", "consoled"][..],
    };
    if !programs.is_empty() {
        let mut build = Command::new(env!("CARGO"));
        build
            .args([
                "build",
                "--locked",
                "-p",
                "rootsrv",
                "-p",
                "consoled",
                "--target",
                "x86_64-unknown-none",
                "--target-dir",
            ])
            .arg(&build_dir)
            .current_dir(workspace.join("servers"));
        match services {
            Services::PciInterruptConsole => build.args([
                "--features",
                "rootsrv/qemu-pci-intx-test,consoled/qemu-pci-intx-test",
            ]),
            Services::CpuBoundConsole => {
                build.args(["--features", "consoled/qemu-preemption-test"])
            }
            Services::FaultingConsole => build.args(["--features", "consoled/qemu-fault-test"]),
            Services::ExitingConsole => build.args(["--features", "consoled/qemu-exit-test"]),
            _ => &mut build,
        };
        let status = build.status().expect("Failed to build boot services");
        assert!(status.success(), "Boot services build failed: {status}");
    }

    let status = Command::new(env!("CARGO"))
        .args([
            "build",
            "--locked",
            "--bin",
            "ruzt-kernel",
            "--features",
            kernel_feature,
            "--target-dir",
        ])
        .arg(&build_dir)
        .current_dir(&kernel_dir)
        .status()
        .expect("Failed to build kernel");
    assert!(status.success(), "Kernel build failed: {status}");

    let disk_image = temp.join("ruzt-test.img");
    let kernel = debug_dir.join("ruzt-kernel");
    if uefi {
        boot_x86_64::create_uefi_image(&disk_image, &kernel, programs)
    } else {
        boot_x86_64::create_image(&disk_image, &kernel, programs)
    }
    .expect("Failed to create disk image");
    disk_image
}

fn run_smoke_test(disk_image: &Path, options: &[&str]) -> String {
    let _slot = qemu_slot();
    let output = Command::new("timeout")
        .arg(BOOT_TIMEOUT.as_secs().to_string())
        .args(["qemu-system-x86_64", "-drive"])
        .arg(format!("format=raw,file={}", disk_image.display()))
        .args([
            "-serial",
            "stdio",
            "-display",
            "none",
            "-no-reboot",
            "-device",
            "isa-debug-exit,iobase=0xf4,iosize=0x04",
        ])
        .args(options)
        .output()
        .expect("Failed to run QEMU");

    let serial = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    eprintln!("QEMU serial output:\n{serial}");

    // isa-debug-exit maps the kernel's 0x10 write to process exit code 33.
    assert_eq!(
        output.status.code(),
        Some(33),
        "QEMU failed: {}\nSerial:\n{serial}\nStderr:\n{stderr}",
        output.status
    );

    serial.into_owned()
}

struct Guest {
    child: Child,
    _slot: MutexGuard<'static, ()>,
}

fn start_guest(disk_image: &Path, serial_path: &Path) -> Guest {
    start_guest_with_devices(disk_image, serial_path, &[])
}

fn start_guest_with_devices(disk_image: &Path, serial_path: &Path, devices: &[&str]) -> Guest {
    let slot = qemu_slot();
    Guest {
        child: Command::new("timeout")
            .arg(GUEST_TIMEOUT.as_secs().to_string())
            .args(["qemu-system-x86_64", "-drive"])
            .arg(format!("format=raw,file={}", disk_image.display()))
            .arg("-serial")
            .arg(format!("file:{}", serial_path.display()))
            .args(["-display", "none", "-monitor", "stdio", "-no-reboot"])
            .args(devices)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .spawn()
            .expect("Failed to run QEMU with a monitor"),
        _slot: slot,
    }
}

impl Drop for Guest {
    fn drop(&mut self) {
        if let Some(mut monitor) = self.child.stdin.take() {
            let _ = writeln!(monitor, "quit");
        }
        let _ = self.child.wait();
    }
}

fn monitor(vm: &mut Child, command: &str) {
    writeln!(vm.stdin.as_mut().expect("QEMU monitor stdin"), "{command}")
        .expect("Failed to send QEMU monitor command");
}

fn wait_for_serial(vm: &mut Child, path: &Path, marker: &str, deadline: Instant) -> String {
    loop {
        let serial = std::fs::read_to_string(path).unwrap_or_default();
        if serial.lines().any(|line| line == marker) {
            return serial;
        }
        assert!(
            vm.try_wait().expect("Failed to poll QEMU").is_none() && Instant::now() < deadline,
            "QEMU did not reach {marker:?}:\n{serial}"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn assert_tile_color(vm: &mut Child, path: &Path, color: [u8; 3], deadline: Instant) {
    let path = path.to_str().expect("UTF-8 screenshot path");
    monitor(vm, &format!("screendump \"{path}\""));
    loop {
        if let Ok(image) = std::fs::read(path) {
            if let Some((width, pixels)) = ppm_pixels(&image) {
                let x = width - 28;
                let y = 28;
                let offset = 3 * (y * width + x);
                assert_eq!(&pixels[offset..offset + 3], &color, "Tile pixel in {path}");
                return;
            }
        }
        assert!(
            vm.try_wait().expect("Failed to poll QEMU").is_none() && Instant::now() < deadline,
            "QEMU did not produce a complete screenshot at {path}"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn ppm_pixels(image: &[u8]) -> Option<(usize, &[u8])> {
    let mut parts = image.splitn(4, |&byte| byte == b'\n');
    if parts.next()? != b"P6" {
        return None;
    }
    let mut dimensions = std::str::from_utf8(parts.next()?).ok()?.split_whitespace();
    let width = dimensions.next()?.parse::<usize>().ok()?;
    let height = dimensions.next()?.parse::<usize>().ok()?;
    if parts.next()? != b"255" || width < 40 || height < 40 {
        return None;
    }
    let pixels = parts.next()?;
    (pixels.len() == width.checked_mul(height)?.checked_mul(3)?).then_some((width, pixels))
}

fn assert_markers(serial: &str, markers: &[&str]) {
    let mut lines = serial.lines();
    for marker in markers {
        assert!(
            lines.any(|line| line.starts_with(marker)),
            "Missing or out-of-order serial marker {marker:?}:\n{serial}"
        );
    }
}
