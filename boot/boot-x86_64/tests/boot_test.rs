use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

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
    let serial = run_smoke_test(&disk_image);
    assert_markers(
        &serial,
        &[
            "Ruzt booting...",
            "EXCEPTION: BREAKPOINT",
            "Breakpoint returned cleanly.",
            "thread A ticking",
            "thread B ticking",
            "ipc_test_receiver: got message: Hello, IPC!",
            "ipc_test_sender: message sent successfully",
        ],
    );
}

#[test]
fn test_rootsrv_updates_the_framebuffer_from_keyboard_input() {
    let temp = tempfile::tempdir().expect("Failed to create boot test directory");
    let disk_image = build_image(temp.path(), "qemu-rootsrv-test", Services::Console);
    let serial_path = temp.path().join("serial.log");
    let mut vm = start_guest(&disk_image, &serial_path);

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
            "rootsrv process created, entering user mode...",
            "rootsrv: moved capability revoked transitively",
            "Hello from ring 3, rootsrv alive.",
            "rootsrv: console write acknowledged over IPC",
            "rootsrv: console endpoint rights verified",
            "rootsrv: notification transferred and revoked across capability spaces",
            "rootsrv: shared frame mapped read-only by console and unmapped on revocation",
            "rootsrv: console allocation and mapping revoked through its Untyped budget",
            "rootsrv: Untyped budget enforced and reclaimed after revocation",
            "rootsrv: both delegated budgets reclaimed",
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
    let temp = tempfile::tempdir().expect("Failed to create boot test directory");
    let disk_image = build_image(temp.path(), "qemu-rootsrv-test", Services::CpuBoundConsole);
    let serial_path = temp.path().join("serial.log");
    let mut vm = start_guest(&disk_image, &serial_path);
    let boot_deadline = Instant::now() + BOOT_TIMEOUT;
    wait_for_serial(
        &mut vm.child,
        &serial_path,
        "consoled: reply followed by CPU-bound loop",
        boot_deadline,
    );
    wait_for_serial(
        &mut vm.child,
        &serial_path,
        "rootsrv thread waiting for keyboard IRQ",
        boot_deadline,
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
    CpuBoundConsole,
    FaultingConsole,
    ExitingConsole,
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
    boot_x86_64::create_image(&disk_image, &debug_dir.join("ruzt-kernel"), programs)
        .expect("Failed to create disk image");
    disk_image
}

fn run_smoke_test(disk_image: &Path) -> String {
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
    let slot = qemu_slot();
    Guest {
        child: Command::new("timeout")
            .arg(GUEST_TIMEOUT.as_secs().to_string())
            .args(["qemu-system-x86_64", "-drive"])
            .arg(format!("format=raw,file={}", disk_image.display()))
            .arg("-serial")
            .arg(format!("file:{}", serial_path.display()))
            .args(["-display", "none", "-monitor", "stdio", "-no-reboot"])
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
