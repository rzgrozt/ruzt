use std::path::PathBuf;
use std::process::Command;

#[test]
fn test_kernel_boots() {
    let workspace_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..");

    // The kernel embeds rootsrv with include_bytes!, so the user binary must
    // exist before the kernel is compiled.
    let rootsrv_dir = workspace_root.join("servers").join("rootsrv");
    let status = Command::new("cargo")
        .args(["build", "--target", "../../x86_64-ruzt-user.json"])
        .current_dir(&rootsrv_dir)
        .status()
        .expect("Failed to build rootsrv");
    assert!(status.success(), "rootsrv build failed");

    let rootsrv_binary = workspace_root
        .join("target")
        .join("x86_64-ruzt-user")
        .join("debug")
        .join("rootsrv");
    assert!(
        rootsrv_binary.exists(),
        "rootsrv binary not found at {:?}",
        rootsrv_binary
    );

    let kernel_dir = workspace_root.join("kernel").join("ruzt-kernel");
    let status = Command::new("cargo")
        .args(["build"])
        .current_dir(&kernel_dir)
        .status()
        .expect("Failed to build kernel");
    assert!(status.success(), "Kernel build failed");

    let kernel_binary = workspace_root
        .join("target")
        .join("x86_64-unknown-none")
        .join("debug")
        .join("ruzt-kernel");
    assert!(
        kernel_binary.exists(),
        "Kernel binary not found at {:?}",
        kernel_binary
    );

    let out_dir = PathBuf::from(
        std::env::var_os("OUT_DIR").unwrap_or_else(|| "/tmp".into()),
    );
    let disk_image = out_dir.join("ruzt-test.img");
    bootloader::BiosBoot::new(&kernel_binary)
        .create_disk_image(&disk_image)
        .expect("Failed to create disk image");

    eprintln!("DEBUG: Starting QEMU...");
    let output = Command::new("timeout")
        .args([
            "30",
            "qemu-system-x86_64",
            "-drive",
            &format!("format=raw,file={}", disk_image.display()),
            "-serial",
            "stdio",
            "-display",
            "none",
            "-device",
            "isa-debug-exit,iobase=0xf4,iosize=0x04",
        ])
        .output()
        .expect("Failed to run QEMU");
    eprintln!("DEBUG: QEMU finished with code {:?}", output.status.code());

    let stdout = String::from_utf8_lossy(&output.stdout);
    eprintln!("DEBUG: QEMU stdout len = {}", stdout.len());
    if !stdout.is_empty() {
        eprintln!("DEBUG: QEMU stdout:\n{}", stdout);
    }

    for marker in [
        "Ruzt booting...",
        "cap object table initialised.",
        "syscall entry initialised.",
        "GDT+TSS initialised.",
        "IDT loaded.",
        "EXCEPTION: BREAKPOINT",
        "PIC initialised.",
        "PIT timer initialised.",
        "Scheduler initialised.",
    ] {
        assert!(
            stdout.contains(marker),
            "Missing '{}' in serial output.\nOutput:\n{}",
            marker,
            stdout
        );
    }

    assert!(
        stdout.contains("rootsrv process created, entering user mode..."),
        "Missing rootsrv launch marker.\nOutput:\n{}",
        stdout
    );
    assert!(
        stdout.contains("Hello from ring 3, rootsrv alive."),
        "Missing ring-3 hello.\nOutput:\n{}",
        stdout
    );
    assert!(
        stdout.contains("........"),
        "Missing heartbeat dots (>= 8 consecutive).\nOutput:\n{}",
        stdout
    );
    assert!(
        stdout.contains("Timer monotonic ns:"),
        "Missing 'Timer monotonic ns:' in serial output.\nOutput:\n{}",
        stdout
    );
    let timer_line = stdout
        .lines()
        .find(|l| l.starts_with("Timer monotonic ns: "))
        .expect("Timer monotonic ns line not found");
    let ns_str = timer_line
        .strip_prefix("Timer monotonic ns: ")
        .expect("Timer line prefix changed");
    let ns: u64 = ns_str.trim().parse().expect("Failed to parse timer ns value");
    assert!(
        ns > 0,
        "Timer monotonic ns should be > 0, got {}",
        ns
    );

    let exit_code = output.status.code().unwrap_or(1);
    // isa-debug-exit maps: exit_code = (value << 1) | 1
    // Writing 0x10 → exit code 33 (0x21)
    assert_eq!(
        exit_code, 33,
        "QEMU did not exit with success code 33 (isa-debug-exit from 0x10).\nOutput:\n{}",
        stdout
    );
}
