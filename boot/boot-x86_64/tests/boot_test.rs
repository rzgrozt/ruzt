use std::path::Path;
use std::process::Command;

#[test]
fn test_kernel_boots() {
    let kernel_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../kernel/ruzt-kernel");
    let temp = tempfile::tempdir().expect("Failed to create boot test directory");
    let build_dir = temp.path().join("target");

    let status = Command::new(env!("CARGO"))
        .args([
            "build",
            "--locked",
            "--bin",
            "ruzt-kernel",
            "--features",
            "qemu-smoke-test",
            "--target-dir",
        ])
        .arg(&build_dir)
        .current_dir(&kernel_dir)
        .status()
        .expect("Failed to build kernel");
    assert!(status.success(), "Kernel build failed: {status}");

    let kernel = build_dir.join("x86_64-unknown-none/debug/ruzt-kernel");
    let disk_image = temp.path().join("ruzt-test.img");
    bootloader::BiosBoot::new(&kernel)
        .create_disk_image(&disk_image)
        .expect("Failed to create disk image");

    let output = Command::new("timeout")
        .args(["30s", "qemu-system-x86_64", "-drive"])
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

    let mut lines = serial.lines();
    for marker in [
        "Ruzt booting...",
        "EXCEPTION: BREAKPOINT",
        "Breakpoint returned cleanly.",
    ] {
        assert!(
            lines.any(|line| line.starts_with(marker)),
            "Missing or out-of-order serial marker {marker:?}:\n{serial}"
        );
    }
}
