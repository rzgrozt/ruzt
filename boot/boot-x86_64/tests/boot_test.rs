use std::path::PathBuf;
use std::process::Command;

#[test]
fn test_kernel_boots() {
    let workspace_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..");

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

    assert!(
        stdout.contains("Ruzt booting..."),
        "Missing 'Ruzt booting...' in serial output.\nOutput:\n{}",
        stdout
    );
    assert!(
        stdout.contains("EXCEPTION: BREAKPOINT"),
        "Missing 'EXCEPTION: BREAKPOINT' in serial output.\nOutput:\n{}",
        stdout
    );
    assert!(
        stdout.contains("thread A ticking"),
        "Missing 'thread A ticking' in serial output.\nOutput:\n{}",
        stdout
    );
    assert!(
        stdout.contains("thread B ticking"),
        "Missing 'thread B ticking' in serial output.\nOutput:\n{}",
        stdout
    );
    assert!(
        stdout.contains("keyboard_echo task started"),
        "Missing 'keyboard_echo task started' in serial output.\nOutput:\n{}",
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
    let ns_str = timer_line.strip_prefix("Timer monotonic ns: ").unwrap();
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