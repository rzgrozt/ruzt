use std::path::PathBuf;
use std::process::Command;

fn main() {
    let workspace_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..");

    let kernel_binary = workspace_root
        .join("target")
        .join("x86_64-unknown-none")
        .join("debug")
        .join("ruzt-kernel");

    if !kernel_binary.exists() {
        eprintln!("Kernel binary not found. Build it first with:");
        eprintln!("  cd kernel/ruzt-kernel && cargo build");
        std::process::exit(1);
    }

    let rootsrv = kernel_binary.with_file_name("rootsrv");
    if !rootsrv.exists() {
        eprintln!("rootsrv binary not found. Build it first with:");
        eprintln!("  cd servers/rootsrv && cargo build --locked --target x86_64-unknown-none");
        std::process::exit(1);
    }

    let temp = tempfile::tempdir().expect("Failed to create boot directory");
    let disk_image = temp.path().join("ruzt-boot.img");
    boot_x86_64::create_image(&disk_image, &kernel_binary, &["rootsrv"])
        .expect("Failed to create disk image");

    let status = Command::new("qemu-system-x86_64")
        .args([
            "-drive",
            &format!("format=raw,file={}", disk_image.display()),
            "-display",
            "gtk",
            "-no-reboot",
            "-serial",
            "stdio",
        ])
        .status()
        .expect("Failed to run QEMU");

    drop(temp);
    std::process::exit(status.code().unwrap_or(1));
}
