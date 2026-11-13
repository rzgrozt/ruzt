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

    let disk_image = PathBuf::from("/tmp/ruzt-boot.img");
    bootloader::BiosBoot::new(&kernel_binary)
        .create_disk_image(&disk_image)
        .expect("Failed to create disk image");

    let status = Command::new("qemu-system-x86_64")
        .args([
            "-drive",
            &format!("format=raw,file={}", disk_image.display()),
            "-serial",
            "stdio",
            "-device",
            "isa-debug-exit,iobase=0xf4,iosize=0x04",
        ])
        .status()
        .expect("Failed to run QEMU");

    std::process::exit(status.code().unwrap_or(1));
}
