use std::path::PathBuf;
use std::process::Command;

fn main() {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    let firmware = match args.as_slice() {
        [] => None,
        [option, code, vars] if option == "--uefi" => {
            Some((PathBuf::from(code), PathBuf::from(vars)))
        }
        _ => {
            eprintln!("Usage: boot-x86_64 [--uefi OVMF_CODE OVMF_VARS]");
            std::process::exit(2);
        }
    };
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

    const PROGRAMS: &[&str] = &["rootsrv", "consoled"];
    for program in PROGRAMS {
        if !kernel_binary.with_file_name(program).exists() {
            eprintln!("{program} binary not found. Build the boot services with:");
            eprintln!("  cd servers && cargo build --locked --target x86_64-unknown-none -p rootsrv -p consoled");
            std::process::exit(1);
        }
    }

    let temp = tempfile::tempdir().expect("Failed to create boot directory");
    let disk_image = temp.path().join("ruzt-boot.img");
    let mut qemu = Command::new("qemu-system-x86_64");
    if let Some((code, vars)) = firmware {
        boot_x86_64::create_uefi_image(&disk_image, &kernel_binary, PROGRAMS)
            .expect("Failed to create UEFI disk image");
        let drives = boot_x86_64::ovmf_drives(&code, &vars, &temp.path().join("vars.fd"))
            .expect("Failed to copy the OVMF variables template");
        qemu.args(["-machine", "q35", "-cpu", "max"]).args(drives);
    } else {
        boot_x86_64::create_image(&disk_image, &kernel_binary, PROGRAMS)
            .expect("Failed to create BIOS disk image");
    }

    let status = qemu
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
