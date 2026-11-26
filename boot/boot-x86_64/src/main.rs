use std::path::PathBuf;
use std::process::Command;

fn main() {
    let mut args = std::env::args_os().skip(1);
    let mut firmware = None;
    let mut data_disk = None;
    while let Some(option) = args.next() {
        if option == "--uefi" && firmware.is_none() {
            let (Some(code), Some(vars)) = (args.next(), args.next()) else {
                usage();
            };
            firmware = Some((PathBuf::from(code), PathBuf::from(vars)));
        } else if option == "--data-disk" && data_disk.is_none() {
            let Some(path) = args.next() else {
                usage();
            };
            let path = PathBuf::from(path)
                .canonicalize()
                .expect("open existing data disk image");
            let metadata = path.metadata().expect("read data disk geometry");
            assert!(
                metadata.is_file() && metadata.len() >= 512 && metadata.len() % 512 == 0,
                "data disk must be an existing raw image with a positive multiple of 512 bytes"
            );
            data_disk = Some(path);
        } else {
            usage();
        }
    }
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

    const PROGRAMS: &[&str] = &["rootsrv", "consoled", "pcid", "virtioblkd"];
    for program in PROGRAMS {
        if !kernel_binary.with_file_name(program).exists() {
            eprintln!("{program} binary not found. Build the boot services with:");
            eprintln!("  cd servers && cargo build --locked --target x86_64-unknown-none -p rootsrv -p consoled -p pcid -p virtioblkd");
            std::process::exit(1);
        }
    }

    let temp = tempfile::tempdir().expect("Failed to create boot directory");
    let disk_image = temp.path().join("ruzt-boot.img");
    let mut qemu = Command::new("qemu-system-x86_64");
    if firmware.is_some() || data_disk.is_some() {
        qemu.args(["-machine", "q35", "-cpu", "max"]);
    }
    if let Some((code, vars)) = firmware {
        boot_x86_64::create_uefi_image(&disk_image, &kernel_binary, PROGRAMS)
            .expect("Failed to create UEFI disk image");
        let drives = boot_x86_64::ovmf_drives(&code, &vars, &temp.path().join("vars.fd"))
            .expect("Failed to copy the OVMF variables template");
        qemu.args(drives);
    } else {
        boot_x86_64::create_image(&disk_image, &kernel_binary, PROGRAMS)
            .expect("Failed to create BIOS disk image");
    }
    if let Some(data_disk) = data_disk {
        qemu.args([
            "-device",
            "intel-iommu,caching-mode=on,intremap=on",
            "-drive",
        ])
        .arg(format!(
            "if=none,id=native,format=raw,cache=writeback,file={}",
            data_disk.to_string_lossy().replace(',', ",,")
        ))
        .args([
            "-device",
            "virtio-blk-pci,drive=native,addr=5,disable-legacy=on,iommu_platform=on",
        ]);
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

fn usage() -> ! {
    eprintln!("Usage: boot-x86_64 [--uefi OVMF_CODE OVMF_VARS] [--data-disk EXISTING_RAW_IMAGE]");
    std::process::exit(2);
}
