use std::error::Error;
use std::io;
use std::path::Path;
use std::process::Command;

use bootloader_boot_config::{BootConfig, LevelFilter};

/// Build a BIOS disk with an optional boot program archive.
pub fn create_image(image: &Path, kernel: &Path, programs: &[&str]) -> Result<(), Box<dyn Error>> {
    build_image(image, kernel, programs, false)
}

/// Build a UEFI disk with an optional boot program archive.
pub fn create_uefi_image(
    image: &Path,
    kernel: &Path,
    programs: &[&str],
) -> Result<(), Box<dyn Error>> {
    build_image(image, kernel, programs, true)
}

fn build_image(
    image: &Path,
    kernel: &Path,
    programs: &[&str],
    uefi: bool,
) -> Result<(), Box<dyn Error>> {
    let temp = tempfile::tempdir()?;
    let mut boot = bootloader::DiskImageBuilder::new(kernel.to_owned());
    let mut config = BootConfig::default();
    // The bootloader reports relocated virtual addresses at info level.
    config.log_level = LevelFilter::Warn;
    boot.set_boot_config(&config);
    if !programs.is_empty() {
        let directory = kernel
            .parent()
            .ok_or_else(|| io::Error::other("missing build directory"))?;
        let initrd = temp.path().join("initrd.tar");
        let status = Command::new("tar")
            .args([
                "--format=ustar",
                "--mtime=@0",
                "--owner=0",
                "--group=0",
                "-cf",
            ])
            .arg(&initrd)
            .arg("-C")
            .arg(directory)
            .arg("--")
            .args(programs)
            .status()?;
        if !status.success() {
            return Err(io::Error::other(format!("packing initrd failed: {status}")).into());
        }
        boot.set_ramdisk(initrd);
    }
    if uefi {
        boot.create_uefi_image(image)?;
    } else {
        boot.create_bios_image(image)?;
    }
    Ok(())
}

/// Copy the OVMF variables template and build the two QEMU pflash arguments.
pub fn ovmf_drives(code: &Path, vars: &Path, writable_vars: &Path) -> io::Result<[String; 4]> {
    std::fs::copy(vars, writable_vars)?;
    Ok([
        "-drive".into(),
        format!("if=pflash,format=raw,readonly=on,file={}", code.display()),
        "-drive".into(),
        format!("if=pflash,format=raw,file={}", writable_vars.display()),
    ])
}
