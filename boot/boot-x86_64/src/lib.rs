use std::error::Error;
use std::io;
use std::path::Path;
use std::process::Command;

/// Build a BIOS disk with an optional boot program archive.
pub fn create_image(image: &Path, kernel: &Path, programs: &[&str]) -> Result<(), Box<dyn Error>> {
    let temp = tempfile::tempdir()?;
    let mut boot = bootloader::BiosBoot::new(kernel);
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
        boot.set_ramdisk(&initrd);
    }
    boot.create_disk_image(image)?;
    Ok(())
}
