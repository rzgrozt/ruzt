//! Minimal host side of QEMU's ivshmem doorbell fixture.

use std::fs::File;
use std::io::{self, Write};
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::process::Child;
use std::time::{Duration, Instant};

pub struct Fixture {
    listener: UnixListener,
    shmem: File,
    events: [File; 2],
    chardev: String,
}

impl Fixture {
    pub fn new(directory: &Path) -> io::Result<Self> {
        let socket = directory.join("ivshmem.sock");
        let listener = UnixListener::bind(&socket)?;
        listener.set_nonblocking(true)?;
        let shmem = tempfile::tempfile_in(directory)?;
        shmem.set_len(1024 * 1024)?;
        Ok(Self {
            listener,
            shmem,
            events: [eventfd()?, eventfd()?],
            chardev: format!("socket,id=ivshmem,path={}", socket.display()),
        })
    }

    pub fn options(&self) -> [&str; 4] {
        [
            "-chardev",
            &self.chardev,
            "-device",
            "ivshmem-doorbell,addr=4,chardev=ivshmem,vectors=2",
        ]
    }

    pub fn connect(&self, child: &mut Child, deadline: Instant) -> io::Result<UnixStream> {
        let mut peer = loop {
            match self.listener.accept() {
                Ok((peer, _)) => break peer,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    if child.try_wait()?.is_some() || Instant::now() >= deadline {
                        return Err(io::Error::new(
                            io::ErrorKind::TimedOut,
                            "QEMU ivshmem connection",
                        ));
                    }
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(error) => return Err(error),
            }
        };
        peer.set_write_timeout(Some(Duration::from_secs(5)))?;
        // Protocol version, peer ID, then shared memory and two vector eventfds.
        peer.write_all(&0i64.to_le_bytes())?;
        peer.write_all(&0i64.to_le_bytes())?;
        send_fd(&mut peer, -1, self.shmem.as_raw_fd())?;
        for event in &self.events {
            send_fd(&mut peer, 0, event.as_raw_fd())?;
        }
        Ok(peer)
    }

    pub fn trigger(&self, vector: usize) -> io::Result<()> {
        (&self.events[vector]).write_all(&1u64.to_ne_bytes())
    }
}

fn eventfd() -> io::Result<File> {
    // SAFETY: eventfd returns a newly owned descriptor on success.
    let fd = unsafe { libc::eventfd(0, libc::EFD_CLOEXEC) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: No other owner exists for this fresh descriptor.
    Ok(unsafe { File::from_raw_fd(fd) })
}

fn send_fd(socket: &mut UnixStream, value: i64, fd: RawFd) -> io::Result<()> {
    let mut bytes = value.to_le_bytes();
    let mut payload = libc::iovec {
        iov_base: bytes.as_mut_ptr().cast(),
        iov_len: bytes.len(),
    };
    // A usize array supplies the alignment needed by cmsghdr and CMSG_DATA.
    let mut control = [0usize; 4];
    // SAFETY: The message uses one initialized iovec and writable ancillary
    // storage for exactly one descriptor. sendmsg borrows both until return.
    let sent = unsafe {
        let fd_bytes = size_of::<RawFd>() as libc::c_uint;
        let space = libc::CMSG_SPACE(fd_bytes) as usize;
        assert!(space <= size_of_val(&control));
        let mut message: libc::msghdr = core::mem::zeroed();
        message.msg_iov = &mut payload;
        message.msg_iovlen = 1;
        message.msg_control = control.as_mut_ptr().cast();
        message.msg_controllen = space;
        let header = libc::CMSG_FIRSTHDR(&message);
        (*header).cmsg_level = libc::SOL_SOCKET;
        (*header).cmsg_type = libc::SCM_RIGHTS;
        (*header).cmsg_len = libc::CMSG_LEN(fd_bytes) as usize;
        libc::CMSG_DATA(header).cast::<RawFd>().write(fd);
        libc::sendmsg(socket.as_raw_fd(), &message, libc::MSG_NOSIGNAL)
    };
    if sent <= 0 {
        return Err(io::Error::last_os_error());
    }
    socket.write_all(&bytes[sent as usize..])
}
