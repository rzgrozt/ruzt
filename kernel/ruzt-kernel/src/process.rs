//! Construction of the trusted boot-time user process.

mod boot_caps;
mod framebuffer;
mod initrd;
mod shared_frames;

use crate::cap::{
    cspace::{self, CSpace, CapabilityId},
    object::{self, KObjectId, KernelObject, ProcessExitPublisher},
};
use crate::sched::{self, ThreadState};
use alloc::vec::Vec;
use ruzt_abi::{CapRights, ErrorCode, FramebufferInfo, ProcessStatus, ROOTSRV_FRAMEBUFFER};
use ruzt_cap::{CapType, EndpointId, ProcessId};
use ruzt_hal::boot::Framebuffer;
use ruzt_hal::mem::{MapError, PageFlags, PhysFrame, VirtAddr};
use ruzt_hal_x86_64::mapper::{self, X86_64Mapper};

const PAGE_SIZE: u64 = PhysFrame::SIZE as u64;
const _: () = assert!(ruzt_abi::FRAME_BYTES == PhysFrame::SIZE);

struct Region {
    start: u64,
    page_count: u64,
}

impl Region {
    fn end(&self) -> Option<u64> {
        self.page_count
            .checked_mul(PAGE_SIZE)?
            .checked_add(self.start)
    }
}

const STACK_REGION: Region = Region {
    start: 0x7fff_0000,
    page_count: 32,
};
const HEAP_REGION: Region = Region {
    start: 0x4000_0000,
    page_count: 256,
};

fn initial_stack_pointer() -> u64 {
    // System V function entry expects an 8-byte return-address bias.
    STACK_REGION.end().unwrap() - 8
}

pub(crate) struct UserProcess {
    space: UserAddressSpace,
    entry: u64,
    pub(crate) name: &'static str,
    pub(crate) cspace: CSpace,
    pub(crate) framebuffer: Option<FramebufferInfo>,
    pub(crate) boot_channels: [EndpointId; 2],
    pub(crate) exit_publisher: Option<ProcessExitPublisher>,
}

impl UserProcess {
    pub(crate) fn root(&self) -> PhysFrame {
        self.space.root
    }
}

struct UserAddressSpace {
    root: PhysFrame,
    ram: Vec<PhysFrame>,
    // Dropped only after Drop destroys the private page tables.
    shared_frames: Vec<shared_frames::Mapping>,
}

impl Drop for UserAddressSpace {
    #[allow(unsafe_code)]
    fn drop(&mut self) {
        mapper::with_mapper(|mapper| {
            // SAFETY: An address space can be dropped only during failed
            // construction or after the scheduler permanently switches away.
            unsafe { mapper.destroy_user_address_space(self.root) };
        });
        for frame in self.ram.drain(..) {
            // SAFETY: These are owned allocator frames. No user table maps
            // them after destroying the root. Device pages are never tracked.
            unsafe { mapper::zero_frame(frame) };
            crate::mm::frame::deallocate(frame);
        }
    }
}

/// Load the initial servers and enqueue them on the boot CPU.
///
/// Any failure stops boot. These frames belong to the boot services for
/// the lifetime of the system.
pub(crate) fn enqueue_initial(archive: &'static [u8], framebuffer: Option<Framebuffer>) {
    let rootsrv = initrd::file(archive, b"rootsrv").expect("unable to load rootsrv from initrd");
    let consoled = initrd::file(archive, b"consoled").expect("unable to load consoled from initrd");
    let (channels, root_space, console_space, console_exit) = boot_caps::initial_services();
    enqueue(
        "consoled",
        consoled,
        console_space,
        None,
        channels,
        Some(console_exit),
    );
    let root = enqueue("rootsrv", rootsrv, root_space, framebuffer, channels, None);
    crate::keyboard::enable_user_driver(root);
}

pub(crate) fn terminate_current(status: ProcessStatus, reason: core::fmt::Arguments<'_>) -> ! {
    let (name, channels) = crate::sched::with_current_user(|user| {
        user.cspace.revoke_all_descendants();
        (user.name, user.boot_channels)
    })
    .expect("termination requires a user task");
    crate::sched::apply_capability_removals();
    crate::serial_println!("user process {name} terminated: {reason}");
    for channel in channels {
        crate::ipc::close_boot_channel(channel);
    }
    crate::keyboard::detach_user_driver(crate::sched::current_thread_id());
    crate::sched::retire_current_user(status)
}

pub(crate) fn wait_for_status(
    process: ProcessId,
    authority: Option<CapabilityId>,
    nonblocking: bool,
) -> Result<ProcessStatus, ErrorCode> {
    let id = KObjectId(process.0);
    loop {
        match object::get(id) {
            Some(KernelObject::Process {
                status: Some(status),
            }) => return Ok(status),
            Some(KernelObject::Process { status: None }) if nonblocking => {
                return Err(ErrorCode::WouldBlock);
            }
            Some(KernelObject::Process { status: None }) => {}
            _ => return Err(ErrorCode::InvalidCap),
        }
        // The syscall gate keeps local interrupts disabled from the status
        // check through blocking on the boot CPU, so publication cannot race.
        sched::block_with_authority(
            ThreadState::BlockedProcess(id),
            authority,
            Default::default(),
        );
        sched::check_ipc_completion()?;
        if authority.is_some_and(|capability| !cspace::is_live(capability)) {
            return Err(ErrorCode::InvalidCap);
        }
    }
}

fn enqueue(
    name: &'static str,
    image: &'static [u8],
    mut cspace: CSpace,
    framebuffer: Option<Framebuffer>,
    boot_channels: [EndpointId; 2],
    exit_publisher: Option<ProcessExitPublisher>,
) -> crate::sched::ThreadId {
    let elf = crate::elf::load_elf(image).unwrap_or_else(|e| panic!("invalid {name} ELF: {e:?}"));
    assert_eq!(elf.stack_size as u64, STACK_REGION.page_count * PAGE_SIZE);
    let (space, framebuffer) = map_image(&elf, framebuffer)
        .unwrap_or_else(|e| panic!("failed to map {name} address space: {e:?}"));

    if framebuffer.is_some() {
        boot_caps::grant(
            &mut cspace,
            ROOTSRV_FRAMEBUFFER,
            CapType::Framebuffer,
            CapRights::WRITE,
        );
    }
    crate::sched::spawn_user(
        UserProcess {
            space,
            entry: elf.entry_point,
            name,
            cspace,
            framebuffer,
            boot_channels,
            exit_publisher,
        },
        enter_user,
    )
}

fn map_image(
    elf: &crate::elf::LoadedElf,
    framebuffer: Option<Framebuffer>,
) -> Result<(UserAddressSpace, Option<FramebufferInfo>), MapError> {
    let root = mapper::with_mapper(|mapper| mapper.create_user_address_space())?;
    let mut space = UserAddressSpace {
        root,
        ram: Vec::new(),
        shared_frames: Vec::new(),
    };
    let framebuffer = mapper::with_mapper(|mapper| {
        for segment in &elf.segments {
            if segment.mem_size == 0 {
                continue;
            }
            let start = segment.vaddr & !(PAGE_SIZE - 1);
            let end = (segment.vaddr + segment.mem_size).next_multiple_of(PAGE_SIZE);
            let data_end = segment.vaddr + segment.data.len() as u64;
            for page in (start..end).step_by(PhysFrame::SIZE) {
                let copy_start = page.max(segment.vaddr);
                let copy_end = (page + PAGE_SIZE).min(data_end).max(copy_start);
                let source_start = (copy_start - segment.vaddr) as usize;
                let bytes = if copy_end > copy_start {
                    &segment.data[source_start..source_start + (copy_end - copy_start) as usize]
                } else {
                    &[]
                };
                map_page(
                    mapper,
                    &mut space,
                    page,
                    segment.flags,
                    (copy_start - page) as usize,
                    bytes,
                )?;
            }
        }

        for region in [STACK_REGION, HEAP_REGION] {
            for page in (region.start..region.end().unwrap()).step_by(PhysFrame::SIZE) {
                map_page(mapper, &mut space, page, PageFlags::WRITABLE, 0, &[])?;
            }
        }
        Ok::<_, MapError>(
            framebuffer
                .map(|framebuffer| framebuffer::map(mapper, root, framebuffer))
                .transpose()?
                .flatten(),
        )
    })?;
    Ok((space, framebuffer))
}

fn enter_user() -> ! {
    let (entry, root, name) =
        crate::sched::with_current_user(|user| (user.entry, user.root(), user.name))
            .expect("scheduled user process");
    crate::serial_println!("{name} process created, entering user mode...");
    #[allow(unsafe_code)]
    // SAFETY: The private root shares the supervisor mappings containing the
    // kernel and its initialized GDT, TSS and IDT. The scheduler installed
    // this thread's kernel stack for traps. The mapped entry and user stack
    // have the permissions required by enter_user.
    unsafe {
        ruzt_hal_x86_64::context::enter_user(entry, initial_stack_pointer(), root.base.as_u64())
    }
}

#[allow(unsafe_code)]
fn map_page(
    mapper: &mut X86_64Mapper,
    space: &mut UserAddressSpace,
    page: u64,
    flags: PageFlags,
    offset: usize,
    bytes: &[u8],
) -> Result<(), MapError> {
    space
        .ram
        .try_reserve(1)
        .map_err(|_| MapError::FrameAllocationFailed)?;
    let frame = crate::mm::frame::allocate().ok_or(MapError::FrameAllocationFailed)?;
    // SAFETY: The allocator gives exclusive ownership of this physmapped
    // frame, and root is the inactive address space under construction.
    let result = unsafe {
        mapper::zero_frame(frame);
        mapper::copy_to_frame(frame, offset, bytes).and_then(|()| {
            mapper.map_in_address_space(
                space.root,
                VirtAddr::new(page),
                frame,
                flags | PageFlags::USER,
            )
        })
    };
    if result.is_err() {
        // SAFETY: A failed mapping leaves this leaf exclusively owned here.
        unsafe { mapper::zero_frame(frame) };
        crate::mm::frame::deallocate(frame);
    } else {
        space.ram.push(frame);
    }
    result
}

#[cfg(test)]
mod tests;
