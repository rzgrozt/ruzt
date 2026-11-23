//! User process construction, launch, and termination.

mod anonymous;
mod boot_caps;
mod framebuffer;
mod initrd;
mod mmio;
mod shared_frames;

use crate::cap::{
    cspace::{self, CSpace, CapabilityId},
    object::{self, KObjectId, KernelObject, ProcessExitPublisher, UntypedBudget},
};
use crate::sched::{self, ThreadState};
use alloc::vec::Vec;
use core::ops::Range;
use ruzt_abi::{
    CapRights, ErrorCode, FramebufferInfo, ProcessStatus, IPC_CAP_SLOTS, PROCESS_ADDRESS_SPACE,
    ROOTSRV_FRAMEBUFFER, ROOTSRV_UNTYPED, USER_HEAP_INITIAL_BYTES, USER_HEAP_LIMIT,
    USER_HEAP_START,
};
use ruzt_cap::{CapType, EndpointId, ProcessId};
use ruzt_hal::boot::Framebuffer;
use ruzt_hal::mem::{MapError, PageFlags, PhysFrame, VirtAddr};
use ruzt_hal_x86_64::mapper::{self, UserPageFrames, X86_64Mapper};

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
    start: USER_HEAP_START,
    page_count: USER_HEAP_INITIAL_BYTES as u64 / PAGE_SIZE,
};

fn overlaps_heap(start: u64, end: u64) -> bool {
    start < USER_HEAP_LIMIT && USER_HEAP_START < end
}

fn page_range(address: u64, count: u64) -> Result<Range<u64>, ErrorCode> {
    let end = count
        .checked_mul(PAGE_SIZE)
        .and_then(|length| address.checked_add(length))
        .ok_or(ErrorCode::BadMessage)?;
    if address == 0 || count == 0 || address % PAGE_SIZE != 0 || end > 1 << 47 {
        return Err(ErrorCode::BadMessage);
    }
    Ok(address..end)
}

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
    exit_channels: [Option<EndpointId>; IPC_CAP_SLOTS],
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
    anonymous: Vec<anonymous::PrivatePage>,
    heap_extension: Vec<anonymous::PrivatePage>,
    // Dropped only after Drop destroys the private page tables.
    shared_frames: Vec<shared_frames::Mapping>,
    device_mappings: Vec<mmio::Mapping>,
    budget: UntypedBudget,
}

impl Drop for UserAddressSpace {
    #[allow(unsafe_code)]
    fn drop(&mut self) {
        mapper::with_mapper(|mapper| {
            // SAFETY: An address space can be dropped only during failed
            // construction or after the scheduler permanently switches away.
            unsafe { mapper.destroy_user_address_space(self.root, &self.budget) };
        });
        let dynamic = self
            .anonymous
            .drain(..)
            .chain(self.heap_extension.drain(..))
            .map(|page| page.frame);
        for frame in self.ram.drain(..).chain(dynamic) {
            // SAFETY: These are owned allocator frames. No user table maps
            // them after destroying the root. Device pages are never tracked.
            unsafe { self.budget.deallocate(frame) };
        }
    }
}

/// Load the root server and give it authority to start the console.
pub(crate) fn enqueue_initial(archive: &'static [u8], framebuffer: Option<Framebuffer>) {
    let rootsrv = initrd::file(archive, b"rootsrv").expect("unable to load rootsrv from initrd");
    let consoled = initrd::file(archive, b"consoled").expect("unable to load consoled from initrd");
    let root_space = boot_caps::root_space(consoled);
    let budget = root_space
        .untyped_budget(ROOTSRV_UNTYPED)
        .expect("rootsrv RAM budget");
    let root = load("rootsrv", rootsrv, root_space, framebuffer, budget).expect("load rootsrv");
    sched::spawn_user(root, enter_user).expect("schedule rootsrv");
}

pub(crate) fn spawn_program(
    program: KObjectId,
    status_slot: u64,
    packet: crate::ipc::Packet,
    close_on_exit: u64,
    memory_slot: u64,
) -> Result<(), ErrorCode> {
    let Some(KernelObject::Program { name, image }) = object::get(program) else {
        return Err(ErrorCode::InvalidCap);
    };
    let count = usize::from(packet.message.cap_count);
    if count > IPC_CAP_SLOTS
        || close_on_exit >> count != 0
        || packet.message.label != 0
        || packet.message.length != 0
    {
        return Err(ErrorCode::BadMessage);
    }

    let (channels, budget) = sched::with_current_user(|parent| {
        parent.cspace.require_vacant(status_slot)?;
        let mut channels = [None; IPC_CAP_SLOTS];
        let channel_rights = CapRights::READ
            .union(CapRights::WRITE)
            .union(CapRights::GRANT);
        for (index, channel) in channels[..count].iter_mut().enumerate() {
            if close_on_exit & (1 << index) == 0 {
                continue;
            }
            let slot = parent.cspace.lookup(packet.message.caps[index].cptr)?;
            let CapType::Endpoint(id) = slot.cap_type else {
                return Err(ErrorCode::BadMessage);
            };
            if !slot.rights.contains(channel_rights) {
                return Err(ErrorCode::CapRightsViolation);
            }
            *channel = Some(id);
        }
        Ok((channels, parent.cspace.untyped_budget(memory_slot)?))
    })
    .ok_or(ErrorCode::InvalidCap)??;

    let mut child_space = CSpace::try_new(4)?;
    child_space.accept_grants(0, None, &packet.grants[..count])?;
    let mut child = load(name, image, child_space, None, budget)?;
    child.exit_channels = channels;
    let (process, publisher) = ProcessExitPublisher::new()?;
    child.exit_publisher = Some(publisher);
    sched::with_current_user(|parent| {
        parent.cspace.insert(
            status_slot,
            ruzt_cap::CapSlot {
                cap_type: CapType::Process(process),
                rights: CapRights::READ.union(CapRights::GRANT),
                badge: 0,
            },
        )
    })
    .ok_or(ErrorCode::InvalidCap)??;

    if let Err(error) = sched::spawn_user(child, enter_user) {
        sched::with_current_user(|parent| parent.cspace.delete(status_slot))
            .expect("launch caller remains current")
            .expect("launch status slot is valid");
        return Err(error);
    }
    Ok(())
}

pub(crate) fn terminate_current(status: ProcessStatus, reason: core::fmt::Arguments<'_>) -> ! {
    let (name, channels) = crate::sched::with_current_user(|user| {
        user.cspace.revoke_all_descendants();
        (user.name, user.exit_channels)
    })
    .expect("termination requires a user task");
    crate::sched::apply_capability_removals();
    crate::serial_println!("user process {name} terminated: {reason}");
    for channel in channels.into_iter().flatten() {
        crate::ipc::close_endpoint(channel);
    }
    crate::irq::detach_thread(crate::sched::current_thread_id());
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

fn load(
    name: &'static str,
    image: &'static [u8],
    mut cspace: CSpace,
    framebuffer: Option<Framebuffer>,
    budget: UntypedBudget,
) -> Result<UserProcess, ErrorCode> {
    let elf = crate::elf::load_elf(image)?;
    if elf.stack_size as u64 != STACK_REGION.page_count * PAGE_SIZE {
        return Err(ErrorCode::BadMessage);
    }
    let (space, framebuffer) =
        map_image(&elf, framebuffer, budget).map_err(|error| match error {
            MapError::FrameAllocationFailed => ErrorCode::NoMemory,
            _ => ErrorCode::BadMessage,
        })?;

    if framebuffer.is_some() {
        boot_caps::grant(
            &mut cspace,
            ROOTSRV_FRAMEBUFFER,
            CapType::Framebuffer,
            CapRights::WRITE,
        );
    }
    let address_space = object::register_address_space(space.root)?;
    if let Err(error) = cspace.insert(
        PROCESS_ADDRESS_SPACE,
        ruzt_cap::CapSlot {
            cap_type: CapType::AddressSpace(address_space),
            rights: CapRights::WRITE,
            badge: 0,
        },
    ) {
        object::deallocate(KObjectId(address_space.0));
        return Err(error);
    }
    Ok(UserProcess {
        space,
        entry: elf.entry_point,
        name,
        cspace,
        framebuffer,
        exit_channels: [None; IPC_CAP_SLOTS],
        exit_publisher: None,
    })
}

fn map_image(
    elf: &crate::elf::LoadedElf,
    framebuffer: Option<Framebuffer>,
    budget: UntypedBudget,
) -> Result<(UserAddressSpace, Option<FramebufferInfo>), MapError> {
    let root = mapper::with_mapper(|mapper| mapper.create_user_address_space(&budget))?;
    let mut space = UserAddressSpace {
        root,
        ram: Vec::new(),
        anonymous: Vec::new(),
        heap_extension: Vec::new(),
        shared_frames: Vec::new(),
        device_mappings: Vec::new(),
        budget,
    };
    let framebuffer = mapper::with_mapper(|mapper| {
        for segment in &elf.segments {
            if segment.mem_size == 0 {
                continue;
            }
            let start = segment.vaddr & !(PAGE_SIZE - 1);
            let end = (segment.vaddr + segment.mem_size).next_multiple_of(PAGE_SIZE);
            if overlaps_heap(start, end) {
                return Err(MapError::AlreadyMapped);
            }
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
                .map(|framebuffer| framebuffer::map(mapper, root, framebuffer, &space.budget))
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
    let frame = map_owned_page(
        mapper,
        space.root,
        &space.budget,
        page,
        flags,
        offset,
        bytes,
    )?;
    space.ram.push(frame);
    Ok(())
}

#[allow(unsafe_code)]
fn map_owned_page(
    mapper: &mut X86_64Mapper,
    root: PhysFrame,
    budget: &UntypedBudget,
    page: u64,
    flags: PageFlags,
    offset: usize,
    bytes: &[u8],
) -> Result<PhysFrame, MapError> {
    let frame = budget.allocate().ok_or(MapError::FrameAllocationFailed)?;
    // SAFETY: The budget gives exclusive ownership of this physmapped
    // frame. The caller serializes updates to the private root.
    let result = unsafe {
        mapper::zero_frame(frame);
        mapper::copy_to_frame(frame, offset, bytes).and_then(|()| {
            mapper.map_in_address_space(
                root,
                VirtAddr::new(page),
                frame,
                flags | PageFlags::USER,
                budget,
            )
        })
    };
    if let Err(error) = result {
        // SAFETY: A failed mapping leaves this leaf exclusively owned here.
        unsafe { budget.deallocate(frame) };
        return Err(error);
    }
    Ok(frame)
}

#[cfg(test)]
mod tests;
