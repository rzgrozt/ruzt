//! Capability-owned device interrupt routes on the boot CPU.

use ruzt_abi::ErrorCode;
use ruzt_hal::irq::{IrqController, IrqNumber};
use ruzt_hal_x86_64::irq::{self as hardware, X86_64IrqController, IRQ_COUNT};
use spin::Mutex;

use crate::cap::cspace::CapabilityPath;
use crate::sched::{self, ThreadId};

#[derive(Clone, Copy, PartialEq, Eq)]
enum State {
    Armed,
    Pending,
    AwaitingAck,
}

#[derive(Clone, Copy)]
struct Route {
    thread: ThreadId,
    authority: CapabilityPath,
    state: State,
}

static ROUTES: Mutex<[Option<Route>; IRQ_COUNT]> = Mutex::new([None; IRQ_COUNT]);

// Route transitions originate in an interrupt gate or run with local
// interrupts disabled. No hardware port operations are needed by host tests.
fn enable(line: u32) {
    #[cfg(not(test))]
    X86_64IrqController::enable(IrqNumber(line));
    #[cfg(test)]
    let _ = line;
}

fn disable(line: u32) {
    #[cfg(not(test))]
    X86_64IrqController::disable(IrqNumber(line));
    #[cfg(test)]
    let _ = line;
}

pub(crate) fn bind(
    line: u32,
    thread: ThreadId,
    authority: CapabilityPath,
) -> Result<(), ErrorCode> {
    let mut routes = ROUTES.lock();
    let route = routes.get_mut(line as usize).ok_or(ErrorCode::InvalidCap)?;
    if route.is_some() {
        return Err(ErrorCode::SlotOccupied);
    }
    *route = Some(Route {
        thread,
        authority,
        state: State::Armed,
    });
    enable(line);
    Ok(())
}

pub(crate) fn is_bound_to(line: u32, thread: ThreadId) -> bool {
    ROUTES
        .lock()
        .get(line as usize)
        .copied()
        .flatten()
        .is_some_and(|r| r.thread == thread)
}

pub(crate) fn consume(line: u32, thread: ThreadId) -> Result<bool, ErrorCode> {
    let mut routes = ROUTES.lock();
    let route = owned_route(&mut routes, line, thread)?;
    if route.state == State::Pending {
        route.state = State::AwaitingAck;
        return Ok(true);
    }
    Ok(false)
}

pub(crate) fn acknowledge(line: u32, thread: ThreadId) -> Result<(), ErrorCode> {
    let mut routes = ROUTES.lock();
    let route = owned_route(&mut routes, line, thread)?;
    if route.state != State::AwaitingAck {
        return Err(ErrorCode::BadMessage);
    }
    route.state = State::Armed;
    enable(line);
    Ok(())
}

pub(crate) fn unbind(line: u32, thread: ThreadId) -> Result<(), ErrorCode> {
    let mut routes = ROUTES.lock();
    owned_route(&mut routes, line, thread)?;
    disable(line);
    routes[line as usize] = None;
    Ok(())
}

fn owned_route(
    routes: &mut [Option<Route>; IRQ_COUNT],
    line: u32,
    thread: ThreadId,
) -> Result<&mut Route, ErrorCode> {
    routes
        .get_mut(line as usize)
        .and_then(Option::as_mut)
        .filter(|route| route.thread == thread)
        .ok_or(ErrorCode::InvalidCap)
}

fn remove_route(line: u32) {
    let mut routes = ROUTES.lock();
    disable(line);
    routes[line as usize] = None;
}

/// Detach the hardware line after its last capability disappears.
pub(crate) fn release(line: u32) {
    remove_route(line);
    hardware::release_gsi(line);
}

pub(crate) fn detach_thread(thread: ThreadId) {
    let mut routes = ROUTES.lock();
    for (line, route) in routes.iter_mut().enumerate() {
        if route.is_some_and(|route| route.thread == thread) {
            disable(line as u32);
            *route = None;
        }
    }
}

pub(crate) fn detach_revoked() {
    for line in 0..IRQ_COUNT {
        // Copy one route without nesting the route and capability tree locks.
        // The boot CPU has interrupts disabled, so delivery cannot interleave.
        let route = ROUTES.lock()[line];
        if let Some(route) = route {
            if !route.authority.is_live() {
                remove_route(line as u32);
                sched::wake_irq(route.thread, line as u32);
            }
        }
    }
}

/// Mask an armed interrupt until the driver consumes it and acknowledges it.
/// Return the owner to wake after dropping the routing lock.
fn latch(line: u32) -> Option<ThreadId> {
    let mut routes = ROUTES.lock();
    let route = routes[line as usize].as_mut()?;
    if route.state == State::Armed {
        disable(line);
        route.state = State::Pending;
        Some(route.thread)
    } else {
        None
    }
}

pub(crate) fn on_interrupt(line: u8) {
    if hardware::dismiss_spurious(line) {
        return;
    }
    if let Some(thread) = latch(u32::from(line)) {
        sched::wake_irq(thread, u32::from(line));
    } else if u32::from(line) == crate::keyboard::IRQ {
        // The standalone kernel diagnostic has no driver binding.
        if ROUTES.lock()[usize::from(line)].is_none() {
            crate::keyboard::on_interrupt();
        }
    } else {
        // Unclaimed lines stay masked, including stray interrupts.
        disable(u32::from(line));
    }
    end_of_interrupt(line);
}

pub(crate) fn end_of_interrupt(line: u8) {
    X86_64IrqController::end_of_interrupt(IrqNumber(u32::from(line)));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cap::cspace::CSpace;
    use ruzt_cap::{CapRights, CapSlot, CapType};

    #[test]
    fn masked_device_routes_rearm_only_after_consumption_and_revoke_with_the_binding() {
        let _state = crate::isolated_kernel_state();
        let line = 4;
        let rights = CapRights::READ.union(CapRights::WRITE);
        let mut manager = CSpace::new(2);
        let mut driver = CSpace::new(1);
        manager
            .insert(
                0,
                CapSlot {
                    cap_type: CapType::IrqControl,
                    rights: CapRights::WRITE,
                    badge: 0,
                },
            )
            .unwrap();
        for irq in [0, 2, 16, u32::MAX] {
            assert_eq!(manager.claim_irq(0, 1, irq), Err(ErrorCode::BadMessage));
        }
        manager.claim_irq(0, 1, line).unwrap();
        assert_eq!(manager.claim_irq(0, 2, line), Err(ErrorCode::SlotOccupied));
        driver
            .derive(manager.capability_id(1).unwrap(), 0, rights, 0)
            .unwrap();
        let (path, _) = driver.lookup_path(0).unwrap();
        bind(line, 7, path).unwrap();
        assert_eq!(bind(line, 8, path), Err(ErrorCode::SlotOccupied));
        assert_eq!(acknowledge(line, 7), Err(ErrorCode::BadMessage));
        assert_eq!(latch(line), Some(7));
        assert_eq!(latch(line), None);
        assert_eq!(consume(line, 8), Err(ErrorCode::InvalidCap));
        assert_eq!(consume(line, 7), Ok(true));
        assert_eq!(consume(line, 7), Ok(false));
        acknowledge(line, 7).unwrap();
        assert_eq!(latch(line), Some(7));

        manager.revoke(1).unwrap();
        detach_revoked();
        assert!(!is_bound_to(line, 7));
        assert_eq!(manager.claim_irq(0, 2, line), Err(ErrorCode::SlotOccupied));
        manager.delete(1).unwrap();
        manager.claim_irq(0, 2, line).unwrap();
        let (reclaimed, _) = manager.lookup_path(2).unwrap();
        bind(line, 8, reclaimed).unwrap();
        detach_thread(8);
        assert_eq!(latch(line), None);
    }
}
