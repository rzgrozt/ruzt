//! Scheduler state for an online processor.

use alloc::collections::VecDeque;
use ruzt_abi::ProcessStatus;

use super::{Scheduler, ThreadId};

pub(super) const BOOT_CPU: usize = 0;
pub(super) use crate::smp::SCHEDULER_SLOTS as CPU_SLOTS;

pub(super) struct Cpu {
    pub(super) idle: ThreadId,
    pub(super) current: ThreadId,
    pub(super) run_queue: VecDeque<ThreadId>,
    pub(super) retired: Option<(ThreadId, Option<ProcessStatus>)>,
}

impl Cpu {
    pub(super) fn new(idle: ThreadId) -> Self {
        Self {
            idle,
            current: idle,
            run_queue: VecDeque::new(),
            retired: None,
        }
    }
}

impl Scheduler {
    pub(super) fn cpu(&self, slot: usize) -> &Cpu {
        self.cpus[slot].as_ref().expect("registered scheduler CPU")
    }

    pub(super) fn cpu_mut(&mut self, slot: usize) -> &mut Cpu {
        self.cpus[slot].as_mut().expect("registered scheduler CPU")
    }

    pub(super) fn pick_next(&mut self, slot: usize) -> ThreadId {
        let local = self.cpu_mut(slot);
        if local.run_queue.front() == Some(&local.current) {
            local.run_queue.rotate_left(1);
        }
        local
            .run_queue
            .front()
            .copied()
            .unwrap_or_else(|| self.steal(slot).unwrap_or_else(|| self.cpu(slot).idle))
    }

    fn steal(&mut self, slot: usize) -> Option<ThreadId> {
        for offset in 1..CPU_SLOTS {
            let victim = (slot + offset) % CPU_SLOTS;
            let Some(remote) = self.cpus[victim].as_ref() else {
                continue;
            };
            let Some(index) = remote
                .run_queue
                .iter()
                .rposition(|&id| id != remote.current && self.threads[id].migratable)
            else {
                continue;
            };
            // Reserve queue space before detaching a task from its old owner.
            self.cpu_mut(slot).run_queue.try_reserve(1).ok()?;
            let id = self
                .cpu_mut(victim)
                .run_queue
                .remove(index)
                .expect("ready task to steal");
            self.threads[id].cpu = slot;
            self.cpu_mut(slot).run_queue.push_back(id);
            return Some(id);
        }
        None
    }
}
