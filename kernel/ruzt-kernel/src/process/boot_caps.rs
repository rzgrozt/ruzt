//! Capabilities granted by the boot policy.

use ruzt_abi::{
    CapRights, ROOTSRV_CONSOLE_PROGRAM, ROOTSRV_IRQ_CONTROL, ROOTSRV_KEYBOARD_DATA,
    ROOTSRV_UART_DATA, ROOTSRV_UART_IRQ_ENABLE, ROOTSRV_UART_IRQ_IDENTIFY, ROOTSRV_UART_STATUS,
    ROOTSRV_UNTYPED,
};
use ruzt_cap::{CapSlot, CapType};

use crate::cap::{cspace::CSpace, object};
use crate::{keyboard, serial};

const ROOTSRV_UNTYPED_BITS: u8 = 23;

pub(super) fn root_space(console_image: &'static [u8]) -> CSpace {
    let mut rootsrv = CSpace::new(5);
    grant(
        &mut rootsrv,
        ROOTSRV_IRQ_CONTROL,
        CapType::IrqControl,
        CapRights::WRITE,
    );
    grant(
        &mut rootsrv,
        ROOTSRV_KEYBOARD_DATA,
        CapType::IoPort {
            port: keyboard::DATA_PORT,
        },
        CapRights::READ,
    );
    rootsrv
        .provision_untyped(ROOTSRV_UNTYPED, ROOTSRV_UNTYPED_BITS)
        .expect("reserve the root server RAM budget");
    let program =
        object::allocate_program("consoled", console_image).expect("register console executable");
    grant(
        &mut rootsrv,
        ROOTSRV_CONSOLE_PROGRAM,
        CapType::Program(program.0),
        CapRights::WRITE.union(CapRights::GRANT),
    );
    grant(
        &mut rootsrv,
        ROOTSRV_UART_DATA,
        CapType::IoPort { port: serial::COM1 },
        CapRights::WRITE.union(CapRights::GRANT),
    );
    grant(
        &mut rootsrv,
        ROOTSRV_UART_STATUS,
        CapType::IoPort {
            port: serial::COM1 + 5,
        },
        CapRights::READ.union(CapRights::GRANT),
    );
    if cfg!(feature = "qemu-rootsrv-test") {
        grant(
            &mut rootsrv,
            ROOTSRV_UART_IRQ_ENABLE,
            CapType::IoPort {
                port: serial::COM1 + 1,
            },
            CapRights::READ
                .union(CapRights::WRITE)
                .union(CapRights::GRANT),
        );
        grant(
            &mut rootsrv,
            ROOTSRV_UART_IRQ_IDENTIFY,
            CapType::IoPort {
                port: serial::COM1 + 2,
            },
            CapRights::READ.union(CapRights::GRANT),
        );
    }
    rootsrv
}

pub(super) fn grant(cspace: &mut CSpace, index: u64, cap_type: CapType, rights: CapRights) {
    cspace
        .insert(
            index,
            CapSlot {
                cap_type,
                rights,
                badge: 0,
            },
        )
        .expect("grant boot service capability");
}
