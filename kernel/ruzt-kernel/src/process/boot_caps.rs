//! Capabilities granted by the boot policy.

use ruzt_abi::{
    console, CapRights, ROOTSRV_CONSOLE_NOTIFICATION, ROOTSRV_CONSOLE_REPLY,
    ROOTSRV_CONSOLE_REQUEST, ROOTSRV_KEYBOARD_DATA, ROOTSRV_KEYBOARD_IRQ,
};
use ruzt_cap::{CapSlot, CapType, EndpointId, NotificationId};

use crate::cap::{cspace::CSpace, object};
use crate::{keyboard, serial};

pub(super) fn initial_services() -> ([EndpointId; 2], CSpace, CSpace) {
    let request = endpoint();
    let reply = endpoint();
    let channels = [request, reply];
    let request = CapType::Endpoint(request);
    let reply = CapType::Endpoint(reply);
    let mut rootsrv = CSpace::new(4);
    grant(
        &mut rootsrv,
        ROOTSRV_CONSOLE_REQUEST,
        request,
        CapRights::WRITE.union(CapRights::GRANT),
    );
    grant(&mut rootsrv, ROOTSRV_CONSOLE_REPLY, reply, CapRights::READ);
    grant(
        &mut rootsrv,
        ROOTSRV_KEYBOARD_IRQ,
        CapType::Irq {
            irq_num: keyboard::IRQ,
        },
        CapRights::READ,
    );
    grant(
        &mut rootsrv,
        ROOTSRV_KEYBOARD_DATA,
        CapType::IoPort {
            port: keyboard::DATA_PORT,
        },
        CapRights::READ,
    );

    let notification = object::allocate(CapType::Notification(NotificationId(0)))
        .expect("allocate boot notification");
    grant(
        &mut rootsrv,
        ROOTSRV_CONSOLE_NOTIFICATION,
        CapType::Notification(NotificationId(notification.0)),
        CapRights::READ
            .union(CapRights::WRITE)
            .union(CapRights::GRANT),
    );

    let mut consoled = CSpace::new(3);
    grant(&mut consoled, console::REQUEST, request, CapRights::READ);
    grant(&mut consoled, console::REPLY, reply, CapRights::WRITE);
    grant(
        &mut consoled,
        console::UART_DATA,
        CapType::IoPort { port: serial::COM1 },
        CapRights::WRITE,
    );
    grant(
        &mut consoled,
        console::UART_STATUS,
        CapType::IoPort {
            port: serial::COM1 + 5,
        },
        CapRights::READ,
    );
    (channels, rootsrv, consoled)
}

fn endpoint() -> EndpointId {
    let id =
        object::allocate(CapType::Endpoint(EndpointId(0))).expect("allocate boot service endpoint");
    EndpointId(id.0)
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
