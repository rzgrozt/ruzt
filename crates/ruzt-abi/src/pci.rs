//! PCI discovery service protocol for directly attached bus-zero functions.

use crate::{ErrorCode, IpcMessage, PciAddress};

/// Startup request endpoint, with receive authority.
pub const REQUEST: u64 = 0;
/// Startup response endpoint, with send authority.
pub const REPLY: u64 = 1;
/// Startup PCI control capability, with read authority.
pub const CONTROL: u64 = 2;
/// Find the first present function at or after the little-endian u16 cursor.
/// The cursor is in 0..=256; 256 denotes the end of bus zero.
pub const NEXT: u64 = 1;
/// One function, encoded as BDF u16, vendor/device u32 and class/revision u32.
pub const FUNCTION: u64 = 2;
/// No remaining functions.
pub const END: u64 = 3;
/// A malformed request.
pub const BAD_REQUEST: u64 = 4;
/// Test-fixture command to exit after acknowledging receipt of the request.
pub const TEST_EXIT: u64 = 5;

/// Read-only identity reported by the discovery service.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Function {
    /// Bus, device and function identifier.
    pub address: PciAddress,
    /// Vendor in bits 15:0 and device in bits 31:16.
    pub vendor_device: u32,
    /// Class in bits 31:8 and revision in bits 7:0.
    pub class_revision: u32,
}

impl Function {
    /// Encode the identity without transferring authority.
    pub fn message(self) -> IpcMessage {
        let mut message = IpcMessage {
            label: FUNCTION,
            length: 10,
            ..IpcMessage::default()
        };
        message.data[..2].copy_from_slice(&self.address.bits().to_le_bytes());
        message.data[2..6].copy_from_slice(&self.vendor_device.to_le_bytes());
        message.data[6..10].copy_from_slice(&self.class_revision.to_le_bytes());
        message
    }

    /// Validate and decode one bus-zero function response.
    pub fn decode(message: &IpcMessage) -> Result<Self, ErrorCode> {
        if message.label != FUNCTION || message.length != 10 || message.cap_count != 0 {
            return Err(ErrorCode::BadMessage);
        }
        let address = u16::from_le_bytes(message.data[..2].try_into().unwrap());
        let vendor_device = u32::from_le_bytes(message.data[2..6].try_into().unwrap());
        if address > 255 || vendor_device as u16 == 0xffff {
            return Err(ErrorCode::BadMessage);
        }
        Ok(Self {
            address: PciAddress::from_bits(address),
            vendor_device,
            class_revision: u32::from_le_bytes(message.data[6..10].try_into().unwrap()),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn function_response_round_trips_and_rejects_invalid_identities() {
        let function = Function {
            address: PciAddress::new(0, 3, 0).unwrap(),
            vendor_device: 0x11e8_1234,
            class_revision: 0xff00_0010,
        };
        let mut message = function.message();
        assert_eq!(Function::decode(&message), Ok(function));
        message.data[1] = 1;
        assert_eq!(Function::decode(&message), Err(ErrorCode::BadMessage));
        message = function.message();
        message.cap_count = 1;
        assert_eq!(Function::decode(&message), Err(ErrorCode::BadMessage));
        message = function.message();
        message.data[2..4].fill(0xff);
        assert_eq!(Function::decode(&message), Err(ErrorCode::BadMessage));
    }
}
