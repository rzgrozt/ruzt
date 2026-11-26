//! Single-client block service protocol. One delegated shared frame carries
//! up to eight 512-byte sectors. Writes are durable only after a successful flush.

use crate::{ErrorCode, IpcMessage};

/// Startup receive endpoint.
pub const REQUEST: u64 = 0;
/// Startup reply endpoint.
pub const REPLY: u64 = 1;
/// Startup exclusive PCI device lease.
pub const DEVICE: u64 = 2;
/// Startup Untyped budget for DMA allocations.
pub const MEMORY: u64 = 3;

/// Request device geometry without a payload.
pub const GEOMETRY: u64 = 1;
/// Establish one read/write shared frame with a single capability grant.
pub const ATTACH: u64 = 2;
/// Read sectors into the shared frame.
pub const READ: u64 = 3;
/// Write sectors from the shared frame.
pub const WRITE: u64 = 4;
/// Persist earlier writes, with zero sector and count operands.
pub const FLUSH: u64 = 5;
/// One-byte operation status.
pub const RESULT: u64 = 6;
/// Capacity u64, sector bytes u32, maximum sectors u16, readonly u8, flush u8.
pub const GEOMETRY_RESULT: u64 = 7;
/// Fixture-only request to terminate the driver before replying.
pub const TEST_EXIT: u64 = 8;
/// Fixture-only request to exit after publishing the next write to the device.
pub const TEST_EXIT_ON_WRITE: u64 = 9;
/// Fixture-only request to delegate a read-only DMA capability to the client.
pub const TEST_DELEGATE_DMA: u64 = 10;

/// Successful operation.
pub const OK: u8 = 0;
/// Invalid protocol fields or missing shared frame.
pub const BAD_REQUEST: u8 = 1;
/// Request exceeds the device capacity or transfer bound.
pub const OUT_OF_RANGE: u8 = 2;
/// Device refuses writes.
pub const READ_ONLY: u8 = 3;
/// Device does not implement the operation.
pub const UNSUPPORTED: u8 = 4;
/// Device reported a failed I/O completion.
pub const IO_ERROR: u8 = 5;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// A bounded data request, encoded in ten little-endian payload bytes.
pub struct Request {
    /// One of READ, WRITE or FLUSH.
    pub operation: u64,
    /// Starting logical sector, in 512-byte units.
    pub sector: u64,
    /// Sector count, one through eight for data and zero for flush.
    pub sectors: u16,
}

impl Request {
    /// Encode request operands. The receiver validates their bounds.
    pub fn message(self) -> IpcMessage {
        let mut message = IpcMessage {
            label: self.operation,
            length: 10,
            ..IpcMessage::default()
        };
        message.data[..8].copy_from_slice(&self.sector.to_le_bytes());
        message.data[8..10].copy_from_slice(&self.sectors.to_le_bytes());
        message
    }

    /// Reject malformed lengths, grants, flags, operation codes and counts.
    pub fn decode(message: &IpcMessage) -> Result<Self, ErrorCode> {
        if message.length != 10
            || message.cap_count != 0
            || message.flags != 0
            || ![READ, WRITE, FLUSH].contains(&message.label)
        {
            return Err(ErrorCode::BadMessage);
        }
        let request = Self {
            operation: message.label,
            sector: u64::from_le_bytes(message.data[..8].try_into().unwrap()),
            sectors: u16::from_le_bytes(message.data[8..10].try_into().unwrap()),
        };
        if request.operation == FLUSH {
            if request.sector != 0 || request.sectors != 0 {
                return Err(ErrorCode::BadMessage);
            }
        } else if !(1..=8).contains(&request.sectors) {
            return Err(ErrorCode::BadMessage);
        }
        Ok(request)
    }
}

/// Encode an operation result.
pub fn response(status: u8) -> IpcMessage {
    let mut message = IpcMessage {
        label: RESULT,
        length: 1,
        ..IpcMessage::default()
    };
    message.data[0] = status;
    message
}

/// Encode the fixed geometry and supported persistence behavior.
pub fn geometry(sectors: u64, read_only: bool, flush: bool) -> IpcMessage {
    let mut message = IpcMessage {
        label: GEOMETRY_RESULT,
        length: 16,
        ..IpcMessage::default()
    };
    message.data[..8].copy_from_slice(&sectors.to_le_bytes());
    message.data[8..12].copy_from_slice(&512u32.to_le_bytes());
    message.data[12..14].copy_from_slice(&8u16.to_le_bytes());
    message.data[14] = u8::from(read_only);
    message.data[15] = u8::from(flush);
    message
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_lengths_counts_and_flush_operands_are_checked() {
        let request = Request {
            operation: WRITE,
            sector: u64::MAX,
            sectors: 8,
        };
        assert_eq!(Request::decode(&request.message()), Ok(request));
        for count in [0, 9, u16::MAX] {
            assert_eq!(
                Request::decode(
                    &Request {
                        sectors: count,
                        ..request
                    }
                    .message()
                ),
                Err(ErrorCode::BadMessage)
            );
        }
        assert!(Request::decode(
            &Request {
                operation: FLUSH,
                sector: 0,
                sectors: 0
            }
            .message()
        )
        .is_ok());
        assert!(Request::decode(
            &Request {
                operation: FLUSH,
                sector: 1,
                sectors: 0
            }
            .message()
        )
        .is_err());
        let mut message = request.message();
        message.length -= 1;
        assert_eq!(Request::decode(&message), Err(ErrorCode::BadMessage));
        message = request.message();
        message.cap_count = 1;
        assert_eq!(Request::decode(&message), Err(ErrorCode::BadMessage));
    }
}
