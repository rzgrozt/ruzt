use super::*;

struct Registers {
    common: [u8; 56],
    features: u64,
    select: u32,
    capacity: u64,
    reject: bool,
    notification_fails: bool,
}

impl Registers {
    fn new(features: u64) -> Self {
        let mut common = [0; 56];
        common[18..20].copy_from_slice(&1u16.to_le_bytes());
        common[24..26].copy_from_slice(&QUEUE_SIZE.to_le_bytes());
        Self {
            common,
            features,
            select: 0,
            capacity: 128,
            reject: false,
            notification_fails: false,
        }
    }
}

impl Transport for Registers {
    fn read8(&self, at: u64) -> Result<u8, Error> {
        Ok(self.common[at as usize])
    }
    fn read16(&self, at: u64) -> Result<u16, Error> {
        Ok(u16::from_le_bytes(
            self.common[at as usize..at as usize + 2]
                .try_into()
                .unwrap(),
        ))
    }
    fn read32(&self, at: u64) -> Result<u32, Error> {
        if at == 4 {
            return Ok((self.features >> (self.select * 32)) as u32);
        }
        Ok(u32::from_le_bytes(
            self.common[at as usize..at as usize + 4]
                .try_into()
                .unwrap(),
        ))
    }
    fn write8(&mut self, at: u64, value: u8) -> Result<(), Error> {
        self.common[at as usize] = if at == 20 && value == 11 && self.reject {
            3
        } else {
            value
        };
        Ok(())
    }
    fn write16(&mut self, at: u64, value: u16) -> Result<(), Error> {
        self.common[at as usize..at as usize + 2].copy_from_slice(&value.to_le_bytes());
        Ok(())
    }
    fn write32(&mut self, at: u64, value: u32) -> Result<(), Error> {
        if at == 0 {
            self.select = value;
        }
        self.common[at as usize..at as usize + 4].copy_from_slice(&value.to_le_bytes());
        Ok(())
    }
    fn device32(&self, at: u64) -> Result<u32, Error> {
        Ok((self.capacity >> (at * 8)) as u32)
    }
    fn notify(&mut self) -> Result<(), Error> {
        if self.notification_fails {
            Err(Error::Transport)
        } else {
            Ok(())
        }
    }
}

struct Memory([u8; DMA_BYTES]);
impl Dma for Memory {
    fn bytes(&self) -> usize {
        self.0.len()
    }
    fn iova(&self) -> u64 {
        0x0200_0000
    }
    fn read(&self, at: usize, output: &mut [u8]) -> Result<(), Error> {
        output.copy_from_slice(self.0.get(at..at + output.len()).ok_or(Error::Bounds)?);
        Ok(())
    }
    fn write(&mut self, at: usize, input: &[u8]) -> Result<(), Error> {
        self.0
            .get_mut(at..at + input.len())
            .ok_or(Error::Bounds)?
            .copy_from_slice(input);
        Ok(())
    }
    fn read_index(&self, at: usize) -> Result<u16, Error> {
        let mut bytes = [0; 2];
        self.read(at, &mut bytes)?;
        Ok(u16::from_le_bytes(bytes))
    }
    fn write_index(&mut self, at: usize, value: u16) -> Result<(), Error> {
        self.write(at, &value.to_le_bytes())
    }
}

fn device() -> Block<Registers, Memory> {
    Block::new(
        Registers::new(VERSION_1 | ACCESS_PLATFORM | FLUSH),
        Memory([0xaa; DMA_BYTES]),
    )
    .unwrap()
}

fn complete(device: &mut Block<Registers, Memory>, id: u32, length: u32, status: u8) {
    let at = USED + 4 + usize::from(device.index % QUEUE_SIZE) * 8;
    device.dma.write(at, &id.to_le_bytes()).unwrap();
    device.dma.write(at + 4, &length.to_le_bytes()).unwrap();
    device.dma.write(STATUS, &[status]).unwrap();
    device
        .dma
        .write_index(USED + 2, device.index.wrapping_add(1))
        .unwrap();
}

#[test]
fn negotiation_requires_isolation_and_durability() {
    for features in [
        0,
        VERSION_1 | FLUSH,
        ACCESS_PLATFORM | FLUSH,
        VERSION_1 | ACCESS_PLATFORM,
    ] {
        assert!(matches!(
            Block::new(Registers::new(features), Memory([0; DMA_BYTES])),
            Err(Error::Unsupported)
        ));
    }
    let mut registers = Registers::new(VERSION_1 | ACCESS_PLATFORM | FLUSH);
    registers.reject = true;
    assert!(matches!(
        Block::new(registers, Memory([0; DMA_BYTES])),
        Err(Error::Unsupported)
    ));
    let mut read_only = Block::new(
        Registers::new(VERSION_1 | ACCESS_PLATFORM | READ_ONLY),
        Memory([0; DMA_BYTES]),
    )
    .unwrap();
    assert!(read_only.read_only());
    assert_eq!(read_only.begin_write(0, &[0; 512]), Err(Error::ReadOnly));
    assert_eq!(read_only.begin_flush(), Err(Error::Unsupported));
    assert!(read_only.begin_read(0, 512).is_ok());
}

#[test]
fn read_ownership_bounds_and_descriptor_addresses() {
    let mut device = device();
    assert!(device.dma.0.iter().all(|byte| *byte == 0));
    for (sector, bytes) in [(0, 0), (0, 513), (0, 8192), (128, 512), (u64::MAX, 512)] {
        assert_eq!(device.begin_read(sector, bytes), Err(Error::Bounds));
    }
    device.begin_read(127, 512).unwrap();
    assert_eq!(
        u64::from_le_bytes(device.dma.0[..8].try_into().unwrap()),
        0x0200_0000 + HEADER as u64
    );
    assert_eq!(device.dma.read_index(AVAIL + 2).unwrap(), 1);
    let published = device.dma.0;
    assert_eq!(device.begin_write(0, &[0xaa; 512]), Err(Error::Busy));
    assert_eq!(device.dma.0, published);
    assert_eq!(device.poll(&mut [0; 1]), Err(Error::Bounds));
    assert_eq!(device.poll(&mut [0; 512]), Ok(false));
    device.dma.write(DATA, &[0x67; 512]).unwrap();
    complete(&mut device, 0, 513, 0);
    let mut output = [0; 512];
    assert_eq!(device.poll(&mut output), Ok(true));
    assert_eq!(output, [0x67; 512]);
}

#[test]
fn invalid_completions_poison_the_queue_without_copying_data() {
    for (id, length, status) in [
        (1, 513, 0),
        (0, 1, 0),
        (0, 514, 0),
        (0, 513, 0xff),
        (0, 0, 1),
    ] {
        let mut device = device();
        device.begin_read(0, 512).unwrap();
        complete(&mut device, id, length, status);
        let mut output = [0x99; 512];
        assert_eq!(device.poll(&mut output), Err(Error::Device));
        assert_eq!(output, [0x99; 512]);
        assert_eq!(device.begin_flush(), Err(Error::Failed));
    }
    let mut device = device();
    device.begin_read(0, 512).unwrap();
    device.dma.write_index(USED + 2, 2).unwrap();
    assert_eq!(device.poll(&mut [0; 512]), Err(Error::Device));
}

#[test]
fn completion_errors_return_to_idle_and_indices_wrap() {
    let mut device = device();
    for (status, expected) in [(1, Error::Io), (2, Error::Unsupported)] {
        device.begin_read(0, 512).unwrap();
        complete(&mut device, 0, 1, status);
        assert_eq!(device.poll(&mut [0; 512]), Err(expected));
    }
    device.index = u16::MAX;
    device.dma.write_index(USED + 2, u16::MAX).unwrap();
    device.begin_flush().unwrap();
    assert_eq!(device.dma.read_index(AVAIL + 2).unwrap(), 0);
    complete(&mut device, 0, 1, 0);
    assert_eq!(device.poll(&mut []), Ok(true));
    assert_eq!(device.index, 0);
    device.begin_write(0, &[0x87; 4096]).unwrap();
    assert_eq!(&device.dma.0[DATA..DATA + 4096], &[0x87; 4096]);
    complete(&mut device, 0, 1, 0);
    assert_eq!(device.poll(&mut []), Ok(true));
}

#[test]
fn failed_notifications_and_capacity_changes_stop_publication() {
    let mut device = device();
    device.transport.notification_fails = true;
    assert_eq!(device.begin_flush(), Err(Error::Transport));
    assert_eq!(device.begin_read(0, 512), Err(Error::Failed));
    let mut device = super::tests::device();
    device.transport.capacity += 1;
    assert_eq!(device.begin_flush(), Err(Error::Device));
    assert_eq!(device.dma.read_index(AVAIL + 2).unwrap(), 0);
}
