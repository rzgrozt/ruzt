//! Read regular boot program files from a POSIX ustar archive.

use ruzt_abi::ErrorCode;

const BLOCK: usize = 512;

pub(super) fn file<'a>(archive: &'a [u8], name: &[u8]) -> Result<&'a [u8], ErrorCode> {
    entry(archive, name).map(|(_, data)| data)
}

pub(super) fn entry<'a>(mut archive: &'a [u8], name: &[u8]) -> Result<(&'a str, &'a [u8]), ErrorCode> {
    let mut found = None;
    loop {
        let (header, rest) = archive
            .split_at_checked(BLOCK)
            .ok_or(ErrorCode::BadMessage)?;
        if header.iter().all(|&byte| byte == 0) {
            if rest.len() < BLOCK || rest.iter().any(|&byte| byte != 0) {
                return Err(ErrorCode::BadMessage);
            }
            return found.ok_or(ErrorCode::NotFound);
        }

        if &header[257..265] != b"ustar\x0000"
            || header[156] != b'0'
            || header[345..500].iter().any(|&byte| byte != 0)
            || octal(&header[148..156]) != Some(checksum(header))
        {
            return Err(ErrorCode::BadMessage);
        }
        let len = octal(&header[124..136]).ok_or(ErrorCode::BadMessage)?;
        let padded = len
            .checked_next_multiple_of(BLOCK)
            .ok_or(ErrorCode::BadMessage)?;
        let (data, tail) = rest.split_at_checked(padded).ok_or(ErrorCode::BadMessage)?;
        archive = tail;

        let filename = header[..100].split(|&byte| byte == 0).next().unwrap();
        if filename == name {
            if found.is_some() {
                return Err(ErrorCode::BadMessage);
            }
            let filename = core::str::from_utf8(filename).map_err(|_| ErrorCode::BadMessage)?;
            found = Some((filename, &data[..len]));
        }
    }
}

fn octal(field: &[u8]) -> Option<usize> {
    let digits = field.trim_ascii_start();
    let end = digits
        .iter()
        .position(|&byte| matches!(byte, 0 | b' '))
        .unwrap_or(digits.len());
    if end == 0 || digits[end..].iter().any(|&byte| !matches!(byte, 0 | b' ')) {
        return None;
    }
    digits[..end].iter().try_fold(0usize, |value, &digit| {
        if !(b'0'..=b'7').contains(&digit) {
            return None;
        }
        value.checked_mul(8)?.checked_add(usize::from(digit - b'0'))
    })
}

fn checksum(header: &[u8]) -> usize {
    header[..148]
        .iter()
        .chain(&header[156..])
        .map(|&byte| usize::from(byte))
        .sum::<usize>()
        + 8 * usize::from(b' ')
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;

    fn entry(name: &[u8], data: &[u8]) -> Vec<u8> {
        let mut entry = alloc::vec![0; BLOCK + data.len().next_multiple_of(BLOCK)];
        entry[..name.len()].copy_from_slice(name);
        let len = alloc::format!("{:011o}", data.len());
        entry[124..135].copy_from_slice(len.as_bytes());
        entry[156] = b'0';
        entry[257..265].copy_from_slice(b"ustar\x0000");
        let sum = alloc::format!("{:06o}", checksum(&entry[..BLOCK]));
        entry[148..154].copy_from_slice(sum.as_bytes());
        entry[155] = b' ';
        entry[BLOCK..BLOCK + data.len()].copy_from_slice(data);
        entry
    }

    #[test]
    fn finds_a_file_after_padded_data() {
        let mut archive = entry(b"first", b"payload");
        archive.extend(entry(b"rootsrv", b"ELF"));
        archive.extend([0; 2 * BLOCK]);

        assert_eq!(file(&archive, b"rootsrv"), Ok(&b"ELF"[..]));
        assert_eq!(file(&archive, b"missing"), Err(ErrorCode::NotFound));
    }

    #[test]
    fn rejects_corruption_truncation_and_ambiguous_names() {
        let mut archive = entry(b"rootsrv", b"ELF");
        assert_eq!(
            file(&archive[..BLOCK + 2], b"rootsrv"),
            Err(ErrorCode::BadMessage)
        );
        assert_eq!(file(&archive, b"rootsrv"), Err(ErrorCode::BadMessage));

        archive.extend([0; 2 * BLOCK]);
        archive[124] ^= 1;
        assert_eq!(file(&archive, b"rootsrv"), Err(ErrorCode::BadMessage));

        let mut archive = entry(b"rootsrv", b"ELF");
        archive.extend(entry(b"rootsrv", b"other"));
        archive.extend([0; 2 * BLOCK]);
        assert_eq!(file(&archive, b"rootsrv"), Err(ErrorCode::BadMessage));
    }
}
