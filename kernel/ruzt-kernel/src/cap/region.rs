//! Page accounting for naturally aligned Untyped regions.

use alloc::vec::Vec;
use ruzt_abi::ErrorCode;

const WORD_PAGES: usize = u64::BITS as usize;

pub(super) struct FreePages {
    count: usize,
    words: Vec<u64>,
}

impl FreePages {
    pub(super) fn new(count: usize) -> Result<Self, ErrorCode> {
        assert!(count.is_power_of_two());
        let word_count = count.div_ceil(WORD_PAGES);
        let mut words = Vec::new();
        words
            .try_reserve_exact(word_count)
            .map_err(|_| ErrorCode::NoMemory)?;
        words.resize(word_count, low_bits(count.min(WORD_PAGES)));
        Ok(Self { count, words })
    }

    pub(super) fn take(&mut self, count: usize) -> Option<usize> {
        assert!(count.is_power_of_two());
        if count > self.count {
            return None;
        }
        let start = if count <= WORD_PAGES {
            let mask = low_bits(count);
            self.words.iter().enumerate().find_map(|(index, &word)| {
                let first = (word.trailing_zeros() as usize).next_multiple_of(count);
                (first..WORD_PAGES)
                    .step_by(count)
                    .find(|&bit| word & (mask << bit) == mask << bit)
                    .map(|bit| index * WORD_PAGES + bit)
            })
        } else {
            let words = count / WORD_PAGES;
            self.words
                .chunks_exact(words)
                .position(|chunk| chunk.iter().all(|&word| word == u64::MAX))
                .map(|index| index * count)
        }?;
        self.update(start, count, false);
        Some(start)
    }

    pub(super) fn put(&mut self, start: usize, count: usize) {
        self.update(start, count, true);
    }

    pub(super) fn is_all_free(&self) -> bool {
        let expected = low_bits(self.count.min(WORD_PAGES));
        self.words.iter().all(|&word| word == expected)
    }

    fn update(&mut self, start: usize, count: usize, free: bool) {
        assert!(count.is_power_of_two() && start % count == 0 && start + count <= self.count);
        let first_word = start / WORD_PAGES;
        if count <= WORD_PAGES {
            let mask = low_bits(count) << (start % WORD_PAGES);
            update_word(&mut self.words[first_word], mask, free);
        } else {
            let end_word = first_word + count / WORD_PAGES;
            for word in &mut self.words[first_word..end_word] {
                update_word(word, u64::MAX, free);
            }
        }
    }
}

fn low_bits(count: usize) -> u64 {
    u64::MAX >> (WORD_PAGES - count)
}

fn update_word(word: &mut u64, mask: u64, free: bool) {
    if free {
        assert_eq!(*word & mask, 0);
        *word |= mask;
    } else {
        assert_eq!(*word & mask, mask);
        *word &= !mask;
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn thirty_two_mib_region_reclaims_both_large_halves() {
        let mut pages = super::FreePages::new(8192).unwrap();
        assert_eq!(pages.take(4096), Some(0));
        assert_eq!(pages.take(4096), Some(4096));
        assert_eq!(pages.take(1), None);
        pages.put(0, 4096);
        assert_eq!(pages.take(4096), Some(0));
        pages.put(0, 4096);
        pages.put(4096, 4096);
        assert!(pages.is_all_free());
        assert_eq!(pages.take(8192), Some(0));
    }
    use super::*;

    #[test]
    fn aligned_delegation_uses_only_wholly_free_ranges() {
        let mut pages = FreePages::new(4).unwrap();
        for page in 0..4 {
            assert_eq!(pages.take(1), Some(page));
        }
        pages.put(1, 1);
        pages.put(2, 1);
        assert_eq!(pages.take(2), None);
        pages.put(3, 1);
        assert_eq!(pages.take(2), Some(2));
        assert_eq!(pages.take(1), Some(1));
        assert_eq!(pages.take(1), None);
    }

    #[test]
    fn a_multiword_region_can_be_reclaimed_after_mixed_allocations() {
        let mut pages = FreePages::new(512).unwrap();
        assert_eq!(pages.take(1), Some(0));
        assert_eq!(pages.take(256), Some(256));
        assert_eq!(pages.take(128), Some(128));
        assert_eq!(pages.take(128), None);
        assert_eq!(pages.take(64), Some(64));
        pages.put(64, 64);
        pages.put(128, 128);
        pages.put(0, 1);
        pages.put(256, 256);
        assert!(pages.is_all_free());
        assert_eq!(pages.take(512), Some(0));
    }
}
