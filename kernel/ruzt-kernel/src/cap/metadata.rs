//! Fallible, ordered storage for bounded capability metadata.

use alloc::vec::Vec;
use core::ops::Index;
use ruzt_abi::ErrorCode;

pub(super) struct MetadataMap<K, V>(Vec<(K, V)>);

impl<K: Ord, V> MetadataMap<K, V> {
    pub(super) const fn new() -> Self {
        Self(Vec::new())
    }

    pub(super) fn len(&self) -> usize {
        self.0.len()
    }

    pub(super) fn reserve(&mut self) -> Result<(), ErrorCode> {
        self.0.try_reserve(1).map_err(|_| ErrorCode::NoMemory)
    }

    pub(super) fn insert(&mut self, key: K, value: V) -> Result<(), ErrorCode> {
        match self.0.binary_search_by(|entry| entry.0.cmp(&key)) {
            Ok(index) => self.0[index].1 = value,
            Err(index) => {
                self.reserve()?;
                self.0.insert(index, (key, value));
            }
        }
        Ok(())
    }

    pub(super) fn get(&self, key: &K) -> Option<&V> {
        let index = self.0.binary_search_by(|entry| entry.0.cmp(key)).ok()?;
        Some(&self.0[index].1)
    }

    pub(super) fn get_mut(&mut self, key: &K) -> Option<&mut V> {
        let index = self.0.binary_search_by(|entry| entry.0.cmp(key)).ok()?;
        Some(&mut self.0[index].1)
    }

    pub(super) fn contains_key(&self, key: &K) -> bool {
        self.get(key).is_some()
    }

    pub(super) fn remove(&mut self, key: &K) -> Option<V> {
        let index = self.0.binary_search_by(|entry| entry.0.cmp(key)).ok()?;
        Some(self.0.remove(index).1)
    }

    pub(super) fn iter(&self) -> impl Iterator<Item = (&K, &V)> {
        self.0.iter().map(|(key, value)| (key, value))
    }

    pub(super) fn values(&self) -> impl Iterator<Item = &V> {
        self.0.iter().map(|(_, value)| value)
    }

    pub(super) fn values_mut(&mut self) -> impl Iterator<Item = &mut V> {
        self.0.iter_mut().map(|(_, value)| value)
    }
}

impl<K: Ord, V> Index<&K> for MetadataMap<K, V> {
    type Output = V;

    fn index(&self, key: &K) -> &V {
        self.get(key).expect("live capability metadata")
    }
}
