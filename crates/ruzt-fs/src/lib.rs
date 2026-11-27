//! Native filesystem operations and an explicitly volatile memory backend.
//!
//! Object identities are metadata. Only sealed handles authorize operations.
//! A service maps kernel-authenticated endpoint badges to these handles.
//! Persistent storage will provide the same folder and document operations.
#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

#[cfg(test)]
mod tests;

static NEXT_STORE: AtomicU64 = AtomicU64::new(1);

pub const MAX_NAME_BYTES: usize = 255;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Denied,
    NotFound,
    NotFolder,
    NotFile,
    InvalidName,
    Exists,
    NotEmpty,
    Conflict,
    Bounds,
    NoSpace,
    NoMemory,
    StaleEdit,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum Access {
    Read = 1,
    Write = 2,
    ReadWrite = 3,
}

impl Access {
    pub fn from_bits(bits: u8) -> Result<Self, Error> {
        match bits {
            1 => Ok(Self::Read),
            2 => Ok(Self::Write),
            3 => Ok(Self::ReadWrite),
            _ => Err(Error::Denied),
        }
    }

    fn includes(self, access: Self) -> bool {
        self as u8 & access as u8 == access as u8
    }
}

/// Stable within a volume, including across rename. This conveys no authority.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ObjectId(pub u64);

/// An instance-bound authority which cannot be constructed from an object ID.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Handle {
    store: u64,
    object: ObjectId,
    access: Access,
}

impl Handle {
    pub fn object_id(self) -> ObjectId {
        self.object
    }
    pub fn access(self) -> Access {
        self.access
    }
    pub fn restrict(self, access: Access) -> Result<Self, Error> {
        if !self.access.includes(access) {
            return Err(Error::Denied);
        }
        Ok(Self { access, ..self })
    }
}

/// An edit has its own authority and becomes stale on commit, abort or removal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Edit {
    store: u64,
    id: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Kind {
    File,
    Folder,
}

/// One case-sensitive UTF-8 component. Traversal and control names are rejected.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Name {
    bytes: [u8; MAX_NAME_BYTES],
    len: u8,
}

impl Name {
    pub fn new(value: &str) -> Result<Self, Error> {
        if value.is_empty()
            || value.len() > MAX_NAME_BYTES
            || [".", ".."].contains(&value)
            || value
                .chars()
                .any(|c| c.is_control() || c == '/' || c == '\\')
        {
            return Err(Error::InvalidName);
        }
        let mut name = Self {
            bytes: [0; MAX_NAME_BYTES],
            len: value.len() as u8,
        };
        name.bytes[..value.len()].copy_from_slice(value.as_bytes());
        Ok(name)
    }

    pub fn as_str(&self) -> &str {
        core::str::from_utf8(&self.bytes[..usize::from(self.len)]).expect("validated UTF-8 name")
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Info {
    pub id: ObjectId,
    pub version: u64,
    pub bytes: u64,
    pub kind: Kind,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DirectoryEntry {
    pub name: Name,
    pub info: Info,
}

#[derive(Clone, Copy, Debug)]
pub struct Limits {
    pub objects: usize,
    pub file_bytes: usize,
    /// Includes capacities retained by both committed files and pending edits.
    pub total_bytes: usize,
    pub edits: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            objects: 128,
            file_bytes: 64 * 1024,
            total_bytes: 512 * 1024,
            edits: 16,
        }
    }
}

enum Data {
    File(Vec<u8>),
    Folder,
}
struct Object {
    id: ObjectId,
    parent: Option<ObjectId>,
    name: Name,
    version: u64,
    data: Data,
}
struct PendingEdit {
    id: u64,
    file: ObjectId,
    base: u64,
    data: Vec<u8>,
}

impl Object {
    fn info(&self) -> Info {
        Info {
            id: self.id,
            version: self.version,
            bytes: match &self.data {
                Data::File(bytes) => bytes.len() as u64,
                Data::Folder => 0,
            },
            kind: match self.data {
                Data::File(_) => Kind::File,
                Data::Folder => Kind::Folder,
            },
        }
    }
}

pub struct MemoryStore {
    instance: u64,
    limits: Limits,
    objects: Vec<Object>,
    edits: Vec<PendingEdit>,
    next_object: u64,
    next_edit: u64,
    generation: u64,
}

impl MemoryStore {
    pub fn new(limits: Limits) -> Result<Self, Error> {
        if limits.objects == 0
            || limits.edits == 0
            || limits.file_bytes > limits.total_bytes
            || limits.total_bytes > isize::MAX as usize
        {
            return Err(Error::Bounds);
        }
        let mut objects = Vec::new();
        objects
            .try_reserve_exact(limits.objects)
            .map_err(|_| Error::NoMemory)?;
        let mut edits = Vec::new();
        edits
            .try_reserve_exact(limits.edits)
            .map_err(|_| Error::NoMemory)?;
        let instance = NEXT_STORE
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |id| id.checked_add(1))
            .map_err(|_| Error::NoSpace)?;
        objects.push(Object {
            id: ObjectId(1),
            parent: None,
            name: Name {
                bytes: [0; MAX_NAME_BYTES],
                len: 0,
            },
            version: 1,
            data: Data::Folder,
        });
        Ok(Self {
            instance,
            limits,
            objects,
            edits,
            next_object: 2,
            next_edit: 1,
            generation: 1,
        })
    }

    pub fn root(&self) -> Handle {
        Handle {
            store: self.instance,
            object: ObjectId(1),
            access: Access::ReadWrite,
        }
    }
    pub fn generation(&self) -> u64 {
        self.generation
    }
    pub fn used_bytes(&self) -> usize {
        self.objects
            .iter()
            .filter_map(|object| match &object.data {
                Data::File(data) => Some(data.capacity()),
                _ => None,
            })
            .chain(self.edits.iter().map(|edit| edit.data.capacity()))
            .fold(0usize, usize::saturating_add)
    }

    fn object(&self, handle: Handle, access: Access) -> Result<usize, Error> {
        if handle.store != self.instance || !handle.access.includes(access) {
            return Err(Error::Denied);
        }
        self.objects
            .iter()
            .position(|object| object.id == handle.object)
            .ok_or(Error::NotFound)
    }

    fn folder(&self, handle: Handle, access: Access) -> Result<usize, Error> {
        let index = self.object(handle, access)?;
        if !matches!(self.objects[index].data, Data::Folder) {
            return Err(Error::NotFolder);
        }
        Ok(index)
    }

    fn child(&self, parent: ObjectId, name: Name) -> Result<usize, Error> {
        self.objects
            .iter()
            .position(|object| object.parent == Some(parent) && object.name == name)
            .ok_or(Error::NotFound)
    }

    /// Metadata is available through either read or write authority.
    pub fn info(&self, handle: Handle) -> Result<Info, Error> {
        Ok(self.objects[self.object(handle, handle.access)?].info())
    }

    pub fn lookup(&self, folder: Handle, name: &str) -> Result<Handle, Error> {
        self.folder(folder, Access::Read)?;
        let object = &self.objects[self.child(folder.object, Name::new(name)?)?];
        Ok(Handle {
            object: object.id,
            ..folder
        })
    }

    /// Enumerate by a stable object-ID cursor, independent of mutable names.
    pub fn next_entry(
        &self,
        folder: Handle,
        after: ObjectId,
    ) -> Result<Option<DirectoryEntry>, Error> {
        self.folder(folder, Access::Read)?;
        Ok(self
            .objects
            .iter()
            .filter(|object| object.parent == Some(folder.object) && object.id > after)
            .min_by_key(|object| object.id)
            .map(|object| DirectoryEntry {
                name: object.name,
                info: object.info(),
            }))
    }

    pub fn create(&mut self, folder: Handle, name: &str, kind: Kind) -> Result<Handle, Error> {
        let parent = self.folder(folder, Access::Write)?;
        let name = Name::new(name)?;
        if self.child(folder.object, name).is_ok() {
            return Err(Error::Exists);
        }
        if self.objects.len() == self.limits.objects {
            return Err(Error::NoSpace);
        }
        let next_object = self.next_object.checked_add(1).ok_or(Error::NoSpace)?;
        let generation = self.generation.checked_add(1).ok_or(Error::NoSpace)?;
        let parent_version = self.objects[parent]
            .version
            .checked_add(1)
            .ok_or(Error::NoSpace)?;
        let id = ObjectId(self.next_object);
        self.objects.push(Object {
            id,
            parent: Some(folder.object),
            name,
            version: 1,
            data: match kind {
                Kind::File => Data::File(Vec::new()),
                Kind::Folder => Data::Folder,
            },
        });
        self.objects[parent].version = parent_version;
        self.next_object = next_object;
        self.generation = generation;
        Ok(Handle {
            object: id,
            ..folder
        })
    }

    pub fn rename(&mut self, folder: Handle, old: &str, new: &str) -> Result<ObjectId, Error> {
        let parent = self.folder(folder, Access::Write)?;
        let old = Name::new(old)?;
        let new = Name::new(new)?;
        let index = self.child(folder.object, old)?;
        let id = self.objects[index].id;
        if old == new {
            return Ok(id);
        }
        if self.child(folder.object, new).is_ok() {
            return Err(Error::Exists);
        }
        let generation = self.generation.checked_add(1).ok_or(Error::NoSpace)?;
        let version = self.objects[parent]
            .version
            .checked_add(1)
            .ok_or(Error::NoSpace)?;
        self.objects[index].name = new;
        self.objects[parent].version = version;
        self.generation = generation;
        Ok(id)
    }

    /// Removing an object invalidates its handles and aborts outstanding edits.
    /// IDs are never recycled and a nonempty folder cannot be removed.
    pub fn remove(&mut self, folder: Handle, name: &str) -> Result<ObjectId, Error> {
        let parent = self.folder(folder, Access::Write)?;
        let index = self.child(folder.object, Name::new(name)?)?;
        let id = self.objects[index].id;
        if self.objects.iter().any(|object| object.parent == Some(id)) {
            return Err(Error::NotEmpty);
        }
        let generation = self.generation.checked_add(1).ok_or(Error::NoSpace)?;
        let version = self.objects[parent]
            .version
            .checked_add(1)
            .ok_or(Error::NoSpace)?;
        self.objects[parent].version = version;
        self.objects.swap_remove(index);
        self.edits.retain(|edit| edit.file != id);
        self.generation = generation;
        Ok(id)
    }

    pub fn read(
        &self,
        file: Handle,
        offset: u64,
        output: &mut [u8],
    ) -> Result<(usize, u64), Error> {
        let object = &self.objects[self.object(file, Access::Read)?];
        let Data::File(data) = &object.data else {
            return Err(Error::NotFile);
        };
        let offset = usize::try_from(offset).map_err(|_| Error::Bounds)?;
        let remaining = data.get(offset..).ok_or(Error::Bounds)?;
        let count = output.len().min(remaining.len());
        output[..count].copy_from_slice(&remaining[..count]);
        Ok((count, object.version))
    }

    pub fn begin_edit(&mut self, file: Handle, expected_version: u64) -> Result<Edit, Error> {
        let object = &self.objects[self.object(file, Access::Write)?];
        let Data::File(data) = &object.data else {
            return Err(Error::NotFile);
        };
        if object.version != expected_version {
            return Err(Error::Conflict);
        }
        if self.edits.len() == self.limits.edits {
            return Err(Error::NoSpace);
        }
        let next_edit = self.next_edit.checked_add(1).ok_or(Error::NoSpace)?;
        let copy = copy_bytes(data, data.len())?;
        self.check_replacement(0, copy.capacity())?;
        let id = self.next_edit;
        self.edits.push(PendingEdit {
            id,
            file: file.object,
            base: expected_version,
            data: copy,
        });
        self.next_edit = next_edit;
        Ok(Edit {
            store: self.instance,
            id,
        })
    }

    fn edit(&self, edit: Edit) -> Result<usize, Error> {
        if edit.store != self.instance {
            return Err(Error::Denied);
        }
        self.edits
            .iter()
            .position(|entry| entry.id == edit.id)
            .ok_or(Error::StaleEdit)
    }

    fn check_replacement(&self, old_capacity: usize, new_capacity: usize) -> Result<(), Error> {
        let used = self
            .used_bytes()
            .checked_sub(old_capacity)
            .and_then(|used| used.checked_add(new_capacity))
            .ok_or(Error::NoSpace)?;
        if used > self.limits.total_bytes {
            return Err(Error::NoSpace);
        }
        Ok(())
    }

    pub fn edit_write(&mut self, edit: Edit, offset: u64, input: &[u8]) -> Result<(), Error> {
        let index = self.edit(edit)?;
        let offset = usize::try_from(offset).map_err(|_| Error::Bounds)?;
        let end = offset
            .checked_add(input.len())
            .filter(|end| *end <= self.limits.file_bytes)
            .ok_or(Error::Bounds)?;
        if input.is_empty() {
            return Ok(());
        }
        if end > self.edits[index].data.len() {
            self.edit_resize(edit, end as u64)?;
        }
        self.edits[index].data[offset..end].copy_from_slice(input);
        Ok(())
    }

    pub fn edit_resize(&mut self, edit: Edit, bytes: u64) -> Result<(), Error> {
        let index = self.edit(edit)?;
        let bytes = usize::try_from(bytes)
            .ok()
            .filter(|bytes| *bytes <= self.limits.file_bytes)
            .ok_or(Error::Bounds)?;
        if bytes == self.edits[index].data.len() {
            return Ok(());
        }
        // Replace on shrink too, so retained capacity cannot evade the quota.
        // Transient copy memory is bounded by two configured file-size limits.
        let replacement = copy_bytes(&self.edits[index].data, bytes)?;
        self.check_replacement(self.edits[index].data.capacity(), replacement.capacity())?;
        self.edits[index].data = replacement;
        Ok(())
    }

    pub fn abort(&mut self, edit: Edit) -> Result<(), Error> {
        let index = self.edit(edit)?;
        self.edits.swap_remove(index);
        Ok(())
    }

    pub fn commit(&mut self, edit: Edit) -> Result<Info, Error> {
        let index = self.edit(edit)?;
        let file = self.edits[index].file;
        let target = self
            .objects
            .iter()
            .position(|object| object.id == file)
            .ok_or(Error::NotFound)?;
        if self.objects[target].version != self.edits[index].base {
            return Err(Error::Conflict);
        }
        let version = self.objects[target]
            .version
            .checked_add(1)
            .ok_or(Error::NoSpace)?;
        let generation = self.generation.checked_add(1).ok_or(Error::NoSpace)?;
        let edit = self.edits.swap_remove(index);
        self.objects[target].data = Data::File(edit.data);
        self.objects[target].version = version;
        self.generation = generation;
        Ok(self.objects[target].info())
    }
}

fn copy_bytes(source: &[u8], bytes: usize) -> Result<Vec<u8>, Error> {
    let mut copy = Vec::new();
    copy.try_reserve_exact(bytes).map_err(|_| Error::NoMemory)?;
    copy.resize(bytes, 0);
    let count = source.len().min(bytes);
    copy[..count].copy_from_slice(&source[..count]);
    Ok(copy)
}
