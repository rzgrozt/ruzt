use super::*;

fn store() -> MemoryStore {
    MemoryStore::new(Limits::default()).unwrap()
}

fn document(store: &mut MemoryStore, folder: Handle, name: &str, data: &[u8]) -> Handle {
    let file = store.create(folder, name, Kind::File).unwrap();
    let edit = store.begin_edit(file, 1).unwrap();
    store.edit_write(edit, 0, data).unwrap();
    store.commit(edit).unwrap();
    file
}

fn content(store: &MemoryStore, file: Handle) -> Vec<u8> {
    let mut output = alloc::vec![0; store.info(file).unwrap().bytes as usize];
    let (count, _) = store.read(file, 0, &mut output).unwrap();
    assert_eq!(count, output.len());
    output
}

#[test]
fn folder_grants_scope_lookup_and_cannot_expand_access() {
    let mut store = store();
    let root = store.root();
    let shared = store.create(root, "Shared", Kind::Folder).unwrap();
    let private = store.create(root, "Private", Kind::Folder).unwrap();
    document(&mut store, shared, "notes.txt", b"shared notes");
    document(&mut store, private, "secret.txt", b"private notes");
    let read_only = shared.restrict(Access::Read).unwrap();
    let notes = store.lookup(read_only, "notes.txt").unwrap();
    assert_eq!(content(&store, notes), b"shared notes");
    assert_eq!(notes.access(), Access::Read);
    assert_eq!(notes.restrict(Access::ReadWrite), Err(Error::Denied));
    assert_eq!(store.begin_edit(notes, 2), Err(Error::Denied));
    assert_eq!(
        store.create(read_only, "other.txt", Kind::File),
        Err(Error::Denied)
    );
    assert_eq!(store.lookup(read_only, "secret.txt"), Err(Error::NotFound));
    for name in [
        "..",
        ".",
        "../Private",
        "/Private",
        "Private\\secret.txt",
        "",
        "bad\0name",
        "bad\nname",
    ] {
        assert_eq!(store.lookup(read_only, name), Err(Error::InvalidName));
    }
    let first = store.next_entry(read_only, ObjectId(0)).unwrap().unwrap();
    assert_eq!(first.name.as_str(), "notes.txt");
    assert_eq!(first.info.id, notes.object_id());
    assert!(store
        .next_entry(read_only, first.info.id)
        .unwrap()
        .is_none());
    assert!(Name::new("café 📝.txt").is_ok());
    assert!(Name::new(&"x".repeat(MAX_NAME_BYTES)).is_ok());
    assert_eq!(
        Name::new(&"x".repeat(MAX_NAME_BYTES + 1)),
        Err(Error::InvalidName)
    );
}

#[test]
fn edits_publish_atomically_and_reject_stale_base_versions() {
    let mut store = store();
    let root = store.root();
    let file = document(&mut store, root, "draft.txt", b"original");
    let base = store.info(file).unwrap().version;
    let first = store.begin_edit(file, base).unwrap();
    let second = store.begin_edit(file, base).unwrap();
    store.edit_resize(first, 0).unwrap();
    store.edit_write(first, 0, b"first save").unwrap();
    store.edit_resize(second, 0).unwrap();
    store.edit_write(second, 0, b"concurrent save").unwrap();
    assert_eq!(content(&store, file), b"original");
    let generation = store.generation();
    let published = store.commit(first).unwrap();
    assert_eq!(published.version, base + 1);
    assert_eq!(store.generation(), generation + 1);
    assert_eq!(content(&store, file), b"first save");
    assert_eq!(store.commit(first), Err(Error::StaleEdit));
    assert_eq!(store.commit(second), Err(Error::Conflict));
    assert_eq!(store.generation(), generation + 1);
    assert_eq!(content(&store, file), b"first save");
    assert_eq!(store.begin_edit(file, base), Err(Error::Conflict));
    store.abort(second).unwrap();
    assert_eq!(store.commit(second), Err(Error::StaleEdit));
    assert_eq!(store.used_bytes(), b"first save".len());
}

#[test]
fn rename_preserves_open_handles_and_failed_renames_preserve_the_tree() {
    let mut store = store();
    let root = store.root();
    let folder = store.create(root, "Documents", Kind::Folder).unwrap();
    let file = document(&mut store, folder, "old.txt", b"saved document");
    let other = document(&mut store, folder, "other.txt", b"other");
    let info = store.info(file).unwrap();
    let pending = store.begin_edit(file, info.version).unwrap();
    store.edit_resize(pending, 0).unwrap();
    store.edit_write(pending, 0, b"renamed edit").unwrap();
    assert_eq!(store.rename(folder, "old.txt", "new.txt"), Ok(info.id));
    assert_eq!(store.info(file), Ok(info));
    assert_eq!(
        store.lookup(folder, "new.txt").unwrap().object_id(),
        info.id
    );
    assert_eq!(store.lookup(folder, "old.txt"), Err(Error::NotFound));
    assert_eq!(content(&store, file), b"saved document");
    assert_eq!(store.commit(pending).unwrap().id, info.id);
    assert_eq!(content(&store, file), b"renamed edit");
    let generation = store.generation();
    assert_eq!(
        store.rename(folder, "new.txt", "other.txt"),
        Err(Error::Exists)
    );
    assert_eq!(
        store.rename(folder, "new.txt", "../escape"),
        Err(Error::InvalidName)
    );
    assert_eq!(store.generation(), generation);
    assert_eq!(content(&store, other), b"other");
    assert_eq!(store.remove(root, "Documents"), Err(Error::NotEmpty));
}

#[test]
fn byte_and_edit_quotas_recover_after_abort_shrink_and_removal() {
    let mut store = MemoryStore::new(Limits {
        objects: 4,
        file_bytes: 16,
        total_bytes: 32,
        edits: 2,
    })
    .unwrap();
    let root = store.root();
    let a = document(&mut store, root, "a", &[0x55; 16]);
    let b = store.create(root, "b", Kind::File).unwrap();
    let c = store.create(root, "c", Kind::File).unwrap();
    assert_eq!(store.create(root, "full", Kind::File), Err(Error::NoSpace));
    let edit = store.begin_edit(a, 2).unwrap();
    let empty = store.begin_edit(b, 1).unwrap();
    assert_eq!(store.used_bytes(), 32);
    assert_eq!(store.begin_edit(c, 1), Err(Error::NoSpace));
    assert_eq!(store.edit_write(empty, 0, &[1]), Err(Error::NoSpace));
    assert_eq!(store.edit_write(edit, 16, &[1]), Err(Error::Bounds));
    assert_eq!(content(&store, a), [0x55; 16]);
    store.edit_resize(edit, 8).unwrap();
    assert_eq!(store.used_bytes(), 24);
    store.edit_resize(edit, 0).unwrap();
    assert_eq!(store.used_bytes(), 16);
    store.abort(edit).unwrap();
    store.abort(empty).unwrap();
    let edit = store.begin_edit(a, 2).unwrap();
    assert_eq!(store.used_bytes(), 32);
    store.remove(root, "a").unwrap();
    assert_eq!(store.used_bytes(), 0);
    assert_eq!(store.commit(edit), Err(Error::StaleEdit));
    assert_eq!(store.info(a), Err(Error::NotFound));
    let replacement = store.create(root, "a", Kind::File).unwrap();
    assert_ne!(replacement.object_id(), a.object_id());
}

#[test]
fn sparse_edits_zero_gaps_and_invalid_ranges_do_not_change_committed_data() {
    let mut store = store();
    let root = store.root();
    let file = store.create(root, "sparse", Kind::File).unwrap();
    let edit = store.begin_edit(file, 1).unwrap();
    store.edit_write(edit, 5, b"ab").unwrap();
    assert_eq!(store.edit_write(edit, u64::MAX, b"bad"), Err(Error::Bounds));
    assert_eq!(store.edit_resize(edit, u64::MAX), Err(Error::Bounds));
    assert_eq!(content(&store, file), b"");
    assert_eq!(store.commit(edit).unwrap().bytes, 7);
    assert_eq!(content(&store, file), [0, 0, 0, 0, 0, b'a', b'b']);
    let mut output = [0x99; 10];
    assert_eq!(store.read(file, 5, &mut output), Ok((2, 2)));
    assert_eq!(&output[..2], b"ab");
    assert_eq!(&output[2..], &[0x99; 8]);
    assert_eq!(store.read(file, u64::MAX, &mut output), Err(Error::Bounds));
    let empty = store.begin_edit(file, 2).unwrap();
    store.edit_write(empty, 64 * 1024, b"").unwrap();
    assert_eq!(store.commit(empty).unwrap().bytes, 7);
}

#[test]
fn handles_and_edits_cannot_cross_store_instances() {
    let mut first = store();
    let mut second = store();
    let root = first.root();
    let file = first.create(root, "first", Kind::File).unwrap();
    assert_eq!(second.info(root), Err(Error::Denied));
    assert_eq!(
        second.create(root, "foreign", Kind::File),
        Err(Error::Denied)
    );
    let edit = first.begin_edit(file, 1).unwrap();
    assert_eq!(second.edit_write(edit, 0, b"foreign"), Err(Error::Denied));
    assert_eq!(second.commit(edit), Err(Error::Denied));
    let write_only = file.restrict(Access::Write).unwrap();
    assert_eq!(first.read(write_only, 0, &mut [0; 8]), Err(Error::Denied));
    assert_eq!(first.info(write_only).unwrap().id, file.object_id());
}
