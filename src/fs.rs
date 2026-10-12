//! Linux directory-capability access. Remote strings never become ambient paths.
use anyhow::{Context, Result, ensure};
use std::{
    ffi::CString,
    fs::{File, Metadata},
    io::{Read, Seek, SeekFrom},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::fs::MetadataExt,
    },
    path::{Path, PathBuf},
};

pub const STATE: &str = ".ssync-state";
pub const MAX_ENTRIES: usize = 10_000;
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Identity {
    dev: u64,
    ino: u64,
    len: u64,
    mtime: i64,
    mtime_ns: i64,
    ctime: i64,
    ctime_ns: i64,
}
pub fn identity(meta: &Metadata) -> Identity {
    Identity {
        dev: meta.dev(),
        ino: meta.ino(),
        len: meta.len(),
        mtime: meta.mtime(),
        mtime_ns: meta.mtime_nsec(),
        ctime: meta.ctime(),
        ctime_ns: meta.ctime_nsec(),
    }
}
pub fn valid(path: &str) -> Result<()> {
    ensure!(
        !path.is_empty()
            && path.len() <= 4096
            && !path.starts_with('/')
            && !path.contains(['\0', '\\']),
        "unsafe or oversized relative path"
    );
    let parts: Vec<_> = path.split('/').collect();
    ensure!(parts.len() <= 64, "path too deep");
    ensure!(
        parts.iter().all(|p| !p.is_empty()
            && *p != "."
            && *p != ".."
            && p.len() <= 255
            && *p != STATE),
        "unsafe/reserved path component"
    );
    Ok(())
}
#[repr(C)]
struct OpenHow {
    flags: u64,
    mode: u64,
    resolve: u64,
}
fn beneath(dir: &File, path: &str, flags: i32, mode: u32) -> std::io::Result<File> {
    let name = CString::new(if path.is_empty() { "." } else { path })
        .map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidInput))?;
    let how = OpenHow {
        flags: (flags | libc::O_CLOEXEC | libc::O_NOFOLLOW) as u64,
        mode: mode as u64,
        resolve: 0x01 | 0x02 | 0x04 | 0x08,
    };
    // SAFETY: syscall receives live descriptors, nul-terminated name and fixed ABI struct.
    let fd = unsafe {
        libc::syscall(
            libc::SYS_openat2,
            dir.as_raw_fd(),
            name.as_ptr(),
            &how,
            std::mem::size_of::<OpenHow>(),
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(unsafe { File::from_raw_fd(fd as i32) })
}
pub fn absolute(path: &Path) -> Result<PathBuf> {
    let p = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()?.join(path)
    };
    let mut result = PathBuf::from("/");
    for c in p.components() {
        match c {
            std::path::Component::Normal(c) => result.push(c),
            std::path::Component::ParentDir => {
                ensure!(result.pop(), "path above root");
            }
            _ => {}
        }
    }
    Ok(result)
}
pub struct Root {
    dir: File,
    pub path: PathBuf,
}
impl Root {
    pub fn new(path: &Path) -> Result<Self> {
        let path = absolute(path)?;
        let base = File::open("/")?;
        // Opening the locally selected root may cross host mounts; all subsequent operations may not.
        let name = CString::new(path.to_str().context("root must be UTF-8")?)?;
        let how = OpenHow {
            flags: (libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW) as u64,
            mode: 0,
            resolve: 0x02 | 0x04,
        };
        let fd = unsafe {
            libc::syscall(
                libc::SYS_openat2,
                base.as_raw_fd(),
                name.as_ptr(),
                &how,
                std::mem::size_of::<OpenHow>(),
            )
        };
        ensure!(
            fd >= 0,
            "cannot securely open root {:?}: {} (Linux 5.6+ required)",
            path,
            std::io::Error::last_os_error()
        );
        let dir = unsafe { File::from_raw_fd(fd as i32) };
        secure_dir(&dir.metadata()?)?;
        Ok(Self { dir, path })
    }
    pub fn try_clone(&self) -> Result<Self> {
        Ok(Self {
            dir: self.dir.try_clone()?,
            path: self.path.clone(),
        })
    }
    pub fn lock(&self) -> Result<()> {
        ensure!(
            unsafe { libc::flock(self.dir.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0,
            "destination root is busy"
        );
        Ok(())
    }
    pub fn metadata(&self, path: &str) -> Result<Option<Metadata>> {
        if !path.is_empty() {
            valid(path)?;
        }
        match beneath(&self.dir, path, libc::O_PATH, 0) {
            Ok(f) => {
                let m = f.metadata()?;
                ensure!(
                    m.is_dir() || (m.is_file() && m.nlink() == 1),
                    "links/special files are unsupported"
                );
                Ok(Some(m))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e.into()),
        }
    }
    pub fn read(&self, path: &str) -> Result<File> {
        valid(path)?;
        let file = beneath(&self.dir, path, libc::O_RDONLY | libc::O_NONBLOCK, 0)?;
        regular(&file.metadata()?)?;
        Ok(file)
    }
    pub fn dir(&self, path: &str) -> Result<File> {
        if !path.is_empty() {
            valid(path)?;
        }
        let dir = beneath(&self.dir, path, libc::O_RDONLY | libc::O_DIRECTORY, 0)?;
        secure_dir(&dir.metadata()?)?;
        Ok(dir)
    }
    pub fn list(&self, path: &str) -> Result<Vec<String>> {
        let dir = self.dir(path)?;
        let mut names = Vec::new();
        for entry in std::fs::read_dir(format!("/proc/self/fd/{}", dir.as_raw_fd()))? {
            let entry = entry?;
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| anyhow::anyhow!("non-UTF8 filename unsupported"))?;
            if name == STATE {
                continue;
            }
            valid(&name)?;
            names.push(name);
            ensure!(names.len() <= MAX_ENTRIES, "too many entries");
        }
        names.sort();
        Ok(names)
    }
    pub fn mkdirs(&self, path: &str) -> Result<()> {
        if path.is_empty() {
            return Ok(());
        }
        valid(path)?;
        let mut prefix = String::new();
        for part in path.split('/') {
            let parent = self.dir(&prefix)?;
            let name = CString::new(part)?;
            let rc = unsafe { libc::mkdirat(parent.as_raw_fd(), name.as_ptr(), 0o700) };
            if rc != 0 {
                let e = std::io::Error::last_os_error();
                if e.kind() != std::io::ErrorKind::AlreadyExists {
                    return Err(e.into());
                }
            }
            if !prefix.is_empty() {
                prefix.push('/');
            }
            prefix.push_str(part);
            self.dir(&prefix)?;
        }
        Ok(())
    }
    pub fn state(&self) -> Result<File> {
        let name = CString::new(STATE)?;
        if unsafe { libc::mkdirat(self.dir.as_raw_fd(), name.as_ptr(), 0o700) } != 0 {
            let e = std::io::Error::last_os_error();
            if e.kind() != std::io::ErrorKind::AlreadyExists {
                return Err(e.into());
            }
        }
        let dir = beneath(&self.dir, STATE, libc::O_RDONLY | libc::O_DIRECTORY, 0)?;
        let meta = dir.metadata()?;
        ensure!(
            meta.uid() == unsafe { libc::geteuid() } && meta.mode() & 0o777 == 0o700,
            "unsafe partial-state directory"
        );
        let count = std::fs::read_dir(format!("/proc/self/fd/{}", dir.as_raw_fd()))?.count();
        ensure!(
            count <= 128,
            "resume state limit reached; inspect private .ssync-state locally"
        );
        Ok(dir)
    }
    pub fn stage(&self, id: &str) -> Result<(File, File)> {
        ensure!(
            id.len() == 64 && id.bytes().all(|b| b.is_ascii_hexdigit()),
            "invalid stage id"
        );
        let state = self.state()?;
        let entries = std::fs::read_dir(format!("/proc/self/fd/{}", state.as_raw_fd()))?;
        let mut count = 0;
        for entry in entries {
            let _ = entry?;
            count += 1;
        }
        let existed = beneath(&state, id, libc::O_PATH, 0).is_ok();
        ensure!(existed || count < 128, "resume state file limit");
        let file = beneath(
            &state,
            id,
            libc::O_RDWR | libc::O_CREAT | libc::O_NONBLOCK,
            0o600,
        )?;
        let meta = file.metadata()?;
        regular(&meta)?;
        ensure!(
            meta.uid() == unsafe { libc::geteuid() } && meta.mode() & 0o777 == 0o600,
            "unsafe partial file"
        );
        Ok((state, file))
    }
    pub fn partial_capacity(&self, state: &File, id: &str, size: u64) -> Result<()> {
        let mut total = size;
        for entry in std::fs::read_dir(format!("/proc/self/fd/{}", state.as_raw_fd()))? {
            let entry = entry?;
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| anyhow::anyhow!("invalid state entry"))?;
            if name == id {
                continue;
            }
            let f = beneath(state, &name, libc::O_PATH, 0)?;
            let m = f.metadata()?;
            regular(&m)?;
            total = total
                .checked_add(m.len())
                .context("partial quota overflow")?;
        }
        ensure!(
            total <= 16 * 1024 * 1024 * 1024,
            "private partial quota exceeded (16 GiB)"
        );
        Ok(())
    }
    pub fn commit(
        &self,
        state: &File,
        id: &str,
        target: &str,
        expected: &Option<Identity>,
    ) -> Result<()> {
        valid(target)?;
        ensure!(
            &self.metadata(target)?.as_ref().map(identity) == expected,
            "destination changed during transfer"
        );
        let (parent, name) = split(target);
        let dir = self.dir(parent)?;
        // Recheck final type without following it, and directory identity relative to root.
        ensure!(
            &self.metadata(target)?.as_ref().map(identity) == expected,
            "destination changed before commit"
        );
        let from = CString::new(id)?;
        let to = CString::new(name)?;
        ensure!(
            unsafe {
                libc::renameat(
                    state.as_raw_fd(),
                    from.as_ptr(),
                    dir.as_raw_fd(),
                    to.as_ptr(),
                )
            } == 0,
            "atomic replacement failed: {}",
            std::io::Error::last_os_error()
        );
        dir.sync_all()?;
        state.sync_all()?;
        Ok(())
    }
    pub fn remove(&self, path: &str, expected: &Identity) -> Result<()> {
        valid(path)?;
        let meta = self.metadata(path)?.context("deletion entry disappeared")?;
        ensure!(&identity(&meta) == expected, "deletion entry changed");
        let (parent, name) = split(path);
        let dir = self.dir(parent)?;
        let name = CString::new(name)?;
        ensure!(
            unsafe {
                libc::unlinkat(
                    dir.as_raw_fd(),
                    name.as_ptr(),
                    if meta.is_dir() { libc::AT_REMOVEDIR } else { 0 },
                )
            } == 0,
            "safe deletion failed: {}",
            std::io::Error::last_os_error()
        );
        Ok(())
    }
}
pub fn split(path: &str) -> (&str, &str) {
    path.rsplit_once('/').unwrap_or(("", path))
}
fn secure_dir(m: &Metadata) -> Result<()> {
    ensure!(
        m.is_dir() && m.mode() & 0o022 == 0,
        "directory is writable by other users or not a directory"
    );
    Ok(())
}
pub fn regular(m: &Metadata) -> Result<()> {
    ensure!(
        m.is_file() && m.nlink() == 1,
        "only single-link regular files allowed"
    );
    Ok(())
}
pub fn digest(file: &mut File) -> Result<blake3::Hash> {
    file.seek(SeekFrom::Start(0))?;
    let before = identity(&file.metadata()?);
    let mut hash = blake3::Hasher::new();
    let mut buf = vec![0; 200_000];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hash.update(&buf[..n]);
    }
    ensure!(
        before == identity(&file.metadata()?),
        "file changed while hashing"
    );
    Ok(hash.finalize())
}
pub fn open_local_file(path: &Path) -> Result<File> {
    let path = absolute(path)?;
    let parent = Root::new(path.parent().context("file parent missing")?)?;
    parent.read(
        path.file_name()
            .context("file name missing")?
            .to_str()
            .context("filename must be UTF8")?,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;
    #[test]
    fn containment() {
        let temp = tempfile::tempdir().unwrap();
        let root = Root::new(temp.path()).unwrap();
        for p in ["../x", "/x", "a/../x", "a//x", "a\\x", ".ssync-state/x"] {
            assert!(root.read(p).is_err());
        }
        symlink("/etc/passwd", temp.path().join("link")).unwrap();
        assert!(root.read("link").is_err());
        std::fs::write(temp.path().join("a"), b"a").unwrap();
        std::fs::hard_link(temp.path().join("a"), temp.path().join("b")).unwrap();
        assert!(root.read("a").is_err());
        root.mkdirs("dir/sub").unwrap();
        let lock = root.try_clone().unwrap();
        root.lock().unwrap();
        let other = Root::new(temp.path()).unwrap();
        assert!(other.lock().is_err());
        drop(lock);
    }
    #[test]
    fn atomic_conflict() {
        let temp = tempfile::tempdir().unwrap();
        let root = Root::new(temp.path()).unwrap();
        std::fs::write(temp.path().join("x"), b"old").unwrap();
        let old = root.metadata("x").unwrap().map(|m| identity(&m));
        let id = "a".repeat(64);
        let (s, mut f) = root.stage(&id).unwrap();
        use std::io::Write;
        f.write_all(b"new").unwrap();
        std::fs::write(temp.path().join("x"), b"changed").unwrap();
        assert!(root.commit(&s, &id, "x", &old).is_err());
        assert_eq!(std::fs::read(temp.path().join("x")).unwrap(), b"changed");
    }
}
