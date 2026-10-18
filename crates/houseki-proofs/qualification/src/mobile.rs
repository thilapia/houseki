//! Narrow application callbacks for the qualification shell, without a general proof ABI.

use crate::{Controller, Error, Lease, LifecycleError, Workload, produce};
use houseki_proofs::ProofRuntime;
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    panic::{UnwindSafe, catch_unwind},
    path::{Path, PathBuf},
    sync::{Arc, Mutex, OnceLock},
    time::{Instant, SystemTime, UNIX_EPOCH},
};

/// Application state owned by the process with only public paths, admission and runtime state.
struct Mobile {
    /// Application private directory for public observations.
    directory: PathBuf,

    /// Foreground cancellation and exclusive worker admission.
    controller: Arc<Controller>,

    /// Shared public runtime with no protected cache.
    runtime: ProofRuntime,

    /// Serializes complete event lines from callbacks and the worker.
    events: Mutex<()>,

    /// Monotonic origin within this process for cancellation acknowledgment measurements.
    origin: Instant,
}

/// A process retains no private work in this singleton between worker attempts.
static MOBILE: OnceLock<Mobile> = OnceLock::new();

impl Mobile {
    /// Admits one configured workload and immediately returns control to the application.
    fn start(&'static self) -> i32 {
        let workload = match self.request() {
            Ok(workload) => workload,
            Err(_) => return 3,
        };

        let lease = match self.controller.enter() {
            Ok(lease) => lease,
            Err(LifecycleError::Busy) => return 2,
            Err(LifecycleError::Background) => return 4,
            Err(_) => return 7,
        };

        let generation = lease.generation();
        if self.event("admitted", generation).is_err() {
            return 5;
        }

        match std::thread::Builder::new()
            .name("houseki-qualification".to_owned())
            .spawn(move || {
                self.worker(workload, lease);
            }) {
            Ok(_) => 0,
            Err(_) => 5,
        }
    }

    /// Reads a bounded trusted workload selector before any worker imports protected state.
    fn request(&self) -> Result<Workload, Error> {
        let mut request = String::new();
        File::open(self.directory.join("request.txt"))?
            .take(65)
            .read_to_string(&mut request)?;
        if request.len() > 64 {
            return Err(Error::Input("oversized mobile request"));
        }

        request.strip_suffix('\n').unwrap_or(&request).parse()
    }

    /// Drops all private operation state and admission before writing the final cleanup event.
    fn worker(&self, workload: Workload, lease: Lease) {
        let generation = lease.generation();
        let result = catch_unwind(|| {
            self.event("started", generation)?;
            let (artifact, sample) = produce(workload, &self.runtime, lease.token())?;
            if lease.token().is_cancelled() {
                return Err(Error::Input("interrupted attempt"));
            }

            let stamp = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|_| Error::Input("invalid system clock"))?
                .as_nanos();
            let directory = self.directory.join(format!(
                "sample-{}-{stamp}-{generation}",
                std::process::id()
            ));
            artifact.write(&directory)?;
            fs::write(directory.join("observation.json"), sample.json())?;

            Ok::<(), Error>(())
        });

        let outcome = match result {
            Ok(Ok(())) => "complete",
            Ok(Err(_)) if lease.token().is_cancelled() => "cancelled",
            Ok(Err(_)) => "failed",
            Err(_) => "panic",
        };

        drop(lease);

        let _ = self.event(outcome, generation);
    }

    /// Appends one fixed public event with a monotonic timestamp and process identity.
    fn event(&self, event: &'static str, generation: u64) -> Result<(), Error> {
        let _guard = self
            .events
            .lock()
            .map_err(|_| Error::Input("event writer poisoned"))?;
        writeln!(
            OpenOptions::new()
                .create(true)
                .append(true)
                .open(self.directory.join("events.jsonl"))?,
            "{{\"event\":\"{event}\",\"attempt\":{generation},\"elapsed_us\":{},\"pid\":{}}}",
            self.origin.elapsed().as_micros(),
            std::process::id()
        )?;

        Ok(())
    }
}

/// Contains callback panics before control returns to the platform's foreign stack.
fn boundary(body: impl FnOnce() -> i32 + UnwindSafe) -> i32 {
    catch_unwind(body).unwrap_or(6)
}

/// Copies the platform's application private UTF-8 directory before the callback returns.
///
/// # Safety
///
/// A nonnull pointer with an accepted nonzero length must identify that many readable bytes.
///
/// The caller retains ownership, and Rust never stores the borrowed pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn houseki_qualification_configure(
    directory: *const u8,
    length: usize,
) -> i32 {
    boundary(|| {
        if directory.is_null() || length == 0 || length > 4096 {
            return 3;
        }

        // The platform owns readable bytes for this callback, and the path is copied below.
        let bytes = unsafe { std::slice::from_raw_parts(directory, length) };
        let Ok(path) = std::str::from_utf8(bytes) else {
            return 3;
        };

        let path = Path::new(path);
        if !path.is_absolute() || path.as_os_str().is_empty() {
            return 3;
        }

        if let Some(mobile) = MOBILE.get() {
            return if mobile.directory == path { 0 } else { 3 };
        }

        if fs::create_dir_all(path).is_err() {
            return 5;
        }

        match MOBILE.set(Mobile {
            directory: path.to_owned(),
            controller: Arc::new(Controller::new()),
            runtime: ProofRuntime::new(),
            events: Mutex::new(()),
            origin: Instant::now(),
        }) {
            Ok(()) => 0,
            Err(_) => 2,
        }
    })
}

/// Resumes foreground admission and tries one fresh configured attempt without queuing.
#[unsafe(no_mangle)]
pub extern "C" fn houseki_qualification_resume() -> i32 {
    boundary(|| {
        let Some(mobile) = MOBILE.get() else {
            return 1;
        };

        if mobile.controller.set_foreground(true).is_err() {
            return 7;
        }

        mobile.start()
    })
}

/// Requests cancellation without waiting or promising cleanup while the process is suspended.
#[unsafe(no_mangle)]
pub extern "C" fn houseki_qualification_pause() -> i32 {
    boundary(|| {
        let Some(mobile) = MOBILE.get() else {
            return 1;
        };

        if mobile.event("cancel_requested", 0).is_err() {
            let _ = mobile.controller.set_foreground(false);

            return 5;
        }

        if mobile.controller.set_foreground(false).is_err() {
            7
        } else {
            0
        }
    })
}

/// Foreign input rejection and panic containment without performing any proving.
#[cfg(test)]
mod tests {
    use super::*;

    /// Invalid lengths and null pointers are rejected before constructing a borrowed slice.
    #[test]
    fn invalid_foreign_directory_bounds_do_not_dereference() {
        assert_eq!(
            unsafe { houseki_qualification_configure(std::ptr::null(), 1) },
            3
        );
        assert_eq!(
            unsafe { houseki_qualification_configure(std::ptr::null(), 0) },
            3
        );
        assert_eq!(
            unsafe { houseki_qualification_configure(std::ptr::dangling(), 4097) },
            3
        );
    }

    /// A Rust panic becomes a public callback failure rather than crossing a foreign frame.
    #[test]
    fn panicking_callback_stays_inside_rust() {
        let result = std::panic::catch_unwind(|| boundary(|| panic!("synthetic callback failure")));
        assert!(matches!(result, Ok(6)));
    }
}
