use anyhow::{Result, bail, ensure};
use std::io::{Read, Write};
use std::os::fd::FromRawFd;
use std::os::unix::net::UnixStream;
use std::sync::{Mutex, OnceLock};

static CHANNEL: OnceLock<Mutex<UnixStream>> = OnceLock::new();

pub fn init() -> Result<()> {
    use nix::libc::{F_SETFD, FD_CLOEXEC, fcntl};
    // fd 3 belongs exclusively to this worker. Never inherit it into project commands.
    ensure!(
        unsafe { fcntl(3, F_SETFD, FD_CLOEXEC) } == 0,
        "Missing IrnBru launcher"
    );
    CHANNEL
        .set(Mutex::new(unsafe { UnixStream::from_raw_fd(3) }))
        .map_err(|_| anyhow::anyhow!("Duplicate credential channel"))
}

pub fn exchange(op: &str, expected: Option<&str>, value: Option<&str>) -> Result<Option<String>> {
    let payload = serde_json::to_vec(
        &serde_json::json!({"op":op, "expected":expected, "value":value, "profile":"default"}),
    )?;
    ensure!(payload.len() <= 262144, "Credential request too large");
    let mut stream = CHANNEL
        .get()
        .ok_or_else(|| anyhow::anyhow!("Missing credential channel"))?
        .lock()
        .map_err(|_| anyhow::anyhow!("Credential channel unavailable"))?;
    stream.write_all(&(payload.len() as u32).to_be_bytes())?;
    stream.write_all(&payload)?;
    let mut header = [0; 4];
    stream.read_exact(&mut header)?;
    let count = u32::from_be_bytes(header) as usize;
    ensure!((1..=262144).contains(&count), "Invalid credential response");
    let mut data = vec![0; count];
    stream.read_exact(&mut data)?;
    let response: serde_json::Value = serde_json::from_slice(&data)?;
    if response["ok"] != true {
        bail!("IrnBru denied credential operation");
    }
    Ok(serde_json::from_value(response["value"].clone())?)
}
