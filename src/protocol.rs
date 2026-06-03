//! Wire protocol and client library for proxy-mode communication.
//!
//! In proxy mode, unprivileged clients connect to the daemon's Unix socket,
//! send a [`Request`], and receive a [`Response`] — potentially with a
//! BPF file descriptor passed via `SCM_RIGHTS`.
//!
//! The protocol uses [bincode] for serialization, chosen for its compact
//! binary format and zero-copy deserialization.
//!
//! # Wire format
//!
//! ```text
//! Client → Daemon:  bincode-encoded Request
//! Daemon → Client:  bincode-encoded Response + optional FD via SCM_RIGHTS
//! ```
//!
//! # Authentication
//!
//! The daemon authenticates clients using `SO_PEERCRED` — the kernel fills
//! in the client's UID/GID/PID, which cannot be spoofed from userspace.
//!
//! [bincode]: https://docs.rs/bincode

use serde::{Deserialize, Serialize};
use std::os::unix::io::RawFd;

/// A request from the client to the daemon.
#[derive(Debug, Serialize, Deserialize)]
pub enum Request {
    /// Load a BPF program from an ELF object file.
    LoadProgram {
        prog_type: String,
        object_path: String,
        program_name: String,
    },
    /// Create a BPF map with the specified parameters.
    CreateMap {
        map_type: String,
        name: String,
        key_size: u32,
        value_size: u32,
        max_entries: u32,
    },
    /// Attach a loaded BPF program to a target.
    Attach {
        attach_type: String,
        prog_fd: RawFd,
        target: String,
    },
}

/// A response from the daemon to the client.
#[derive(Debug, Serialize, Deserialize)]
pub enum Response {
    /// The operation succeeded. If the operation produces a file descriptor
    /// (e.g. map creation, program loading), it is sent via `SCM_RIGHTS`
    /// and the `fd` field contains the daemon-side FD number for logging.
    Success { fd: Option<RawFd> },
    /// The operation was denied by policy.
    Denied { reason: String },
    /// An internal error occurred.
    Error { message: String },
}

/// Client library for connecting to the bpf-rbacd proxy.
///
/// # Example
///
/// ```rust,no_run
/// use bpf_rbacd::protocol::client::BpfRbacClient;
///
/// let mut client = BpfRbacClient::connect().unwrap();
/// let fd = client.create_map("hash", "my_map", 4, 8, 1024).unwrap();
/// println!("Got map fd: {}", fd);
/// ```
pub mod client {
    use super::*;
    use anyhow::Result;
    use nix::sys::socket::{recvmsg, ControlMessageOwned, MsgFlags};
    use std::io::{IoSliceMut, Write};
    use std::os::unix::io::AsRawFd;
    use std::os::unix::net::UnixStream;

    const SOCKET_PATH: &str = "/run/bpf-rbac.sock";

    /// A client connection to the bpf-rbacd daemon.
    pub struct BpfRbacClient {
        stream: UnixStream,
    }

    impl BpfRbacClient {
        /// Connect to the daemon's Unix socket at `/run/bpf-rbac.sock`.
        ///
        /// # Errors
        ///
        /// Returns an error if the socket does not exist or the connection
        /// is refused (daemon not running).
        pub fn connect() -> Result<Self> {
            let stream = UnixStream::connect(SOCKET_PATH)?;
            Ok(Self { stream })
        }

        /// Request the daemon to create a BPF map and return its file descriptor.
        ///
        /// The returned `RawFd` is valid in the calling process and can be used
        /// with standard BPF operations.
        pub fn create_map(
            &mut self,
            map_type: &str,
            name: &str,
            key_size: u32,
            value_size: u32,
            max_entries: u32,
        ) -> Result<RawFd> {
            let request = Request::CreateMap {
                map_type: map_type.to_string(),
                name: name.to_string(),
                key_size,
                value_size,
                max_entries,
            };

            // Send request
            let bytes = bincode::serialize(&request)?;
            self.stream.write_all(&bytes)?;

            // Receive response with potential FD
            let (response, fd) = self.recv_response_with_fd()?;

            match response {
                Response::Success { fd: Some(_) } => {
                    fd.ok_or_else(|| anyhow::anyhow!("Expected FD but none received"))
                }
                Response::Success { fd: None } => {
                    anyhow::bail!("No FD in response")
                }
                Response::Denied { reason } => {
                    anyhow::bail!("Denied: {}", reason)
                }
                Response::Error { message } => {
                    anyhow::bail!("Error: {}", message)
                }
            }
        }

        fn recv_response_with_fd(&self) -> Result<(Response, Option<RawFd>)> {
            let raw_fd = self.stream.as_raw_fd();

            let mut buf = [0u8; 4096];
            let mut cmsg_buf = nix::cmsg_space!([RawFd; 1]);

            let (bytes_received, received_fd) = {
                let mut iov = [IoSliceMut::new(&mut buf)];
                let msg = recvmsg::<()>(raw_fd, &mut iov, Some(&mut cmsg_buf), MsgFlags::empty())?;

                let mut fd = None;
                for cmsg in msg.cmsgs() {
                    if let ControlMessageOwned::ScmRights(fds) = cmsg {
                        if let Some(&f) = fds.first() {
                            fd = Some(f);
                        }
                    }
                }
                (msg.bytes, fd)
            };

            let response: Response = bincode::deserialize(&buf[..bytes_received])?;
            Ok((response, received_fd))
        }
    }
}
