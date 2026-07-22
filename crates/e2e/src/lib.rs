//! Utilities for integration tests
#![allow(
    clippy::missing_errors_doc,
    clippy::module_name_repetitions,
    clippy::struct_excessive_bools,
    clippy::missing_panics_doc,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic
)]

use qos_p256::P256Pair;
use std::future::Future;
use std::net::TcpListener;
use std::process::Command;
use std::thread;
use std::time::Duration;

const MAX_PORT_BIND_WAIT_TIME: Duration = Duration::from_secs(90);
const PORT_BIND_WAIT_TIME_INCREMENT: Duration = Duration::from_millis(500);
const POST_BIND_SLEEP: Duration = Duration::from_millis(500);

/// Wrapper type for [`std::process::Child`] that kills the process on drop.
#[derive(Debug)]
struct ChildWrapper(std::process::Child);

impl From<std::process::Child> for ChildWrapper {
    fn from(child: std::process::Child) -> Self {
        Self(child)
    }
}

impl Drop for ChildWrapper {
    fn drop(&mut self) {
        drop(self.0.kill());
        drop(self.0.wait());
    }
}

/// Get a bind-able TCP port on the local system.
#[must_use]
pub fn find_free_port() -> Option<u16> {
    match TcpListener::bind((HOST_IP, 0)) {
        Ok(listener) => listener.local_addr().ok().map(|addr| addr.port()),
        Err(error) => panic!("failed to bind an OS-assigned local port: {error}"),
    }
}

/// Wait until the given `port` is bound.
///
/// # Panics
///
/// Panics if the port is not bound within `MAX_PORT_BIND_WAIT_TIME`.
fn wait_until_port_is_bound(port: u16) {
    let mut wait_time = PORT_BIND_WAIT_TIME_INCREMENT;

    while wait_time < MAX_PORT_BIND_WAIT_TIME {
        thread::sleep(wait_time);
        if port_is_available(port) {
            wait_time += PORT_BIND_WAIT_TIME_INCREMENT;
        } else {
            thread::sleep(POST_BIND_SLEEP);
            return;
        }
    }
    panic!(
        "Server has not come up: port {} is still available after {}s",
        port,
        MAX_PORT_BIND_WAIT_TIME.as_secs()
    )
}

/// Return whether or not the port can be bound to.
fn port_is_available(port: u16) -> bool {
    TcpListener::bind(("127.0.0.1", port)).is_ok()
}

const HOST_IP: &str = "127.0.0.1";

/// Arguments passed to the `test` function in [`Builder::execute`].
pub struct TestArgs {
    /// The base URL for the REST server (e.g. `http://127.0.0.1:12345`)
    pub base_url: String,
    /// The JSON encoded fake QOS v2 manifest envelope served by the server
    /// under test.
    pub manifest: Vec<u8>,
}

/// Test harness builder.
#[derive(Default)]
pub struct Builder {}

impl Builder {
    /// Create a new instance of [`Self`].
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Execute `test`.
    ///
    /// Spawns the `base_prover` binary, waits for it to bind, then runs
    /// the provided test function with a [`TestArgs`] containing the base URL.
    ///
    /// Note this test env builder relies on the `base_prover` binary already
    /// being built and existing in the target directory. Run `cargo build`
    /// from the workspace root before running integration tests.
    ///
    /// # Panics
    ///
    /// Panics if `test` panics or the server binary cannot be spawned.
    pub async fn execute<F, T>(self, test: F)
    where
        F: Fn(TestArgs) -> T,
        T: Future<Output = ()>,
    {
        let host_port =
            find_free_port().expect("failed to find a free port after maximum search attempts");

        let server_binary = assert_cmd::cargo::cargo_bin("base_prover");
        let temp_dir = tempfile::tempdir().expect("failed to create temp dir");
        let ephemeral_key_path = temp_dir.path().join("qos.ephemeral.key");
        let quorum_key_path = temp_dir.path().join("qos.quorum.key");
        let manifest_path = temp_dir.path().join("qos.manifest");
        P256Pair::generate()
            .expect("failed to generate ephemeral key")
            .to_hex_file(&ephemeral_key_path)
            .expect("failed to write ephemeral key");
        let quorum_pair = P256Pair::generate().expect("failed to generate quorum key");
        quorum_pair
            .to_hex_file(&quorum_key_path)
            .expect("failed to write quorum key");
        // A real JSON encoded v2 manifest envelope: the NSM commits to its
        // hash in the live manifest-commitment PCR.
        let envelope =
            tvc_utils::fake_manifest::fake_manifest_envelope(&quorum_pair.public_key().to_bytes())
                .expect("failed to build fake manifest envelope");
        let manifest =
            qos_json::to_vec(&envelope).expect("failed to serialize fake manifest envelope");
        std::fs::write(&manifest_path, &manifest).expect("failed to write manifest");

        let _server_process: ChildWrapper = Command::new(server_binary)
            .arg("--host")
            .arg(HOST_IP)
            .arg("--port")
            .arg(host_port.to_string())
            .arg("--ephemeral-file")
            .arg(&ephemeral_key_path)
            .arg("--quorum-file")
            .arg(&quorum_key_path)
            .arg("--manifest-file")
            .arg(&manifest_path)
            .arg("--mock-nsm")
            .spawn()
            .expect("failed to spawn base_prover binary")
            .into();

        wait_until_port_is_bound(host_port);

        let base_url = format!("http://{HOST_IP}:{host_port}");

        let test_args = TestArgs { base_url, manifest };

        test(test_args).await;
    }
}
