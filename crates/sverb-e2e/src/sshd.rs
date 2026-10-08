//! OpenSSH servers in Docker: [`Sshd`] (one container, a [`Profile`]) and [`JumpNet`]
//! (bastion → inner on a private network).
//!
//! The image is `tests/fixtures/sshd/Dockerfile`. Unless `SVERB_E2E_IMAGE` names a
//! prebuilt image (CI builds it once with layer caching), the harness builds it on
//! first use, tagged with a hash of the fixture directory, and reuses it while the
//! fixtures are unchanged.

use std::{
    net::SocketAddr,
    path::Path,
    sync::Arc,
    time::{Duration, Instant},
};

use parking_lot::Mutex;
use sha2::{Digest, Sha256};
use testcontainers::{
    ContainerAsync, GenericBuildableImage, GenericImage, ImageExt,
    core::{BuildImageOptions, ExecCommand, IntoContainerPort, WaitFor, logs::LogFrame},
    runners::{AsyncBuilder, AsyncRunner},
};
use tokio::{io::AsyncReadExt, net::TcpStream, sync::OnceCell};

use crate::{E2eError, Result, diag, keys};

/// The image repository name used for local builds.
pub const IMAGE_NAME: &str = "sverb-e2e-sshd";

/// An sshd configuration of the fixture image (`tests/fixtures/sshd/profiles/`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Profile {
    /// `PasswordAuthentication yes`, user `test`/`test`.
    Password,
    /// Public keys only (`keys/authorized_keys`).
    Key,
    /// `TrustedUserCAKeys` + a host certificate from the test host CA.
    Cert,
    /// Keyboard-interactive through PAM; one round answered with [`keys::OTP`].
    Kbd,
    /// `MaxAuthTries 2`, keys only.
    MaxAuth2,
    /// Only `diffie-hellman-group14-sha1`, `ssh-rsa`, `aes128-cbc`, `hmac-sha1`.
    Legacy,
    /// `AcceptEnv FOO`.
    Env,
    /// TCP and agent forwarding, `GatewayPorts clientspecified`.
    Forward,
    /// The bastion and inner host of a [`JumpNet`].
    Jump,
    /// A `ForceCommand` that makes `uname` fail (non-POSIX shell).
    WindowsLike,
}

impl Profile {
    /// Every profile.
    pub const ALL: [Self; 10] = [
        Self::Password,
        Self::Key,
        Self::Cert,
        Self::Kbd,
        Self::MaxAuth2,
        Self::Legacy,
        Self::Env,
        Self::Forward,
        Self::Jump,
        Self::WindowsLike,
    ];

    /// The profile's name (`profiles/<name>.conf`, `SSHD_PROFILE=<name>`).
    pub fn name(self) -> &'static str {
        match self {
            Self::Password => "password",
            Self::Key => "key",
            Self::Cert => "cert",
            Self::Kbd => "kbd",
            Self::MaxAuth2 => "maxauth2",
            Self::Legacy => "legacy",
            Self::Env => "env",
            Self::Forward => "forward",
            Self::Jump => "jump",
            Self::WindowsLike => "windows-like",
        }
    }
}

// ---------------------------------------------------------------- docker and the image

/// Ping the Docker daemon (`DOCKER_HOST` or the default socket).
///
/// # Errors
/// The daemon is not reachable.
pub async fn ping_docker() -> Result<()> {
    let docker = testcontainers::bollard::Docker::connect_with_defaults()
        .map_err(|e| E2eError::new(format!("connect: {e}")))?;
    tokio::time::timeout(Duration::from_secs(5), docker.ping())
        .await
        .map_err(|_| E2eError::new("ping timed out"))?
        .map_err(|e| E2eError::new(format!("ping: {e}")))?;
    Ok(())
}

/// The files of the build context, relative to the fixture directory.
const CONTEXT: &[&str] = &[
    "keys",
    "sshd_config",
    "profiles",
    "pam",
    "bin",
    "entrypoint.sh",
];

/// `(name, tag)` of the image to run: `SVERB_E2E_IMAGE` (`name:tag`), or a local
/// build tagged with the fixture hash (built once per test process).
///
/// # Errors
/// The build failed.
pub async fn image() -> Result<(String, String)> {
    static IMAGE: OnceCell<std::result::Result<(String, String), String>> = OnceCell::const_new();
    IMAGE
        .get_or_init(|| async { build_image().await.map_err(|e| e.0) })
        .await
        .clone()
        .map_err(E2eError)
}

async fn build_image() -> Result<(String, String)> {
    if let Ok(image) = std::env::var("SVERB_E2E_IMAGE")
        && !image.is_empty()
    {
        let (name, tag) = image.rsplit_once(':').unwrap_or((image.as_str(), "latest"));
        return Ok((name.to_owned(), tag.to_owned()));
    }
    let dir = keys::fixtures_dir();
    let tag = format!("h{}", fixture_hash(&dir)?);
    let mut build = GenericBuildableImage::new(IMAGE_NAME, tag.as_str())
        .with_dockerfile(dir.join("Dockerfile"));
    for entry in CONTEXT {
        build = build.with_file(dir.join(entry), format!("./{entry}"));
    }
    let _image = build
        .build_image_with(BuildImageOptions::new().with_skip_if_exists(true))
        .await
        .map_err(|e| E2eError::new(format!("building {IMAGE_NAME}:{tag}: {e}")))?;
    Ok((IMAGE_NAME.to_owned(), tag))
}

/// A short hash of the Dockerfile and the build context (paths and contents).
///
/// # Errors
/// A fixture file could not be read.
pub fn fixture_hash(dir: &Path) -> Result<String> {
    let mut files = vec![dir.join("Dockerfile")];
    for entry in CONTEXT {
        collect(&dir.join(entry), &mut files)?;
    }
    files.sort();
    let mut hasher = Sha256::new();
    for file in files {
        let rel = file.strip_prefix(dir).unwrap_or(&file);
        hasher.update(rel.to_string_lossy().as_bytes());
        hasher.update([0]);
        hasher.update(std::fs::read(&file)?);
        hasher.update([0]);
    }
    Ok(hex::encode(&hasher.finalize()[..8]))
}

fn collect(path: &Path, out: &mut Vec<std::path::PathBuf>) -> Result<()> {
    if path.is_dir() {
        for entry in std::fs::read_dir(path)? {
            collect(&entry?.path(), out)?;
        }
    } else {
        out.push(path.to_owned());
    }
    Ok(())
}

// ---------------------------------------------------------------- Sshd

/// How to start an [`Sshd`].
#[derive(Debug, Clone)]
pub struct SshdOptions {
    /// The sshd profile.
    pub profile: Profile,
    /// Publish port 22 on the Docker host (reachable from the test runner).
    pub publish: bool,
    /// Join this Docker network (created on first use, removed with its last container).
    pub network: Option<String>,
    /// Container name (also its DNS name on a user-defined network). Default: unique.
    pub name: Option<String>,
    /// Extra environment for the entrypoint.
    pub env: Vec<(String, String)>,
}

impl SshdOptions {
    /// A published container with `profile`.
    pub fn new(profile: Profile) -> Self {
        Self {
            profile,
            publish: true,
            network: None,
            name: None,
            env: Vec::new(),
        }
    }
}

/// The result of [`Sshd::exec`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecOutput {
    /// Exit code (`-1` if Docker did not report one in time).
    pub code: i64,
    /// Standard output.
    pub stdout: String,
    /// Standard error.
    pub stderr: String,
}

impl ExecOutput {
    /// Whether the command exited with 0.
    pub fn success(&self) -> bool {
        self.code == 0
    }
}

/// An OpenSSH server in a container. Removed when dropped; if the test is failing at
/// that point, its logs are dumped first ([`diag`]).
pub struct Sshd {
    container: ContainerAsync<GenericImage>,
    profile: Profile,
    name: String,
    network: Option<String>,
    /// `(host, port)` for the test runner; `None` when port 22 is not published.
    endpoint: Option<(String, u16)>,
    /// Logs collected while the container runs (a restart ends the stream; see
    /// [`Sshd::logs`] for the complete log).
    collected: Arc<Mutex<Vec<u8>>>,
}

impl std::fmt::Debug for Sshd {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Sshd")
            .field("id", &self.container.id())
            .field("name", &self.name)
            .field("profile", &self.profile)
            .field("endpoint", &self.endpoint)
            .finish_non_exhaustive()
    }
}

fn unique(prefix: &str) -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static N: AtomicU64 = AtomicU64::new(0);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or_default();
    format!(
        "{prefix}-{}-{nanos:x}-{}",
        std::process::id(),
        N.fetch_add(1, Ordering::Relaxed)
    )
}

/// The Docker host's name as seen by the runner, from `DOCKER_HOST` (`tcp://h:p`).
fn docker_host_name() -> Option<String> {
    let host = std::env::var("DOCKER_HOST").ok()?;
    let rest = host.strip_prefix("tcp://")?;
    let name = rest.split([':', '/']).next()?;
    (!name.is_empty()).then(|| name.to_owned())
}

impl Sshd {
    /// Start a published container with `profile` and wait until sshd answers.
    ///
    /// # Errors
    /// Docker or the image build failed, or sshd did not come up.
    pub async fn start(profile: Profile) -> Result<Self> {
        Self::start_with(SshdOptions::new(profile)).await
    }

    /// Start a container as described by `opts`.
    ///
    /// # Errors
    /// As [`Sshd::start`].
    pub async fn start_with(opts: SshdOptions) -> Result<Self> {
        let (image_name, tag) = image().await?;
        let name = opts.name.clone().unwrap_or_else(|| unique("sverb-sshd"));
        let mut image = GenericImage::new(image_name, tag)
            .with_wait_for(WaitFor::message_on_stderr("Server listening on"));
        if opts.publish {
            image = image.with_exposed_port(22.tcp());
        }
        let collected = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&collected);
        let mut principals = vec![name.clone()];
        principals.extend(docker_host_name());
        let mut req = image
            .with_container_name(name.clone())
            .with_env_var("SSHD_PROFILE", opts.profile.name())
            .with_env_var("SVERB_HOST_CERT_PRINCIPALS", principals.join(","))
            .with_startup_timeout(Duration::from_secs(120))
            .with_log_consumer(move |frame: &LogFrame| {
                let bytes = match frame {
                    LogFrame::StdOut(b) | LogFrame::StdErr(b) => b,
                };
                sink.lock().extend_from_slice(bytes);
            });
        for (k, v) in &opts.env {
            req = req.with_env_var(k.clone(), v.clone());
        }
        if let Some(network) = &opts.network {
            req = req.with_network(network.clone());
        }
        let container = req.start().await?;
        let mut sshd = Self {
            container,
            profile: opts.profile,
            name,
            network: opts.network,
            endpoint: None,
            collected,
        };
        if opts.publish {
            sshd.refresh_endpoint().await?;
            sshd.wait_ready().await?;
        }
        Ok(sshd)
    }

    async fn refresh_endpoint(&mut self) -> Result<()> {
        let host = self.container.get_host().await?.to_string();
        let port = self.container.get_host_port_ipv4(22.tcp()).await?;
        // `localhost` may resolve to ::1 first; Docker publishes on IPv4.
        let host = if host == "localhost" {
            "127.0.0.1".to_owned()
        } else {
            host
        };
        self.endpoint = Some((host, port));
        Ok(())
    }

    /// Wait until the published port answers with an SSH banner.
    ///
    /// # Errors
    /// Not published, or no banner within [`crate::timeout`].
    pub async fn wait_ready(&self) -> Result<()> {
        let (host, port) = self.endpoint()?;
        let deadline = Instant::now() + crate::timeout();
        loop {
            let last = match banner(&host, port).await {
                Ok(b) if b.starts_with("SSH-2.0-") => return Ok(()),
                Ok(b) => format!("unexpected banner {b:?}"),
                Err(e) => e.to_string(),
            };
            if Instant::now() > deadline {
                return Err(E2eError::new(format!(
                    "sshd at {host}:{port} not ready: {last}"
                )));
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    /// One quick check (2 s) that the published port answers with an SSH banner.
    pub async fn probe(&self) -> bool {
        let Some((host, port)) = self.endpoint.clone() else {
            return false;
        };
        banner(&host, port)
            .await
            .is_ok_and(|b| b.starts_with("SSH-2.0-"))
    }

    fn endpoint(&self) -> Result<(String, u16)> {
        self.endpoint.clone().ok_or_else(|| {
            E2eError::new(format!(
                "{} does not publish port 22 (it is only reachable inside its network)",
                self.name
            ))
        })
    }

    /// The host to connect to from the test runner. Panics for an unpublished
    /// container.
    pub fn host(&self) -> String {
        self.endpoint()
            .map(|(h, _)| h)
            .unwrap_or_else(|e| panic!("{e}"))
    }

    /// The published port (changes after [`Sshd::restart`]). Panics for an
    /// unpublished container.
    pub fn port(&self) -> u16 {
        self.endpoint()
            .map(|(_, p)| p)
            .unwrap_or_else(|e| panic!("{e}"))
    }

    /// `host:port` as a socket address, when the host is an IP literal.
    pub fn socket_addr(&self) -> Option<SocketAddr> {
        let (h, p) = self.endpoint.clone()?;
        format!("{h}:{p}").parse().ok()
    }

    /// The profile.
    pub fn profile(&self) -> Profile {
        self.profile
    }

    /// The container name (its DNS name on [`Sshd::network`]).
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The Docker network it joined, if any.
    pub fn network(&self) -> Option<&str> {
        self.network.as_deref()
    }

    /// The Docker container id.
    pub fn id(&self) -> &str {
        self.container.id()
    }

    /// Run `cmd` with `sh -c` as the user `test`.
    ///
    /// # Errors
    /// Docker failed.
    pub async fn exec(&self, cmd: &str) -> Result<ExecOutput> {
        self.exec_argv(["runuser", "-u", keys::USER, "--", "sh", "-c", cmd])
            .await
    }

    /// Run `cmd` with `sh -c` as root.
    ///
    /// # Errors
    /// Docker failed.
    pub async fn exec_root(&self, cmd: &str) -> Result<ExecOutput> {
        self.exec_argv(["sh", "-c", cmd]).await
    }

    async fn exec_argv<const N: usize>(&self, argv: [&str; N]) -> Result<ExecOutput> {
        let mut res = self.container.exec(ExecCommand::new(argv)).await?;
        let stdout = String::from_utf8_lossy(&res.stdout_to_vec().await?).into_owned();
        let stderr = String::from_utf8_lossy(&res.stderr_to_vec().await?).into_owned();
        let deadline = Instant::now() + crate::timeout();
        let code = loop {
            if let Some(code) = res.exit_code().await? {
                break code;
            }
            if Instant::now() > deadline {
                break -1;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        };
        Ok(ExecOutput {
            code,
            stdout,
            stderr,
        })
    }

    /// Freeze the container (`docker pause`): connections stall without closing.
    ///
    /// # Errors
    /// Docker failed.
    pub async fn pause(&self) -> Result<()> {
        Ok(self.container.pause().await?)
    }

    /// Resume after [`Sshd::pause`].
    ///
    /// # Errors
    /// Docker failed.
    pub async fn unpause(&self) -> Result<()> {
        Ok(self.container.unpause().await?)
    }

    /// Stop the container (SIGTERM, then SIGKILL after 5 s). [`Sshd::start_again`]
    /// starts it again.
    ///
    /// # Errors
    /// Docker failed.
    pub async fn stop(&self) -> Result<()> {
        Ok(self.container.stop_with_timeout(Some(5)).await?)
    }

    /// Start a stopped container again and wait until sshd answers. The host keys
    /// are kept; the published port may change.
    ///
    /// # Errors
    /// Docker failed or sshd did not come up.
    pub async fn start_again(&mut self) -> Result<()> {
        self.container.start().await?;
        if self.endpoint.is_some() {
            self.refresh_endpoint().await?;
            self.wait_ready().await?;
        }
        Ok(())
    }

    /// `docker restart`: [`Sshd::stop`] then [`Sshd::start_again`].
    ///
    /// # Errors
    /// As those.
    pub async fn restart(&mut self) -> Result<()> {
        self.stop().await?;
        self.start_again().await
    }

    /// The host public keys (`type base64`, no comment), ed25519 first.
    ///
    /// # Errors
    /// Docker failed or the keys are missing.
    pub async fn host_keys(&self) -> Result<Vec<String>> {
        let out = self
            .exec_root(
                "cat /etc/ssh/ssh_host_ed25519_key.pub /etc/ssh/ssh_host_ecdsa_key.pub \
                 /etc/ssh/ssh_host_rsa_key.pub",
            )
            .await?;
        if !out.success() {
            return Err(E2eError::new(format!("host keys: {}", out.stderr)));
        }
        Ok(out
            .stdout
            .lines()
            .filter_map(|l| {
                let mut parts = l.split_whitespace();
                Some(format!("{} {}", parts.next()?, parts.next()?))
            })
            .collect())
    }

    /// The `SHA256:…` fingerprint of the host key of `key_type` (`ed25519`, `ecdsa`,
    /// `rsa`), as `ssh-keygen -l` prints it.
    ///
    /// # Errors
    /// Docker failed or there is no such key.
    pub async fn host_fingerprint(&self, key_type: &str) -> Result<String> {
        let out = self
            .exec_root(&format!(
                "ssh-keygen -l -E sha256 -f /etc/ssh/ssh_host_{key_type}_key.pub"
            ))
            .await?;
        out.stdout
            .split_whitespace()
            .nth(1)
            .filter(|f| f.starts_with("SHA256:"))
            .map(str::to_owned)
            .ok_or_else(|| E2eError::new(format!("fingerprint: {out:?}")))
    }

    /// The ed25519 host key the **running** daemon presents (`ssh-keyscan` inside the
    /// container), as `ssh-ed25519 base64`.
    ///
    /// # Errors
    /// Docker failed or sshd did not answer.
    pub async fn served_host_key(&self) -> Result<String> {
        let out = self
            .exec_root("ssh-keyscan -T 2 -t ed25519 127.0.0.1 2>/dev/null")
            .await?;
        out.stdout
            .lines()
            .find_map(|l| {
                let mut parts = l.split_whitespace().skip(1);
                Some(format!("{} {}", parts.next()?, parts.next()?))
            })
            .ok_or_else(|| E2eError::new(format!("ssh-keyscan: {out:?}")))
    }

    /// Replace every host key (and the host certificate in the `cert` profile), make
    /// sshd re-execute with them, and wait until it serves the new ed25519 key.
    /// Returns the new host keys.
    ///
    /// # Errors
    /// Docker failed, or sshd did not come back with the new key in time.
    pub async fn regenerate_host_key(&self) -> Result<Vec<String>> {
        let out = self.exec_root("sverb-regen-hostkeys").await?;
        if !out.success() {
            return Err(E2eError::new(format!("sverb-regen-hostkeys: {out:?}")));
        }
        let keys = self.host_keys().await?;
        let want = keys.first().cloned().unwrap_or_default();
        let deadline = Instant::now() + crate::timeout();
        loop {
            match self.served_host_key().await {
                Ok(served) if served == want => break,
                _ if Instant::now() > deadline => {
                    return Err(E2eError::new("sshd did not serve the new host key"));
                }
                _ => tokio::time::sleep(Duration::from_millis(100)).await,
            }
        }
        if self.endpoint.is_some() {
            self.wait_ready().await?;
        }
        Ok(keys)
    }

    /// The container's complete log (stdout and stderr, across restarts).
    ///
    /// # Errors
    /// Docker failed.
    pub async fn logs(&self) -> Result<String> {
        let out = self.container.stdout_to_vec().await?;
        let err = self.container.stderr_to_vec().await?;
        Ok(format!(
            "{}{}",
            String::from_utf8_lossy(&out),
            String::from_utf8_lossy(&err)
        ))
    }

    /// Dump the logs now ([`diag::dump`]).
    pub fn dump_logs(&self) {
        let logs = docker_cli_logs(self.container.id())
            .unwrap_or_else(|| String::from_utf8_lossy(&self.collected.lock()).into_owned());
        diag::dump(
            &format!(
                "docker logs {} (profile {}, {})",
                self.name,
                self.profile.name(),
                self.container.id()
            ),
            &diag::tail(&logs, 200),
        );
    }
}

/// `docker logs <id>` through the CLI (usable from `Drop`).
fn docker_cli_logs(id: &str) -> Option<String> {
    let out = std::process::Command::new("docker")
        .args(["logs", "--tail", "400", id])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    Some(format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    ))
}

impl Drop for Sshd {
    fn drop(&mut self) {
        if diag::failing() {
            self.dump_logs();
        }
    }
}

/// Read the SSH identification line from `host:port`.
async fn banner(host: &str, port: u16) -> std::io::Result<String> {
    let mut stream = tokio::time::timeout(Duration::from_secs(2), TcpStream::connect((host, port)))
        .await
        .map_err(|_| std::io::Error::other("connect timed out"))??;
    let mut buf = vec![0_u8; 256];
    let n = tokio::time::timeout(Duration::from_secs(2), stream.read(&mut buf))
        .await
        .map_err(|_| std::io::Error::other("no banner"))??;
    Ok(String::from_utf8_lossy(&buf[..n]).trim().to_owned())
}

/// The host key file suffix (`ssh_host_<type>_key`) for an SSH key type name:
/// `ssh-ed25519` → `ed25519`, `ecdsa-sha2-nistp256` → `ecdsa`, `ssh-rsa` /
/// `rsa-sha2-*` → `rsa`.
pub fn ssh_key_file_type(key_type: &str) -> Option<&'static str> {
    match key_type {
        "ssh-ed25519" => Some("ed25519"),
        t if t.starts_with("ecdsa-sha2-") => Some("ecdsa"),
        "ssh-rsa" | "rsa-sha2-256" | "rsa-sha2-512" => Some("rsa"),
        _ => None,
    }
}

// ---------------------------------------------------------------- JumpNet

/// A bastion and an inner host on a private Docker network. Only the bastion's
/// port 22 is published; the inner host is reachable from the bastion as
/// [`JumpNet::inner_addr_from_bastion`].
#[derive(Debug)]
pub struct JumpNet {
    /// The bastion (published, profile `jump`).
    pub bastion: Sshd,
    /// The inner host (not published, profile `jump`).
    pub inner: Sshd,
}

impl JumpNet {
    /// Start both containers on a fresh network.
    ///
    /// # Errors
    /// As [`Sshd::start`].
    pub async fn start() -> Result<Self> {
        let network = unique("sverb-jumpnet");
        let inner = Sshd::start_with(SshdOptions {
            publish: false,
            network: Some(network.clone()),
            name: Some(unique("sverb-inner")),
            ..SshdOptions::new(Profile::Jump)
        })
        .await?;
        let bastion = Sshd::start_with(SshdOptions {
            network: Some(network),
            name: Some(unique("sverb-bastion")),
            ..SshdOptions::new(Profile::Jump)
        })
        .await?;
        Ok(Self { bastion, inner })
    }

    /// The inner host's address as the bastion sees it (`<container name>`, 22).
    pub fn inner_addr_from_bastion(&self) -> (String, u16) {
        (self.inner.name().to_owned(), 22)
    }
}
