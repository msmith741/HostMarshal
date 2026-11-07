//! Real but tightly bounded M3 observation transport implementations.
//! No arbitrary shell commands, client URLs, HTTP body exposure or redirects.
use std::{future::Future, net::IpAddr, path::Path, pin::Pin, process::Stdio};

use serde_json::{Value, json};
use tokio::{io::AsyncReadExt, process::Command};

use crate::{
    adapter::{
        AdapterFailure, AdapterInvocation, HTTPS_HEALTH, LINUX_UNAME, OperationAdapter,
        OperationDescriptor,
    },
    transport::check_public_trust_file,
};

pub struct LinuxUname;

impl OperationAdapter for LinuxUname {
    fn descriptor(&self) -> &'static OperationDescriptor {
        &LINUX_UNAME
    }

    fn execute(
        &self,
        invocation: AdapterInvocation,
    ) -> Pin<Box<dyn Future<Output = Result<Value, AdapterFailure>> + Send + '_>> {
        Box::pin(async move {
            let host = invocation.target;
            let Some(endpoint) = host.ssh else {
                return Err(AdapterFailure::Rejected);
            };
            let Some(lease) = invocation.lease else {
                return Err(AdapterFailure::Rejected);
            };
            if lease.scope().operation() != LINUX_UNAME.id
                || lease.scope().target() != host.id
                || lease.scope().purpose() != "ssh-observe"
            {
                return Err(AdapterFailure::Rejected);
            }
            let known_hosts = Path::new(&endpoint.known_hosts_file);
            let identity = Path::new(lease.opaque_handle());
            if check_public_trust_file(known_hosts).is_err()
                || crate::credentials::check_private_key_file(identity).is_err()
            {
                return Err(AdapterFailure::Rejected);
            }
            // Absolute executable path, argv-only. -F /dev/null prevents user ssh
            // configuration, ProxyCommand and Include injection. We never use sh -c.
            // A host key MUST be present under the trusted inventory ID alias.
            let mut command = Command::new("/usr/bin/ssh");
            command
                .arg("-F")
                .arg("/dev/null")
                .arg("-o")
                .arg("BatchMode=yes")
                .arg("-o")
                .arg("PasswordAuthentication=no")
                .arg("-o")
                .arg("KbdInteractiveAuthentication=no")
                .arg("-o")
                .arg("GSSAPIAuthentication=no")
                .arg("-o")
                .arg("IdentitiesOnly=yes")
                .arg("-o")
                .arg("IdentityAgent=none")
                .arg("-o")
                .arg("StrictHostKeyChecking=yes")
                .arg("-o")
                .arg("UpdateHostKeys=no")
                .arg("-o")
                .arg("CheckHostIP=no")
                .arg("-o")
                .arg("GlobalKnownHostsFile=/dev/null")
                .arg("-o")
                .arg(format!("UserKnownHostsFile={}", endpoint.known_hosts_file))
                .arg("-o")
                .arg(format!("HostKeyAlias={}", host.id))
                .arg("-o")
                .arg("ProxyCommand=none")
                .arg("-o")
                .arg("ProxyJump=none")
                .arg("-o")
                .arg("ClearAllForwardings=yes")
                .arg("-o")
                .arg("PermitLocalCommand=no")
                .arg("-o")
                .arg("ConnectTimeout=2")
                .arg("-o")
                .arg("ConnectionAttempts=1")
                .arg("-T")
                .arg("-i")
                .arg(identity)
                .arg("-l")
                .arg(&endpoint.user)
                .arg("-p")
                .arg(endpoint.port.to_string())
                .arg(&host.address)
                .arg("uname -s")
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .kill_on_drop(true);

            let mut child = command.spawn().map_err(|_| AdapterFailure::Unavailable)?;
            let stdout = child.stdout.take().ok_or(AdapterFailure::Failed)?;
            let mut data = Vec::with_capacity(32);
            // Bound malicious/unexpected server output BEFORE waiting on the child.
            stdout
                .take(65)
                .read_to_end(&mut data)
                .await
                .map_err(|_| AdapterFailure::Failed)?;
            if data.len() > 64 {
                return Err(AdapterFailure::Rejected);
            }
            let status = child.wait().await.map_err(|_| AdapterFailure::Failed)?;
            if !status.success() || data != b"Linux\n" {
                return Err(AdapterFailure::Rejected);
            }
            Ok(json!({"id": host.id, "os": "Linux"}))
        })
    }
}

pub struct HttpsHealth;

impl OperationAdapter for HttpsHealth {
    fn descriptor(&self) -> &'static OperationDescriptor {
        &HTTPS_HEALTH
    }

    fn execute(
        &self,
        invocation: AdapterInvocation,
    ) -> Pin<Box<dyn Future<Output = Result<Value, AdapterFailure>> + Send + '_>> {
        Box::pin(async move {
            let host = invocation.target;
            if invocation.lease.is_some() {
                return Err(AdapterFailure::Rejected);
            }
            let Some(endpoint) = host.https else {
                return Err(AdapterFailure::Rejected);
            };
            // URL is derived solely from typed, validated *trusted inventory*.
            // "/health" is a compiled-in path; MCP cannot choose a URL or headers.
            let address = if host.address.parse::<IpAddr>().is_ok_and(|ip| ip.is_ipv6()) {
                format!("[{}]", host.address)
            } else {
                host.address.clone()
            };
            let url = format!("https://{address}:{}/health", endpoint.port);
            let mut client = reqwest::Client::builder()
                .https_only(true)
                .no_proxy()
                .redirect(reqwest::redirect::Policy::none())
                .connect_timeout(std::time::Duration::from_secs(2))
                .timeout(std::time::Duration::from_secs(3))
                .user_agent("HostMarshal/0.1");
            if let Some(ca) = endpoint.ca_certificate_file {
                let path = Path::new(&ca);
                check_public_trust_file(path).map_err(|_| AdapterFailure::Rejected)?;
                let bytes = std::fs::read(path).map_err(|_| AdapterFailure::Rejected)?;
                let cert =
                    reqwest::Certificate::from_pem(&bytes).map_err(|_| AdapterFailure::Rejected)?;
                client = client.add_root_certificate(cert);
            }
            let client = client.build().map_err(|_| AdapterFailure::Failed)?;
            let response = client
                .get(url)
                .send()
                .await
                .map_err(|_| AdapterFailure::Failed)?;
            // Do not consume, log, parse or expose arbitrary API response bodies.
            // 3xx is returned as unhealthy, never followed.
            let status = response.status().as_u16();
            Ok(json!({
                "id": host.id,
                "statusCode": status,
                "healthy": (200..300).contains(&status)
            }))
        })
    }
}
