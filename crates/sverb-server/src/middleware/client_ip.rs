//! Client IP resolution for rate limiting (SPEC §10.5).
//!
//! The TCP peer address is used unless the peer is one of the configured
//! `SVERB_TRUSTED_PROXIES`. Only then is `X-Forwarded-For` consulted, walked
//! right to left (each trusted proxy appends the address it saw), and the
//! first hop that is not itself a trusted proxy is the client.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use axum::extract::{ConnectInfo, Request, State};
use axum::http::HeaderMap;
use axum::middleware::Next;
use axum::response::Response;
use ipnet::IpNet;

use crate::state::AppState;

/// The resolved client address (stored as a request extension).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClientIp(pub IpAddr);

fn trusted(ip: IpAddr, proxies: &[IpNet]) -> bool {
    proxies.iter().any(|net| net.contains(&ip))
}

fn parse_hop(s: &str) -> Option<IpAddr> {
    let s = s.trim();
    s.parse::<IpAddr>()
        .ok()
        .or_else(|| s.parse::<SocketAddr>().ok().map(|a| a.ip()))
}

/// Resolves the client IP from the peer address and headers.
#[must_use]
pub fn resolve(peer: IpAddr, headers: &HeaderMap, proxies: &[IpNet]) -> IpAddr {
    if !trusted(peer, proxies) {
        return peer;
    }
    let hops: Vec<&str> = headers
        .get_all("x-forwarded-for")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .collect();
    let mut last_trusted = peer;
    for hop in hops.iter().rev() {
        match parse_hop(hop) {
            Some(ip) if trusted(ip, proxies) => last_trusted = ip,
            Some(ip) => return ip,
            // Garbage can only come from the untrusted (client) end of the chain.
            None => return last_trusted,
        }
    }
    last_trusted
}

/// Inserts [`ClientIp`]. Without `ConnectInfo` (in-process tests) the peer
/// is taken to be `0.0.0.0`.
pub async fn layer(State(state): State<AppState>, mut req: Request, next: Next) -> Response {
    let peer = req
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED), |c| c.0.ip());
    let ip = resolve(peer, req.headers(), &state.config().trusted_proxies);
    req.extensions_mut().insert(ClientIp(ip));
    next.run(req).await
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    fn h(xff: &str) -> HeaderMap {
        let mut m = HeaderMap::new();
        m.insert("x-forwarded-for", HeaderValue::from_str(xff).unwrap());
        m
    }

    #[test]
    fn untrusted_peer_ignores_header() {
        let peer: IpAddr = "203.0.113.9".parse().unwrap();
        assert_eq!(resolve(peer, &h("1.2.3.4"), &[]), peer);
        let proxies = vec!["10.0.0.0/8".parse().unwrap()];
        assert_eq!(resolve(peer, &h("1.2.3.4"), &proxies), peer);
    }

    #[test]
    fn trusted_chain_walks_right_to_left() {
        let proxies: Vec<IpNet> = vec!["10.0.0.0/8".parse().unwrap()];
        let peer: IpAddr = "10.0.0.1".parse().unwrap();
        // Client-supplied spoof on the left is skipped.
        assert_eq!(
            resolve(peer, &h("6.6.6.6, 198.51.100.7, 10.0.0.2"), &proxies),
            "198.51.100.7".parse::<IpAddr>().unwrap()
        );
        assert_eq!(
            resolve(peer, &h("garbage, 10.0.0.3"), &proxies),
            "10.0.0.3".parse::<IpAddr>().unwrap()
        );
        assert_eq!(resolve(peer, &HeaderMap::new(), &proxies), peer);
        assert_eq!(
            resolve(peer, &h("198.51.100.7:4711"), &proxies),
            "198.51.100.7".parse::<IpAddr>().unwrap()
        );
    }
}
