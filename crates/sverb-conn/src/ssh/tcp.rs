//! DNS and direct TCP with Happy Eyeballs (SPEC §6.1.1 step 2, RFC 8305).
//!
//! - [`lookup`]: `tokio::net::lookup_host` on every connection (never cached); IP
//!   literals skip DNS.
//! - [`interleave`]: IPv6 first, then alternate families.
//! - [`happy_eyeballs`]: start the first attempt, start the next one after
//!   [`STAGGER`] if nothing has connected yet (or at once when an attempt fails); the
//!   first success wins and the other attempts are dropped (cancelled). Generic over
//!   the dialer so the timing is unit-tested with a mock.
//! - [`connect_tcp`]: the real dialer, with `TCP_NODELAY`, under the connect timeout.

use std::{
    future::Future,
    io,
    net::{IpAddr, SocketAddr},
    pin::Pin,
    time::Duration,
};

use futures::{StreamExt, stream::FuturesUnordered};
use tokio::net::TcpStream;
use tracing::debug;

/// Delay before starting the next attempt while earlier ones are still pending.
pub const STAGGER: Duration = Duration::from_millis(250);

/// Resolve `host:port`. IP literals (with or without brackets) are returned as is.
///
/// # Errors
/// The resolver's error, or `NotFound` when it returned no addresses.
pub async fn lookup(host: &str, port: u16) -> io::Result<Vec<SocketAddr>> {
    let literal = host.trim_start_matches('[').trim_end_matches(']');
    if let Ok(ip) = literal.parse::<IpAddr>() {
        return Ok(vec![SocketAddr::new(ip, port)]);
    }
    let addrs: Vec<SocketAddr> = tokio::net::lookup_host((host, port)).await?.collect();
    if addrs.is_empty() {
        return Err(io::Error::new(io::ErrorKind::NotFound, "no addresses"));
    }
    Ok(addrs)
}

/// Order addresses for Happy Eyeballs: IPv6 first, then alternating families, each
/// family keeping the resolver's order (RFC 8305 §4).
pub fn interleave(addrs: &[SocketAddr]) -> Vec<SocketAddr> {
    let (v6, v4): (Vec<SocketAddr>, Vec<SocketAddr>) = addrs.iter().partition(|a| a.is_ipv6());
    let mut out = Vec::with_capacity(addrs.len());
    let (mut a, mut b) = (v6.into_iter(), v4.into_iter());
    loop {
        match (a.next(), b.next()) {
            (None, None) => break,
            (x, y) => out.extend(x.into_iter().chain(y)),
        }
    }
    out
}

/// Why no attempt connected.
#[derive(Debug)]
pub struct DialFailure {
    /// Each attempted address with its error, in attempt order.
    pub errors: Vec<(SocketAddr, io::Error)>,
}

impl DialFailure {
    /// The first error (the most preferred address).
    pub fn first(&self) -> Option<&(SocketAddr, io::Error)> {
        self.errors.first()
    }
}

type Attempt<S> = Pin<Box<dyn Future<Output = (SocketAddr, io::Result<S>)> + Send>>;

/// Race connection attempts to `addrs` (already ordered) with a `stagger` between
/// starts. `dial` starts one attempt. Returns the first stream that connects and its
/// address. Dropping the returned future cancels every attempt.
///
/// # Errors
/// Every attempt failed (or `addrs` was empty).
pub async fn happy_eyeballs<S, F, Fut>(
    addrs: &[SocketAddr],
    stagger: Duration,
    dial: F,
) -> Result<(S, SocketAddr), DialFailure>
where
    S: Send + 'static,
    F: Fn(SocketAddr) -> Fut,
    Fut: Future<Output = io::Result<S>> + Send + 'static,
{
    let mut pending = addrs.iter().copied();
    let mut running: FuturesUnordered<Attempt<S>> = FuturesUnordered::new();
    let mut errors = Vec::new();
    let start = |addr: SocketAddr, running: &mut FuturesUnordered<Attempt<S>>| {
        let fut = dial(addr);
        running.push(Box::pin(async move { (addr, fut.await) }));
    };
    match pending.next() {
        Some(addr) => start(addr, &mut running),
        None => return Err(DialFailure { errors }),
    }
    let timer = tokio::time::sleep(stagger);
    tokio::pin!(timer);
    let mut more = addrs.len() > 1;
    loop {
        tokio::select! {
            Some((addr, result)) = running.next() => match result {
                Ok(stream) => return Ok((stream, addr)),
                Err(err) => {
                    debug!(%err, "tcp attempt failed");
                    errors.push((addr, err));
                    // A failure starts the next attempt at once.
                    match pending.next() {
                        Some(next) => {
                            start(next, &mut running);
                            timer.as_mut().reset(tokio::time::Instant::now() + stagger);
                        }
                        None => {
                            more = false;
                            if running.is_empty() {
                                return Err(DialFailure { errors });
                            }
                        }
                    }
                }
            },
            () = &mut timer, if more => {
                match pending.next() {
                    Some(next) => {
                        start(next, &mut running);
                        timer.as_mut().reset(tokio::time::Instant::now() + stagger);
                    }
                    None => more = false,
                }
            }
        }
    }
}

/// How [`connect_tcp`] failed.
#[derive(Debug)]
pub enum TcpError {
    /// Every address was refused or unreachable.
    Failed(DialFailure),
    /// Nothing connected within the timeout.
    TimedOut,
}

/// Happy Eyeballs over real TCP to `addrs` (interleaved here), `TCP_NODELAY` on, the
/// whole race bounded by `timeout`.
///
/// # Errors
/// [`TcpError`].
pub async fn connect_tcp(
    addrs: &[SocketAddr],
    timeout: Duration,
) -> Result<(TcpStream, SocketAddr), TcpError> {
    let ordered = interleave(addrs);
    let race = happy_eyeballs(&ordered, STAGGER, |addr| async move {
        let stream = TcpStream::connect(addr).await?;
        if let Err(err) = stream.set_nodelay(true) {
            debug!(%err, "set_nodelay failed");
        }
        Ok(stream)
    });
    match tokio::time::timeout(timeout, race).await {
        Ok(Ok(won)) => Ok(won),
        Ok(Err(failure)) => Err(TcpError::Failed(failure)),
        Err(_) => Err(TcpError::TimedOut),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use std::{
        collections::HashMap,
        sync::{Arc, Mutex},
    };

    use tokio::time::Instant;

    use super::*;

    fn v4(last: u8) -> SocketAddr {
        SocketAddr::from(([192, 0, 2, last], 22))
    }

    fn v6(last: u16) -> SocketAddr {
        SocketAddr::from(([0x2001, 0xdb8, 0, 0, 0, 0, 0, last], 22))
    }

    /// T-01: [v4a, v4b, v6a, v6b] → v6a, v4a, v6b, v4b.
    #[test]
    fn t01_happy_eyeballs_ordering() {
        let (v4a, v4b, v6a, v6b) = (v4(1), v4(2), v6(1), v6(2));
        assert_eq!(interleave(&[v4a, v4b, v6a, v6b]), [v6a, v4a, v6b, v4b]);
        assert_eq!(interleave(&[v4a, v4b]), [v4a, v4b]);
        assert_eq!(interleave(&[v6a, v6b, v4a]), [v6a, v4a, v6b]);
        assert!(interleave(&[]).is_empty());
    }

    #[derive(Clone, Copy)]
    enum Plan {
        Hang,
        SucceedAfter(Duration),
        FailAfter(Duration),
    }

    /// A mock dialer that records when each attempt started (virtual time).
    #[derive(Clone)]
    struct Mock {
        plans: HashMap<SocketAddr, Plan>,
        started: Arc<Mutex<Vec<(SocketAddr, Duration)>>>,
        t0: Instant,
    }

    impl Mock {
        fn new(plans: &[(SocketAddr, Plan)]) -> Self {
            Self {
                plans: plans.iter().copied().collect(),
                started: Arc::default(),
                t0: Instant::now(),
            }
        }

        fn dial(
            &self,
            addr: SocketAddr,
        ) -> impl Future<Output = io::Result<SocketAddr>> + Send + 'static {
            self.started.lock().unwrap().push((addr, self.t0.elapsed()));
            let plan = self.plans[&addr];
            async move {
                match plan {
                    Plan::Hang => std::future::pending().await,
                    Plan::SucceedAfter(d) => {
                        tokio::time::sleep(d).await;
                        Ok(addr)
                    }
                    Plan::FailAfter(d) => {
                        tokio::time::sleep(d).await;
                        Err(io::Error::from(io::ErrorKind::ConnectionRefused))
                    }
                }
            }
        }

        fn started(&self) -> Vec<(SocketAddr, Duration)> {
            self.started.lock().unwrap().clone()
        }
    }

    /// T-02: v6 hangs, v4 succeeds 10 ms after it starts; v4 starts at 250 ms and wins.
    #[tokio::test(start_paused = true)]
    async fn t02_v4_starts_after_the_stagger_and_wins() {
        let mock = Mock::new(&[
            (v6(1), Plan::Hang),
            (v4(1), Plan::SucceedAfter(Duration::from_millis(10))),
        ]);
        let t0 = Instant::now();
        let (won, addr) = happy_eyeballs(&[v6(1), v4(1)], STAGGER, |a| mock.dial(a))
            .await
            .unwrap();
        assert_eq!((won, addr), (v4(1), v4(1)));
        assert_eq!(t0.elapsed(), Duration::from_millis(260));
        assert_eq!(
            mock.started(),
            [(v6(1), Duration::ZERO), (v4(1), Duration::from_millis(250))]
        );
    }

    /// T-02: when v6 fails immediately, v4 starts immediately.
    #[tokio::test(start_paused = true)]
    async fn t02_failure_starts_the_next_attempt_at_once() {
        let mock = Mock::new(&[
            (v6(1), Plan::FailAfter(Duration::ZERO)),
            (v4(1), Plan::SucceedAfter(Duration::from_millis(10))),
        ]);
        let t0 = Instant::now();
        let (_, addr) = happy_eyeballs(&[v6(1), v4(1)], STAGGER, |a| mock.dial(a))
            .await
            .unwrap();
        assert_eq!(addr, v4(1));
        assert_eq!(t0.elapsed(), Duration::from_millis(10));
        assert_eq!(mock.started()[1], (v4(1), Duration::ZERO));
    }

    /// A slow first attempt that finishes before a later one still wins (first success).
    #[tokio::test(start_paused = true)]
    async fn first_success_wins_and_all_failures_are_reported() {
        let mock = Mock::new(&[
            (v6(1), Plan::SucceedAfter(Duration::from_millis(300))),
            (v4(1), Plan::SucceedAfter(Duration::from_millis(400))),
        ]);
        let (_, addr) = happy_eyeballs(&[v6(1), v4(1)], STAGGER, |a| mock.dial(a))
            .await
            .unwrap();
        assert_eq!(addr, v6(1));

        let mock = Mock::new(&[
            (v6(1), Plan::FailAfter(Duration::from_millis(5))),
            (v4(1), Plan::FailAfter(Duration::from_millis(5))),
        ]);
        let failure = happy_eyeballs(&[v6(1), v4(1)], STAGGER, |a| mock.dial(a))
            .await
            .unwrap_err();
        let order: Vec<_> = failure.errors.iter().map(|(a, _)| *a).collect();
        assert_eq!(order, [v6(1), v4(1)]);
    }

    /// T-03 (TCP part): nothing answers → the race gives up at the connect timeout.
    #[tokio::test(start_paused = true)]
    async fn t03_connect_timeout() {
        let mock = Mock::new(&[(v6(1), Plan::Hang), (v4(1), Plan::Hang)]);
        let t0 = Instant::now();
        let addrs = [v6(1), v4(1)];
        let race = happy_eyeballs(&addrs, STAGGER, |a| mock.dial(a));
        let res = tokio::time::timeout(Duration::from_secs(15), race).await;
        assert!(res.is_err());
        assert_eq!(t0.elapsed(), Duration::from_secs(15));
        assert_eq!(mock.started().len(), 2);
    }

    #[tokio::test]
    async fn ip_literals_skip_dns() {
        assert_eq!(
            lookup("127.0.0.1", 22).await.unwrap(),
            [SocketAddr::from(([127, 0, 0, 1], 22))]
        );
        assert_eq!(lookup("[::1]", 2222).await.unwrap()[0].port(), 2222);
        assert!(lookup("::1", 22).await.unwrap()[0].is_ipv6());
    }

    #[tokio::test]
    async fn real_tcp_connects_with_nodelay() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (stream, got) = connect_tcp(&[addr], Duration::from_secs(5)).await.unwrap();
        assert_eq!(got, addr);
        assert!(stream.nodelay().unwrap());
        drop(listener);
        // A refused port fails (not a timeout).
        let err = connect_tcp(&[addr], Duration::from_secs(5))
            .await
            .unwrap_err();
        assert!(matches!(err, TcpError::Failed(_)), "{err:?}");
    }
}
