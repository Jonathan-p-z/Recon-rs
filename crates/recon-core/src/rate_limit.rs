//! Shared rate limiting + concurrency limiting primitives.
//!
//! Every module that talks to a target over the network (DNS resolution, HTTP probing,
//! ...) MUST gate its requests through one of the two types here —
//! [`RateLimitedGate`] (one shared, aggregate limit) or [`PerHostRateLimitedGate`] (one
//! limit per destination host) — rather than growing its own `governor`/`Semaphore`
//! plumbing: a second, slightly different implementation is exactly how a rate limit
//! silently stops being enforced somewhere.

use std::num::NonZeroU32;
use std::sync::Arc;

use governor::{Quota, RateLimiter};
use tokio::sync::{AcquireError, Semaphore, SemaphorePermit};

/// A non-keyed, in-memory, default-clock rate limiter shared across every request.
type DirectRateLimiter = governor::DefaultDirectRateLimiter;

/// Combines a shared per-second rate limit with a maximum-concurrency cap.
///
/// [`RateLimitedGate::acquire`] first waits its turn on a shared
/// [`governor::RateLimiter`] (so the aggregate request rate towards the target is
/// bounded no matter how many callers are concurrently waiting), then acquires a
/// `tokio::sync::Semaphore` permit (bounding how many requests may be in flight at
/// once). Holding on to the returned permit keeps the concurrency slot reserved for the
/// duration of the request.
pub(crate) struct RateLimitedGate {
    rate_limiter: Arc<DirectRateLimiter>,
    semaphore: Arc<Semaphore>,
    max_concurrent: usize,
}

impl RateLimitedGate {
    /// Builds a gate allowing at most `requests_per_second` requests per second and at
    /// most `max_concurrent` requests in flight at once. Both are floored at 1 so a
    /// misconfigured `0` cannot silently disable throttling.
    pub(crate) fn new(requests_per_second: u32, max_concurrent: usize) -> Self {
        let rate = NonZeroU32::new(requests_per_second).unwrap_or(NonZeroU32::MIN);
        let quota = Quota::per_second(rate);
        let max_concurrent = max_concurrent.max(1);

        Self {
            rate_limiter: Arc::new(RateLimiter::direct(quota)),
            semaphore: Arc::new(Semaphore::new(max_concurrent)),
            max_concurrent,
        }
    }

    /// The configured concurrency cap, e.g. for sizing a `buffer_unordered` batch.
    pub(crate) fn max_concurrent(&self) -> usize {
        self.max_concurrent
    }

    /// Waits for the shared rate limiter, then for a free concurrency slot. Every
    /// individual request MUST call this before being issued, with no exceptions.
    pub(crate) async fn acquire(&self) -> Result<SemaphorePermit<'_>, AcquireError> {
        self.rate_limiter.until_ready().await;
        self.semaphore.acquire().await
    }
}

/// A keyed (one rate-limiting state per string key), in-memory, default-clock rate
/// limiter — `governor`'s `dashmap`-backed keyed limiter under the hood.
type KeyedRateLimiter = governor::DefaultKeyedRateLimiter<String>;

/// Combines a **per-key** rate limit with a single, global concurrency cap.
///
/// Unlike [`RateLimitedGate`] (one shared rate limiter for every request, regardless of
/// destination), [`PerHostRateLimitedGate::acquire`] enforces `requests_per_second`
/// independently for each distinct key (in practice, a target host): exceeding the
/// quota against one host never throttles requests to a different host. This exists
/// specifically for bug bounty programs whose published rules cap the rate *per host*
/// rather than in aggregate across an entire scan — see
/// [`crate::prober::ProberConfig::requests_per_second`] for why this matters and why a
/// single aggregate-only limiter is not just "extra cautious" but can leave individual
/// hosts *under*-throttled relative to what the program actually intends to bound.
///
/// The concurrency cap, by contrast, stays global rather than per-key: it exists to
/// protect this machine's own outbound resources (open sockets, file descriptors), not
/// to satisfy any per-target policy, so there is no reason to let it scale with the
/// number of distinct hosts probed in a scan.
///
/// Rate-limiting state for a key is created lazily on first use and is never evicted —
/// acceptable for `recon-cli`'s one-shot, single-scan process lifetime, but worth
/// knowing if this type is ever reused inside a long-running daemon, where the
/// per-host map would grow unbounded over the process's lifetime.
pub(crate) struct PerHostRateLimitedGate {
    rate_limiter: Arc<KeyedRateLimiter>,
    semaphore: Arc<Semaphore>,
    max_concurrent: usize,
}

impl PerHostRateLimitedGate {
    /// Builds a gate allowing at most `requests_per_second` requests per second *to each
    /// distinct key*, and at most `max_concurrent` requests in flight at once in total.
    /// Both are floored at 1 so a misconfigured `0` cannot silently disable throttling.
    pub(crate) fn new(requests_per_second: u32, max_concurrent: usize) -> Self {
        let rate = NonZeroU32::new(requests_per_second).unwrap_or(NonZeroU32::MIN);
        let quota = Quota::per_second(rate);
        let max_concurrent = max_concurrent.max(1);

        Self {
            rate_limiter: Arc::new(RateLimiter::keyed(quota)),
            semaphore: Arc::new(Semaphore::new(max_concurrent)),
            max_concurrent,
        }
    }

    /// The configured concurrency cap, e.g. for sizing a `buffer_unordered` batch.
    pub(crate) fn max_concurrent(&self) -> usize {
        self.max_concurrent
    }

    /// Waits for `key`'s own rate-limit slot, then for a free (global) concurrency
    /// slot. Every individual request MUST call this before being issued, with no
    /// exceptions.
    pub(crate) async fn acquire(&self, key: &str) -> Result<SemaphorePermit<'_>, AcquireError> {
        self.rate_limiter.until_key_ready(&key.to_string()).await;
        self.semaphore.acquire().await
    }
}
