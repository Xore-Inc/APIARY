//! Ported from ip-enrichment-worker/pending.go: lines whose src_ip is the
//! tunnel peer but whose matching portbridge via_port entry hasn't landed
//! yet get held briefly and retried — portbridge logs a connection's
//! via_port at dial time, before the honeypot itself ever sees the
//! resulting connection, so a miss is almost always a brief race, not a
//! permanent condition.

use std::time::{Duration, Instant};

use super::viamap::ViaMap;

/// Shared signature every enrich function has, so `PendingQueue::drain` can
/// retry any of them through one code path without knowing which kind of
/// source it's got.
pub type EnrichFn = fn(&[u8], &ViaMap, &ViaMap, &str) -> (Vec<u8>, bool);

struct PendingLine {
    line: Vec<u8>,
    deadline: Instant,
}

#[derive(Default)]
pub struct PendingQueue {
    items: Vec<PendingLine>,
}

impl PendingQueue {
    pub fn add(&mut self, line: Vec<u8>, timeout: Duration, now: Instant) {
        self.items.push(PendingLine { line, deadline: now + timeout });
    }

    /// Retries every pending line against `vm`/`tftp_vm` via `enrich`,
    /// returning (in original order) every line that either resolved or
    /// timed out — ready to write now, enriched or not. Lines still within
    /// their window and still unresolved stay queued for the next call.
    /// A line whose enricher panics is dropped (loudly, #2181) rather than
    /// left re-panicking every drain until its deadline: offsets already
    /// sit past these bytes, so a kept-poisoned retry would only ever
    /// repeat — and the raw record is still upstream if anyone needs it.
    pub fn drain(&mut self, vm: &ViaMap, tftp_vm: &ViaMap, now: Instant, persona: &str, enrich: EnrichFn) -> Vec<Vec<u8>> {
        let mut ready = Vec::new();
        let mut remaining = Vec::with_capacity(self.items.len());
        for item in self.items.drain(..) {
            let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                enrich(&item.line, vm, tftp_vm, persona)
            }));
            let (out, resolved) = match outcome {
                Ok(pair) => pair,
                Err(payload) => {
                    tracing::warn!(
                        persona,
                        preview = %String::from_utf8_lossy(&item.line[..item.line.len().min(120)]),
                        detail = %crate::isolate::panic_detail(payload),
                        "ip-enrichment: queued line panicked its enricher; dropped from the retry queue (#2181)"
                    );
                    continue;
                }
            };
            if resolved || now >= item.deadline {
                ready.push(out);
            } else {
                remaining.push(item);
            }
        }
        self.items = remaining;
        ready
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::sensors::enrich_line;

    fn never_resolves(line: &[u8], _vm: &ViaMap, _tftp_vm: &ViaMap, _persona: &str) -> (Vec<u8>, bool) {
        (line.to_vec(), false)
    }

    #[test]
    fn unresolved_line_stays_queued_until_its_deadline() {
        let mut q = PendingQueue::default();
        let vm = ViaMap::new();
        let now = Instant::now();
        q.add(b"line".to_vec(), Duration::from_secs(5), now);
        let ready = q.drain(&vm, &vm, now, "cowrie", never_resolves);
        assert!(ready.is_empty(), "still within its timeout window, must stay queued");
        let later = now + Duration::from_secs(6);
        let ready2 = q.drain(&vm, &vm, later, "cowrie", never_resolves);
        assert_eq!(ready2.len(), 1, "past its deadline, must be flushed even though unresolved");
    }

    // #2181: offsets already sit past everything sitting in this queue, so
    // a retry whose enricher panics can only ever repeat its panic — it is
    // dropped loudly instead of poisoning every later drain call forever.

    /// Resolves nothing; panics on any line carrying POISON.
    fn poison_on_marker(line: &[u8], _vm: &ViaMap, _tftp_vm: &ViaMap, _persona: &str) -> (Vec<u8>, bool) {
        if line.windows(6).any(|w| w == b"POISON") {
            panic!("synthetic poisoned capture");
        }
        (line.to_vec(), false)
    }

    #[test]
    fn a_panicking_retry_is_dropped_rather_than_requeued_forever() {
        let mut q = PendingQueue::default();
        let vm = ViaMap::new();
        let now = Instant::now();
        q.add(b"{\"bad\":\"POISON\"}".to_vec(), Duration::from_secs(5), now);
        q.add(b"{\"ok\":1}".to_vec(), Duration::from_secs(5), now);

        // Both lines are still inside their retry window and unresolved by
        // ordinary rules -- but the POISON line panics its enricher instead
        // of merely resolving false, so it leaves the queue entirely rather
        // than re-panicking every drain until its deadline.
        let ready = q.drain(&vm, &vm, now, "cowrie", poison_on_marker);
        assert!(ready.is_empty(), "nothing resolved yet");
        assert_eq!(
            q.items.len(),
            1,
            "the poisoned retry left the queue; its healthy sibling is still waiting"
        );
        assert_eq!(q.items[0].line, b"{\"ok\":1}");

        // The healthy sibling still reaches its normal timeout flush, so
        // dropping poison changed nothing about anyone else's semantics.
        let later = now + Duration::from_secs(6);
        let flushed = q.drain(&vm, &vm, later, "cowrie", poison_on_marker);
        assert_eq!(flushed, vec![b"{\"ok\":1}".to_vec()]);
        assert!(q.items.is_empty());
    }

    // Ported from the Go worker's pending_test.go before that tree was
    // retired (#1890). The queue's whole reason to exist is that a sensor
    // line often arrives before portbridge's record of the connection it
    // describes, so the case where the map catches up is the one that has
    // to work -- the timeout case below is the fallback.
    #[test]
    fn a_queued_line_resolves_once_the_map_catches_up() {
        let mut q = PendingQueue::default();
        let now = Instant::now();
        q.add(
            br#"{"src_ip":"10.8.0.1","src_port":1}"#.to_vec(),
            Duration::from_secs(5),
            now,
        );

        // Nothing yet: portbridge has not logged the dial.
        let ready = q.drain(
            &ViaMap::new(),
            &ViaMap::new(),
            now + Duration::from_secs(1),
            "",
            enrich_line,
        );
        assert!(ready.is_empty(), "not ready before resolution or timeout");

        let mut vm = ViaMap::new();
        vm.insert(1, vec![super::super::viamap::ViaEntry { ip: "203.0.113.9".into(), ..Default::default() }]);
        let ready = q.drain(&vm, &ViaMap::new(), now + Duration::from_secs(2), "", enrich_line);

        assert_eq!(ready.len(), 1, "the line resolves and flushes");
        let out: serde_json::Value = serde_json::from_slice(&ready[0]).unwrap();
        assert_eq!(out["src_ip"], serde_json::json!("203.0.113.9"));
    }

    #[test]
    fn a_flushed_line_is_never_retried() {
        // Once a line has left the queue it must not come back when the
        // map later gains the entry, or it is emitted twice.
        let mut q = PendingQueue::default();
        let now = Instant::now();
        q.add(
            br#"{"src_ip":"10.8.0.1","src_port":1}"#.to_vec(),
            Duration::from_secs(5),
            now,
        );

        let ready = q.drain(&ViaMap::new(), &ViaMap::new(), now + Duration::from_secs(6), "", enrich_line);
        assert_eq!(ready.len(), 1, "flushes unenriched at its deadline");

        let mut vm = ViaMap::new();
        vm.insert(1, vec![super::super::viamap::ViaEntry { ip: "203.0.113.9".into(), ..Default::default() }]);
        let again = q.drain(&vm, &ViaMap::new(), now + Duration::from_secs(7), "", enrich_line);
        assert!(again.is_empty(), "an already-flushed line must not reappear");
    }
}
