//! Server-Sent Events (SSE) framing: encode and streaming decode.
//!
//! This module carries opaque text `data` payloads only; it knows nothing
//! about JSON-RPC.

/// One decoded (or to-be-encoded) SSE event.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SseEvent {
    pub event: Option<String>,
    pub data: String,
    pub id: Option<String>,
}

fn first_line(s: &str) -> &str {
    match s.find(['\n', '\r']) {
        Some(idx) => &s[..idx],
        None => s,
    }
}

/// Encodes a single [`SseEvent`] into its wire representation.
pub fn encode_sse_event(event: &SseEvent) -> String {
    let mut out = String::new();

    if let Some(name) = &event.event {
        out.push_str("event: ");
        out.push_str(first_line(name));
        out.push('\n');
    }

    if let Some(id) = &event.id {
        out.push_str("id: ");
        out.push_str(first_line(id));
        out.push('\n');
    }

    for line in event.data.split('\n') {
        out.push_str("data: ");
        out.push_str(line);
        out.push('\n');
    }

    out.push('\n');
    out
}

#[derive(Default)]
struct PendingEvent {
    event: Option<String>,
    id: Option<String>,
    data_lines: Vec<String>,
}

impl PendingEvent {
    fn apply_line(&mut self, line: &str) {
        if line.starts_with(':') {
            return;
        }

        let (field, raw_value) = match line.split_once(':') {
            Some((field, value)) => (field, value),
            None => (line, ""),
        };
        let value = raw_value.strip_prefix(' ').unwrap_or(raw_value);

        match field {
            "data" => self.data_lines.push(value.to_string()),
            "event" => self.event = Some(value.to_string()),
            "id" => self.id = Some(value.to_string()),
            _ => {}
        }
    }

    fn dispatch(&mut self) -> Option<SseEvent> {
        if self.data_lines.is_empty() {
            self.reset();
            return None;
        }

        let event = SseEvent {
            event: self.event.take(),
            data: self.data_lines.join("\n"),
            id: self.id.take(),
        };
        self.reset();
        Some(event)
    }

    fn reset(&mut self) {
        self.event = None;
        self.id = None;
        self.data_lines.clear();
    }
}

/// Incremental SSE parser. Feed it arbitrary chunks of raw text as they
/// arrive over the wire; it buffers internally and returns every complete
/// event framed since the previous call. Never panics.
#[derive(Default)]
pub struct SseDecoder {
    buffer: String,
    pending: PendingEvent,
}

impl SseDecoder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn feed(&mut self, chunk: &str) -> Vec<SseEvent> {
        self.buffer.push_str(chunk);
        let mut events = Vec::new();

        while let Some(idx) = self.buffer.find('\n') {
            let mut line = self.buffer[..idx].to_string();
            self.buffer.replace_range(..=idx, "");

            if line.ends_with('\r') {
                line.pop();
            }

            if line.is_empty() {
                if let Some(event) = self.pending.dispatch() {
                    events.push(event);
                }
                continue;
            }

            self.pending.apply_line(&line);
        }

        events
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrips_multiline_data() {
        let event = SseEvent {
            event: Some("update".to_string()),
            data: "line1\nline2\nline3".to_string(),
            id: Some("42".to_string()),
        };
        let encoded = encode_sse_event(&event);

        let mut decoder = SseDecoder::new();
        let decoded = decoder.feed(&encoded);

        assert_eq!(decoded.len(), 1);
        assert_eq!(decoded[0], event);
    }

    #[test]
    fn encode_uses_one_data_line_per_segment() {
        let event = SseEvent {
            event: None,
            data: "a\nb".to_string(),
            id: None,
        };
        let encoded = encode_sse_event(&event);
        assert_eq!(encoded, "data: a\ndata: b\n\n");
    }

    #[test]
    fn feed_handles_a_chunk_boundary_mid_line() {
        let full = encode_sse_event(&SseEvent {
            event: Some("msg".to_string()),
            data: "hello world".to_string(),
            id: None,
        });
        let split_at = full.find("hello").unwrap() + 2;
        let (first_half, second_half) = full.split_at(split_at);

        let mut decoder = SseDecoder::new();
        let from_first = decoder.feed(first_half);
        assert!(from_first.is_empty());

        let from_second = decoder.feed(second_half);
        assert_eq!(from_second.len(), 1);
        assert_eq!(from_second[0].data, "hello world");
        assert_eq!(from_second[0].event.as_deref(), Some("msg"));
    }

    #[test]
    fn feed_handles_multiple_events_in_one_call() {
        let mut combined = String::new();
        combined.push_str(&encode_sse_event(&SseEvent {
            event: None,
            data: "first".to_string(),
            id: None,
        }));
        combined.push_str(&encode_sse_event(&SseEvent {
            event: None,
            data: "second".to_string(),
            id: None,
        }));
        combined.push_str(&encode_sse_event(&SseEvent {
            event: None,
            data: "third".to_string(),
            id: None,
        }));

        let mut decoder = SseDecoder::new();
        let events = decoder.feed(&combined);

        assert_eq!(events.len(), 3);
        assert_eq!(events[0].data, "first");
        assert_eq!(events[1].data, "second");
        assert_eq!(events[2].data, "third");
    }

    #[test]
    fn blank_line_with_no_data_does_not_dispatch() {
        let mut decoder = SseDecoder::new();
        let events = decoder.feed("id: 1\nevent: ping\n\n");
        assert!(events.is_empty());
    }

    #[test]
    fn crlf_line_endings_are_supported() {
        let mut decoder = SseDecoder::new();
        let events = decoder.feed("data: hello\r\n\r\n");
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].data, "hello");
    }

    #[test]
    fn comment_lines_are_ignored() {
        let mut decoder = SseDecoder::new();
        let events = decoder.feed(": this is a comment\ndata: hello\n\n");
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].data, "hello");
    }

    #[test]
    fn empty_feed_does_not_panic() {
        let mut decoder = SseDecoder::new();
        let events = decoder.feed("");
        assert!(events.is_empty());
    }

    #[test]
    fn garbage_without_blank_line_never_emits() {
        let mut decoder = SseDecoder::new();
        let events = decoder.feed("not really sse data at all, no newline terminator");
        assert!(events.is_empty());
    }
}
