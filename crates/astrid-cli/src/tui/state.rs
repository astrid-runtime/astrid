//! TUI state machine — stripped to Nexus view only.

use std::collections::HashSet;
use std::time::{Duration, Instant};

use astrid_types::Topic;

// ─── Input Buffer ───────────────────────────────────────────────

/// A segment of user input - either typed text or an atomic paste block.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum InputSegment {
    /// Normal typed text (character-by-character editing).
    Text(String),
    /// An atomic paste block - deleted as a whole unit on Backspace.
    PasteBlock {
        /// The raw pasted content, preserving all newlines.
        raw: String,
        /// Number of lines in the raw content (cached for rendering).
        line_count: usize,
    },
}

/// Structured input buffer holding a sequence of text and paste-block segments.
///
/// The cursor is represented as `(segment_index, byte_offset)`. For `PasteBlock`
/// segments, the byte offset is always 0 (the cursor sits at the boundary, never
/// inside the block).
#[derive(Debug, Clone, Default)]
pub(crate) struct InputBuffer {
    pub segments: Vec<InputSegment>,
    /// `(segment_index, byte_offset_within_segment)`.
    pub cursor: (usize, usize),
}

impl InputBuffer {
    /// Whether the buffer contains no text or paste blocks.
    pub(crate) fn is_empty(&self) -> bool {
        self.segments.is_empty()
            || self.segments.iter().all(|s| match s {
                InputSegment::Text(t) => t.is_empty(),
                InputSegment::PasteBlock { .. } => false,
            })
    }

    /// Clear all segments and reset the cursor.
    pub(crate) fn clear(&mut self) {
        self.segments.clear();
        self.cursor = (0, 0);
    }

    /// Concatenate all segments into a single string for submission.
    /// `PasteBlock` raw content is injected inline with newlines preserved.
    pub(crate) fn flat_text(&self) -> String {
        let mut out = String::new();
        for seg in &self.segments {
            match seg {
                InputSegment::Text(t) => out.push_str(t),
                InputSegment::PasteBlock { raw, .. } => out.push_str(raw),
            }
        }
        out
    }

    /// Whether the first segment is a `Text` starting with `/`.
    pub(crate) fn starts_with_slash(&self) -> bool {
        matches!(self.segments.first(), Some(InputSegment::Text(t)) if t.starts_with('/'))
    }

    /// Return the text content for palette filtering (the full flat text of the
    /// first Text segment, or empty if the buffer starts with a `PasteBlock`).
    pub(crate) fn text_for_palette(&self) -> &str {
        match self.segments.first() {
            Some(InputSegment::Text(t)) => t.as_str(),
            _ => "",
        }
    }

    /// Whether the buffer contains any paste blocks.
    pub(crate) fn has_paste_blocks(&self) -> bool {
        self.segments
            .iter()
            .any(|s| matches!(s, InputSegment::PasteBlock { .. }))
    }

    /// Total line count across all paste blocks (for height calculation).
    pub(crate) fn paste_block_total_lines(&self) -> usize {
        self.segments
            .iter()
            .map(|s| match s {
                InputSegment::PasteBlock { line_count, .. } => *line_count,
                InputSegment::Text(_) => 0,
            })
            .sum()
    }

    /// Replace the entire buffer with a single `Text` segment.
    pub(crate) fn set_text(&mut self, s: String) {
        let len = s.len();
        self.segments.clear();
        if !s.is_empty() {
            self.segments.push(InputSegment::Text(s));
        }
        self.cursor = (0, len);
        self.normalize();
    }

    /// Consume the buffer and return the flat text if non-empty.
    pub(crate) fn take_flat(&mut self) -> Option<String> {
        let text = self.flat_text();
        self.clear();
        if text.trim().is_empty() {
            None
        } else {
            Some(text)
        }
    }

    /// Insert a character at the current cursor position.
    pub(crate) fn insert_char(&mut self, c: char) {
        self.ensure_text_at_cursor();
        if let Some(InputSegment::Text(t)) = self.segments.get_mut(self.cursor.0) {
            t.insert(self.cursor.1, c);
            self.cursor.1 = self.cursor.1.saturating_add(c.len_utf8());
        }
        self.normalize();
    }

    /// Insert a string at the current cursor position in O(N) time.
    /// Preferred over repeated `insert_char` calls for bulk insertion.
    pub(crate) fn insert_str(&mut self, s: &str) {
        self.ensure_text_at_cursor();
        if let Some(InputSegment::Text(t)) = self.segments.get_mut(self.cursor.0) {
            t.insert_str(self.cursor.1, s);
            self.cursor.1 = self.cursor.1.saturating_add(s.len());
        }
        self.normalize();
    }

    /// Delete the character before the cursor, or delete an entire paste block
    /// if the cursor is at the boundary after one.
    pub(crate) fn backspace(&mut self) {
        if self.segments.is_empty() {
            return;
        }

        let (seg_idx, byte_off) = self.cursor;

        // If cursor is inside a Text segment with offset > 0, delete the char before cursor.
        if let Some(InputSegment::Text(t)) = self.segments.get(seg_idx)
            && byte_off > 0
        {
            let prev = t[..byte_off]
                .char_indices()
                .next_back()
                .map_or(0, |(i, _)| i);
            if let Some(InputSegment::Text(t)) = self.segments.get_mut(seg_idx) {
                t.remove(prev);
            }
            self.cursor.1 = prev;
            self.normalize();
            return;
        }

        // Cursor is at offset 0 of a segment - look at the previous segment.
        if seg_idx == 0 {
            // At very start of buffer - nothing to delete.
            // Unless the current segment is a PasteBlock and cursor is at its start.
            if matches!(self.segments.first(), Some(InputSegment::PasteBlock { .. })) {
                self.segments.remove(0);
                self.cursor = (0, 0);
                self.normalize();
            }
            return;
        }

        // If cursor is ON a non-leading PasteBlock, delete it directly.
        if matches!(
            self.segments.get(seg_idx),
            Some(InputSegment::PasteBlock { .. })
        ) {
            self.segments.remove(seg_idx);
            self.cursor.0 = seg_idx.saturating_sub(1);
            self.normalize();
            return;
        }

        // Delete the previous segment if it's a PasteBlock, or the last char of the
        // previous Text segment.
        let prev_idx = seg_idx.saturating_sub(1);
        match &self.segments[prev_idx] {
            InputSegment::PasteBlock { .. } => {
                self.segments.remove(prev_idx);
                // Cursor segment index shifts down by 1, byte offset stays.
                self.cursor.0 = prev_idx;
                self.normalize();
            },
            InputSegment::Text(t) => {
                if let Some((prev_char_idx, _)) = t.char_indices().next_back() {
                    if let Some(InputSegment::Text(t)) = self.segments.get_mut(prev_idx) {
                        t.remove(prev_char_idx);
                    }
                    self.cursor = (prev_idx, prev_char_idx);
                    self.normalize();
                }
            },
        }
    }

    /// Delete the character or paste block after the cursor.
    pub(crate) fn delete_forward(&mut self) {
        if self.segments.is_empty() {
            return;
        }

        let (seg_idx, byte_off) = self.cursor;

        if let Some(seg) = self.segments.get(seg_idx) {
            match seg {
                InputSegment::Text(t) => {
                    if byte_off < t.len() {
                        // Delete char at cursor position.
                        if let Some(InputSegment::Text(t)) = self.segments.get_mut(seg_idx) {
                            t.remove(byte_off);
                        }
                        self.normalize();
                        return;
                    }
                    // At end of Text segment - look at next segment.
                    let next_idx = seg_idx.saturating_add(1);
                    if next_idx < self.segments.len()
                        && matches!(self.segments[next_idx], InputSegment::PasteBlock { .. })
                    {
                        self.segments.remove(next_idx);
                        self.normalize();
                    } else if let Some(InputSegment::Text(next_t)) = self.segments.get(next_idx)
                        && !next_t.is_empty()
                    {
                        let first_char_len = next_t.chars().next().map_or(0, char::len_utf8);
                        if let Some(InputSegment::Text(next_t)) = self.segments.get_mut(next_idx) {
                            next_t.drain(..first_char_len);
                        }
                        self.normalize();
                    }
                },
                InputSegment::PasteBlock { .. } => {
                    // Cursor at a PasteBlock: delete it.
                    self.segments.remove(seg_idx);
                    self.normalize();
                },
            }
        }
    }

    /// Move cursor one character left, or skip over a paste block.
    pub(crate) fn move_left(&mut self) {
        if self.segments.is_empty() {
            return;
        }

        let (seg_idx, byte_off) = self.cursor;

        // If inside a Text segment with offset > 0, move back one char.
        if let Some(InputSegment::Text(t)) = self.segments.get(seg_idx)
            && byte_off > 0
        {
            let prev = t[..byte_off]
                .char_indices()
                .next_back()
                .map_or(0, |(i, _)| i);
            self.cursor.1 = prev;
            return;
        }

        // At offset 0 of current segment - move to previous segment.
        if seg_idx == 0 {
            return; // Already at start.
        }

        let prev_idx = seg_idx.saturating_sub(1);
        match &self.segments[prev_idx] {
            InputSegment::PasteBlock { .. } => {
                // Skip over the paste block entirely.
                if prev_idx == 0 {
                    // Insert a leading Text segment so cursor has a typeable home.
                    self.segments.insert(0, InputSegment::Text(String::new()));
                    // All indices shifted by 1.
                    self.cursor = (0, 0);
                } else {
                    let prev_prev = prev_idx.saturating_sub(1);
                    match &self.segments[prev_prev] {
                        InputSegment::Text(t) => self.cursor = (prev_prev, t.len()),
                        InputSegment::PasteBlock { .. } => {
                            // Two consecutive PasteBlocks: insert a Text between them.
                            self.segments
                                .insert(prev_idx, InputSegment::Text(String::new()));
                            self.cursor = (prev_idx, 0);
                        },
                    }
                }
            },
            InputSegment::Text(t) => {
                self.cursor = (prev_idx, t.len());
            },
        }
    }

    /// Move cursor one character right, or skip over a paste block.
    pub(crate) fn move_right(&mut self) {
        if self.segments.is_empty() {
            return;
        }

        let (seg_idx, byte_off) = self.cursor;

        if let Some(seg) = self.segments.get(seg_idx) {
            match seg {
                InputSegment::Text(t) => {
                    if byte_off < t.len() {
                        let (_, c) = t[byte_off..]
                            .char_indices()
                            .next()
                            .expect("byte_off < len guarantees a char");
                        self.cursor.1 = byte_off.saturating_add(c.len_utf8());
                        return;
                    }
                    // At end of Text - move to next segment.
                },
                InputSegment::PasteBlock { .. } => {
                    // Skip over paste block.
                },
            }

            // Move to next segment, skipping over all consecutive PasteBlocks.
            let mut target = seg_idx.saturating_add(1);
            while target < self.segments.len()
                && matches!(self.segments[target], InputSegment::PasteBlock { .. })
            {
                target = target.saturating_add(1);
            }
            if target < self.segments.len() {
                self.cursor = (target, 0);
            }
            // else: already at the end of the last segment - no-op.
        }
    }

    /// Move cursor to the start of the buffer.
    ///
    /// If the first segment is a `PasteBlock`, skips to the first Text
    /// segment so the cursor remains visible and typeable.
    pub(crate) fn move_home(&mut self) {
        // If the buffer starts with a PasteBlock, insert an empty Text at the
        // front so Home always lands at the true beginning of the buffer.
        if matches!(self.segments.first(), Some(InputSegment::PasteBlock { .. })) {
            self.segments.insert(0, InputSegment::Text(String::new()));
        }
        self.cursor = (0, 0);
    }

    /// Move cursor to the end of the buffer.
    pub(crate) fn move_end(&mut self) {
        if self.segments.is_empty() {
            self.cursor = (0, 0);
            return;
        }
        let last_idx = self.segments.len().saturating_sub(1);
        let byte_off = match &self.segments[last_idx] {
            InputSegment::Text(t) => t.len(),
            InputSegment::PasteBlock { .. } => 0,
        };
        self.cursor = (last_idx, byte_off);
    }

    /// Insert a paste block at the current cursor position. If the cursor is
    /// inside a Text segment, splits it around the cursor.
    pub(crate) fn insert_paste(&mut self, content: String) {
        // Note: `str::lines()` does not yield a trailing empty line for content
        // ending in `\n`. The render path also uses `raw.lines()`, so both are
        // consistent.
        let line_count = content.lines().count().max(1);
        let block = InputSegment::PasteBlock {
            raw: content,
            line_count,
        };

        if self.segments.is_empty() {
            self.segments.push(block);
            self.cursor = (0, 0);
            // Add an empty Text segment after the block for further typing.
            self.segments.push(InputSegment::Text(String::new()));
            self.cursor = (1, 0);
            self.normalize();
            return;
        }

        let (seg_idx, byte_off) = self.cursor;

        if seg_idx >= self.segments.len() {
            // Past the end - append.
            self.segments.push(block);
            let new_idx = self.segments.len().saturating_sub(1);
            self.segments.push(InputSegment::Text(String::new()));
            self.cursor = (new_idx.saturating_add(1), 0);
            self.normalize();
            return;
        }

        match &self.segments[seg_idx] {
            InputSegment::Text(t) => {
                if byte_off == 0 && t.is_empty() {
                    // Replace the empty Text segment with the block, add trailing Text.
                    self.segments[seg_idx] = block;
                    self.segments
                        .insert(seg_idx.saturating_add(1), InputSegment::Text(String::new()));
                    self.cursor = (seg_idx.saturating_add(1), 0);
                } else if byte_off == 0 {
                    // Insert block before this Text segment.
                    self.segments.insert(seg_idx, block);
                    self.cursor = (seg_idx.saturating_add(1), 0);
                } else if byte_off >= t.len() {
                    // Insert block after this Text segment.
                    let insert_pos = seg_idx.saturating_add(1);
                    self.segments.insert(insert_pos, block);
                    let trailing_pos = insert_pos.saturating_add(1);
                    self.segments
                        .insert(trailing_pos, InputSegment::Text(String::new()));
                    self.cursor = (trailing_pos, 0);
                } else {
                    // Split the Text segment around the cursor.
                    let after = t[byte_off..].to_string();
                    if let Some(InputSegment::Text(t)) = self.segments.get_mut(seg_idx) {
                        t.truncate(byte_off);
                    }
                    let insert_pos = seg_idx.saturating_add(1);
                    self.segments.insert(insert_pos, block);
                    let trailing_pos = insert_pos.saturating_add(1);
                    self.segments
                        .insert(trailing_pos, InputSegment::Text(after));
                    self.cursor = (trailing_pos, 0);
                }
            },
            InputSegment::PasteBlock { .. } => {
                // Insert before the current PasteBlock and add trailing Text
                // so the cursor always has a typeable segment to land on.
                self.segments.insert(seg_idx, block);
                let after_idx = seg_idx.saturating_add(1);
                // Ensure there's a Text segment after the original PasteBlock.
                let orig_paste_idx = after_idx;
                let needs_trailing = !matches!(
                    self.segments.get(orig_paste_idx.saturating_add(1)),
                    Some(InputSegment::Text(_))
                );
                if needs_trailing {
                    self.segments.insert(
                        orig_paste_idx.saturating_add(1),
                        InputSegment::Text(String::new()),
                    );
                }
                self.cursor = (orig_paste_idx.saturating_add(1), 0);
            },
        }

        self.normalize();
    }

    /// Ensure there's a Text segment at the cursor position so char insertion
    /// has somewhere to go.
    fn ensure_text_at_cursor(&mut self) {
        if self.segments.is_empty() {
            self.segments.push(InputSegment::Text(String::new()));
            self.cursor = (0, 0);
            return;
        }

        if self.cursor.0 >= self.segments.len() {
            self.segments.push(InputSegment::Text(String::new()));
            self.cursor = (self.segments.len().saturating_sub(1), 0);
            return;
        }

        if matches!(
            self.segments[self.cursor.0],
            InputSegment::PasteBlock { .. }
        ) {
            // Insert a Text segment after the PasteBlock so the user types after it.
            let insert_idx = self.cursor.0.saturating_add(1);
            self.segments
                .insert(insert_idx, InputSegment::Text(String::new()));
            self.cursor = (insert_idx, 0);
        }
    }

    /// Merge adjacent `Text` segments, remove empties, and clamp cursor.
    fn normalize(&mut self) {
        // First pass: merge adjacent Text segments.
        let mut i: usize = 0;
        while i.saturating_add(1) < self.segments.len() {
            let next: usize = i.saturating_add(1);
            if let (InputSegment::Text(_), InputSegment::Text(_)) =
                (&self.segments[i], &self.segments[next])
            {
                // Remove `next` first to get an owned String, avoiding a clone.
                let current_len = if let InputSegment::Text(t) = &self.segments[i] {
                    t.len()
                } else {
                    unreachable!()
                };

                let removed = self.segments.remove(next);
                let InputSegment::Text(merged_text) = removed else {
                    unreachable!()
                };

                if let InputSegment::Text(t) = &mut self.segments[i] {
                    t.push_str(&merged_text);
                }

                // Adjust cursor if it was in the removed segment.
                if self.cursor.0 == next {
                    self.cursor = (i, current_len.saturating_add(self.cursor.1));
                } else if self.cursor.0 > next {
                    self.cursor.0 = self.cursor.0.saturating_sub(1);
                }
                // Don't increment i - check the new next segment.
            } else {
                i = i.saturating_add(1);
            }
        }

        // Clamp cursor to valid range.
        if self.segments.is_empty() {
            self.cursor = (0, 0);
        } else {
            if self.cursor.0 >= self.segments.len() {
                self.cursor.0 = self.segments.len().saturating_sub(1);
            }
            match &self.segments[self.cursor.0] {
                InputSegment::Text(t) => {
                    if self.cursor.1 > t.len() {
                        self.cursor.1 = t.len();
                    }
                },
                InputSegment::PasteBlock { .. } => {
                    self.cursor.1 = 0;
                },
            }
        }
    }
}

// ─── Slash Command Palette ──────────────────────────────────────

#[derive(Debug, Clone)]
pub(crate) struct SlashCommandDef {
    pub name: String,
    pub description: String,
}

pub(crate) const PALETTE_MAX_VISIBLE: usize = 6;

// ─── UI State Machine ────────────────────────────────────────────

/// UI state machine states.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum UiState {
    /// Waiting for user input.
    Idle,
    /// Agent is thinking/processing.
    Thinking { start_time: Instant, dots: usize },
    /// Awaiting approval for tool use.
    AwaitingApproval,
    /// Tool is currently running.
    ToolRunning {
        tool_name: String,
        start_time: Instant,
    },
    /// Streaming response from agent.
    Streaming { start_time: Instant },
    /// Error state.
    Error { message: String },
    /// Interrupted by user.
    Interrupted,
    /// Copy mode — keyboard-driven block selection for clean text copying.
    CopyMode,
    /// Generic selection picker driven by a capsule.
    Selection {
        title: String,
        options: Vec<astrid_types::ipc::SelectionOption>,
        selected: usize,
        scroll_offset: usize,
        callback_topic: String,
        request_id: String,
    },
    /// Capsule Onboarding (configuring environment variables).
    Onboarding {
        capsule_id: String,
        fields: Vec<astrid_types::ipc::OnboardingField>,
        current_idx: usize,
        answers: std::collections::HashMap<String, String>,
        /// Selected index within an enum picker (only used for Enum fields).
        enum_selected: usize,
        /// Scroll offset within an enum picker.
        enum_scroll_offset: usize,
        /// Items accumulated so far for the current array field.
        current_array_items: Vec<String>,
    },
}

// ─── Messages ────────────────────────────────────────────────────

/// Message sender role.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum MessageRole {
    User,
    Assistant,
    LocalUi,
}

/// Special message kinds for styled rendering.
#[derive(Debug, Clone, PartialEq)]
#[expect(dead_code)]
pub(crate) enum MessageKind {
    DiffHeader,
    DiffRemoved,
    DiffAdded,
    DiffFooter,
    /// Inline tool result (index into `completed_tools`).
    ToolResult(usize),
}

/// A conversation message.
#[derive(Debug, Clone)]
pub(crate) struct Message {
    pub role: MessageRole,
    pub content: String,
    #[expect(dead_code)]
    pub timestamp: Instant,
    pub kind: Option<MessageKind>,
    /// Whether to add a blank line after this message.
    pub spacing: bool,
}

/// A single entry in the Nexus unified timeline.
#[derive(Debug, Clone)]
pub(crate) enum NexusEntry {
    Message(Message),
}

// ─── Tool Status ─────────────────────────────────────────────────

/// Status of a tool execution.
#[derive(Debug, Clone)]
pub(crate) struct ToolStatus {
    /// The tool call ID from the LLM, used to match results to running tools.
    pub id: String,
    pub name: String,
    /// Primary argument for display, e.g. `"src/auth.rs"` for `read_file`.
    pub display_arg: String,
    pub status: ToolStatusKind,
    pub start_time: Instant,
    pub end_time: Option<Instant>,
    pub output: Option<String>,
    pub expanded: bool,
}

#[derive(Debug, Clone, PartialEq)]
#[expect(dead_code)]
pub(crate) enum ToolStatusKind {
    Pending,
    Running,
    Success,
    Failed(String),
    Denied,
}

// ─── Approval ────────────────────────────────────────────────────

/// A pending approval request (TUI-local representation).
#[derive(Debug, Clone)]
pub(crate) struct ApprovalRequest {
    pub id: String,
    pub tool_name: String,
    pub description: String,
    pub details: Vec<(String, String)>,
}

// ─── Pending Actions ─────────────────────────────────────────────

/// Deferred action to send to the daemon.
#[derive(Debug, Clone)]
pub(crate) enum PendingAction {
    Approve {
        request_id: String,
        decision: ApprovalDecisionKind,
    },
    Deny {
        request_id: String,
        reason: Option<String>,
    },
    SendInput(String),
    CancelTurn,
    SubmitOnboarding {
        capsule_id: String,
        answers: std::collections::HashMap<String, String>,
    },
    /// Re-fetch the dynamic slash command palette from the kernel.
    RefreshCommands,
    /// Send the user's selection back to a capsule.
    SubmitSelection {
        callback_topic: String,
        request_id: String,
        selected_id: String,
        selected_label: String,
    },
    /// Respond to a lifecycle `elicit` request.
    SubmitElicitResponse {
        request_id: uuid::Uuid,
        value: Option<String>,
        values: Option<Vec<String>>,
    },
    /// Hydrate the TUI with session history from the session store.
    HydrateSession,
}

/// What the user chose for approval.
#[derive(Debug, Clone)]
pub(crate) enum ApprovalDecisionKind {
    Once,
    Session,
    Always,
}

// ─── App ─────────────────────────────────────────────────────────

/// Main application state.
pub(crate) struct App {
    // ── UI state ──
    pub state: UiState,
    pub should_quit: bool,
    pub quit_pending: bool,

    // ── Content ──
    pub messages: Vec<Message>,
    pub nexus_stream: Vec<NexusEntry>,
    pub running_tools: Vec<ToolStatus>,
    pub completed_tools: Vec<ToolStatus>,
    pub pending_approvals: Vec<ApprovalRequest>,
    pub selected_approval: usize,

    // ── Input ──
    pub input_buf: InputBuffer,
    pub scroll_offset: usize,

    // ── Slash palette ──
    pub slash_commands: Vec<SlashCommandDef>,
    pub palette_selected: usize,
    pub palette_scroll_offset: usize,

    // ── Display ──
    pub working_dir: String,
    pub model_name: String,
    pub context_usage: f32,
    pub tokens_streamed: usize,
    pub session_id_short: String,
    /// Terminal height in rows, updated each render tick.
    pub terminal_height: u16,

    // ── Timing ──
    pub last_completed: Option<(String, Duration)>,
    pub last_completed_at: Option<Instant>,
    pub stream_buffer: String,

    // ── Actions ──
    pub pending_actions: Vec<PendingAction>,

    // ── Copy mode ──
    pub copy_cursor: usize,
    pub copy_selected: HashSet<usize>,
    pub copy_notice: Option<(String, Instant)>,

    // ── Status Bar ──
    pub status_message: Option<(String, Instant)>,

    // ── Lifecycle Elicit ──
    /// When set, the current onboarding UI is driven by a lifecycle `elicit`
    /// request. On completion, an `ElicitResponse` is published to the event
    /// bus instead of writing `.env.json`.
    pub elicit_request_id: Option<uuid::Uuid>,

    // ── Session Hydration ──
    /// Expected reply topic for the pending hydration request. Precomputed to
    /// avoid per-event `format!` allocation. Cleared after the first response.
    pub hydration_reply_topic: Option<Topic>,
}

impl App {
    /// Create a new app instance.
    pub(crate) fn new(working_dir: String, model_name: String, session_id_short: String) -> Self {
        Self {
            state: UiState::Idle,
            should_quit: false,
            quit_pending: false,

            messages: Vec::new(),
            nexus_stream: Vec::new(),
            running_tools: Vec::new(),
            completed_tools: Vec::new(),
            pending_approvals: Vec::new(),
            selected_approval: 0,

            input_buf: InputBuffer::default(),
            scroll_offset: 0,

            slash_commands: vec![
                SlashCommandDef {
                    name: "/help".to_string(),
                    description: "Show available commands".to_string(),
                },
                SlashCommandDef {
                    name: "/clear".to_string(),
                    description: "Clear conversation history".to_string(),
                },
                SlashCommandDef {
                    name: "/install".to_string(),
                    description: "Install a capsule from a path or registry".to_string(),
                },
                SlashCommandDef {
                    name: "/refresh".to_string(),
                    description: "Reload all installed capsules into the OS".to_string(),
                },
                SlashCommandDef {
                    name: "/quit".to_string(),
                    description: "Disconnect from the daemon".to_string(),
                },
            ],
            palette_selected: 0,
            palette_scroll_offset: 0,

            working_dir,
            model_name,
            context_usage: 0.0,
            tokens_streamed: 0,
            session_id_short,
            terminal_height: 24,

            last_completed: None,
            last_completed_at: None,
            stream_buffer: String::new(),

            pending_actions: Vec::new(),

            copy_cursor: 0,
            copy_selected: HashSet::new(),
            copy_notice: None,

            status_message: None,

            elicit_request_id: None,

            hydration_reply_topic: None,
        }
    }

    /// Whether the slash command palette should be displayed.
    pub(crate) fn palette_active(&self) -> bool {
        matches!(self.state, UiState::Idle | UiState::Interrupted)
            && self.input_buf.starts_with_slash()
            && !self.input_buf.has_paste_blocks()
    }

    /// Return the filtered list of slash commands matching the current input prefix.
    pub(crate) fn palette_filtered(&self) -> Vec<&SlashCommandDef> {
        let prefix = self.input_buf.text_for_palette();
        self.slash_commands
            .iter()
            .filter(|cmd| cmd.name.starts_with(prefix))
            .collect()
    }

    /// Reset palette selection and scroll to top.
    pub(crate) fn palette_reset(&mut self) {
        self.palette_selected = 0;
        self.palette_scroll_offset = 0;
    }

    /// Submit the current input, returning the text if non-empty.
    pub(crate) fn submit_input(&mut self) -> Option<String> {
        self.input_buf.take_flat()
    }

    /// Push a user/assistant/system message and add it to the nexus stream.
    pub(crate) fn push_message(&mut self, role: MessageRole, content: String) {
        let msg = Message {
            role,
            content,
            timestamp: Instant::now(),
            kind: None,
            spacing: true,
        };
        self.nexus_stream.push(NexusEntry::Message(msg.clone()));
        self.messages.push(msg);
    }

    /// Push a system notice.
    pub(crate) fn push_notice(&mut self, text: &str) {
        self.push_message(MessageRole::LocalUi, text.to_string());
    }

    /// Approve a pending tool call.
    ///
    /// Does NOT push to `running_tools` — the daemon will send a
    /// `ToolCallStart` event once the tool actually begins executing,
    /// which avoids duplicate entries.
    pub(crate) fn approve_tool(&mut self, id: &str, decision: ApprovalDecisionKind) {
        if let Some(pos) = self.pending_approvals.iter().position(|a| a.id == id) {
            let approval = self.pending_approvals.remove(pos);

            self.pending_actions.push(PendingAction::Approve {
                request_id: id.to_string(),
                decision,
            });

            // Transition to ToolRunning or Thinking while waiting for daemon.
            if let Some(tool) = self.running_tools.last() {
                self.state = UiState::ToolRunning {
                    tool_name: tool.name.clone(),
                    start_time: tool.start_time,
                };
            } else {
                self.state = UiState::Thinking {
                    start_time: Instant::now(),
                    dots: 0,
                };
            }

            let _ = approval; // consumed above
        }

        if self.pending_approvals.is_empty() && self.running_tools.is_empty() {
            // Still waiting for the daemon to resume after approval.
            self.state = UiState::Thinking {
                start_time: Instant::now(),
                dots: 0,
            };
        } else if !self.pending_approvals.is_empty() {
            self.state = UiState::AwaitingApproval;
        }
    }

    /// Deny a pending tool call.
    pub(crate) fn deny_tool(&mut self, id: &str) {
        self.pending_approvals.retain(|a| a.id != id);

        self.pending_actions.push(PendingAction::Deny {
            request_id: id.to_string(),
            reason: None,
        });

        self.push_notice("Tool call denied.");

        if self.pending_approvals.is_empty() {
            self.state = UiState::Idle;
        }
    }

    // ── Copy Mode ───────────────────────────────────────────────

    /// Enter copy mode, positioning the cursor on the last entry.
    pub(crate) fn enter_copy_mode(&mut self) {
        if self.nexus_stream.is_empty() {
            return;
        }
        self.copy_cursor = self.nexus_stream.len().saturating_sub(1);
        self.copy_selected.clear();
        self.state = UiState::CopyMode;
        self.scroll_offset = 0;
    }

    /// Exit copy mode, clearing selections.
    pub(crate) fn exit_copy_mode(&mut self) {
        self.copy_selected.clear();
        self.state = UiState::Idle;
    }

    /// Toggle the current cursor entry in/out of the selected set.
    pub(crate) fn toggle_copy_selection(&mut self) {
        if !self.copy_selected.remove(&self.copy_cursor) {
            self.copy_selected.insert(self.copy_cursor);
        }
    }

    /// Select all nexus entries.
    pub(crate) fn select_all_copy(&mut self) {
        for i in 0..self.nexus_stream.len() {
            self.copy_selected.insert(i);
        }
    }

    /// Gather clean text from selected entries (or cursor entry if none toggled).
    pub(crate) fn collect_copy_text(&self) -> String {
        let indices: Vec<usize> = if self.copy_selected.is_empty() {
            vec![self.copy_cursor]
        } else {
            let mut v: Vec<usize> = self.copy_selected.iter().copied().collect();
            v.sort_unstable();
            v
        };

        let mut parts = Vec::new();
        for idx in indices {
            if let Some(entry) = self.nexus_stream.get(idx) {
                match entry {
                    NexusEntry::Message(msg) => {
                        if let Some(MessageKind::ToolResult(tool_idx)) = &msg.kind {
                            if let Some(tool) = self.completed_tools.get(*tool_idx) {
                                let header = if tool.display_arg.is_empty() {
                                    tool.name.clone()
                                } else {
                                    format!("{}({})", tool.name, tool.display_arg)
                                };
                                if let Some(ref output) = tool.output {
                                    parts.push(format!("{header}\n{output}"));
                                } else {
                                    parts.push(header);
                                }
                            }
                        } else {
                            match msg.role {
                                MessageRole::User => {
                                    parts.push(format!("> {}", msg.content));
                                },
                                MessageRole::Assistant | MessageRole::LocalUi => {
                                    parts.push(msg.content.clone());
                                },
                            }
                        }
                    },
                }
            }
        }

        parts.join("\n\n")
    }

    /// Copy selected text to system clipboard. Returns Ok(()) or an error message.
    pub(crate) fn copy_to_clipboard(&mut self) -> Result<(), String> {
        let text = self.collect_copy_text();
        let mut clipboard =
            arboard::Clipboard::new().map_err(|e| format!("Clipboard error: {e}"))?;
        clipboard
            .set_text(text)
            .map_err(|e| format!("Clipboard error: {e}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── InputBuffer tests ───────────────────────────────────────

    #[test]
    fn input_buffer_empty_by_default() {
        let buf = InputBuffer::default();
        assert!(buf.is_empty());
        assert_eq!(buf.flat_text(), "");
        assert!(!buf.starts_with_slash());
        assert!(!buf.has_paste_blocks());
    }

    #[test]
    fn input_buffer_insert_char_basic() {
        let mut buf = InputBuffer::default();
        buf.insert_char('h');
        buf.insert_char('i');
        assert_eq!(buf.flat_text(), "hi");
        assert!(!buf.is_empty());
        assert_eq!(buf.cursor, (0, 2));
    }

    #[test]
    fn input_buffer_insert_char_utf8() {
        let mut buf = InputBuffer::default();
        buf.insert_char('a');
        buf.insert_char('\u{00e9}'); // e-acute (2 bytes)
        buf.insert_char('b');
        assert_eq!(buf.flat_text(), "a\u{00e9}b");
        assert_eq!(buf.cursor.1, 4); // 1 + 2 + 1
    }

    #[test]
    fn input_buffer_insert_str_basic() {
        let mut buf = InputBuffer::default();
        buf.insert_str("hello");
        assert_eq!(buf.flat_text(), "hello");
        assert_eq!(buf.cursor, (0, 5));
        // Insert in the middle.
        buf.cursor.1 = 2;
        buf.insert_str("XY");
        assert_eq!(buf.flat_text(), "heXYllo");
        assert_eq!(buf.cursor, (0, 4));
    }

    #[test]
    fn input_buffer_insert_str_utf8() {
        let mut buf = InputBuffer::default();
        buf.insert_str("a\u{00e9}b"); // e-acute is 2 bytes
        assert_eq!(buf.flat_text(), "a\u{00e9}b");
        assert_eq!(buf.cursor, (0, 4)); // 1 + 2 + 1
    }

    #[test]
    fn input_buffer_insert_str_adjacent_to_paste() {
        let mut buf = InputBuffer::default();
        buf.insert_paste("A\nB".to_string());
        buf.insert_str("after");
        assert_eq!(buf.flat_text(), "A\nBafter");
    }

    #[test]
    fn input_buffer_backspace_basic() {
        let mut buf = InputBuffer::default();
        buf.insert_char('a');
        buf.insert_char('b');
        buf.insert_char('c');
        buf.backspace();
        assert_eq!(buf.flat_text(), "ab");
        buf.backspace();
        assert_eq!(buf.flat_text(), "a");
        buf.backspace();
        assert_eq!(buf.flat_text(), "");
        // Backspace on empty is no-op.
        buf.backspace();
        assert_eq!(buf.flat_text(), "");
    }

    #[test]
    fn input_buffer_backspace_utf8() {
        let mut buf = InputBuffer::default();
        buf.insert_char('\u{1f600}'); // grinning face (4 bytes)
        buf.insert_char('x');
        assert_eq!(buf.flat_text(), "\u{1f600}x");
        buf.backspace();
        assert_eq!(buf.flat_text(), "\u{1f600}");
        buf.backspace();
        assert_eq!(buf.flat_text(), "");
    }

    #[test]
    fn input_buffer_move_left_right() {
        let mut buf = InputBuffer::default();
        buf.insert_char('a');
        buf.insert_char('b');
        buf.insert_char('c');
        // Cursor at end: (0, 3)
        assert_eq!(buf.cursor, (0, 3));

        buf.move_left();
        assert_eq!(buf.cursor, (0, 2));
        buf.move_left();
        assert_eq!(buf.cursor, (0, 1));
        buf.move_left();
        assert_eq!(buf.cursor, (0, 0));
        // Left at start is no-op.
        buf.move_left();
        assert_eq!(buf.cursor, (0, 0));

        buf.move_right();
        assert_eq!(buf.cursor, (0, 1));
        buf.move_right();
        assert_eq!(buf.cursor, (0, 2));
        buf.move_right();
        assert_eq!(buf.cursor, (0, 3));
        // Right at end is no-op.
        buf.move_right();
        assert_eq!(buf.cursor, (0, 3));
    }

    #[test]
    fn input_buffer_home_end() {
        let mut buf = InputBuffer::default();
        buf.insert_char('a');
        buf.insert_char('b');
        buf.insert_char('c');

        buf.move_home();
        assert_eq!(buf.cursor, (0, 0));

        buf.move_end();
        assert_eq!(buf.cursor, (0, 3));
    }

    #[test]
    fn input_buffer_insert_paste_empty_buffer() {
        let mut buf = InputBuffer::default();
        buf.insert_paste("line1\nline2\nline3".to_string());
        assert!(buf.has_paste_blocks());
        assert_eq!(buf.paste_block_total_lines(), 3);
        assert_eq!(buf.flat_text(), "line1\nline2\nline3");
        // Cursor should be after the paste block (on trailing Text).
        assert!(!buf.is_empty());
    }

    #[test]
    fn input_buffer_insert_paste_splits_text() {
        let mut buf = InputBuffer::default();
        buf.insert_char('a');
        buf.insert_char('b');
        buf.insert_char('c');
        buf.insert_char('d');

        // Move cursor to between 'b' and 'c'.
        buf.move_left();
        buf.move_left();
        assert_eq!(buf.cursor, (0, 2));

        buf.insert_paste("X\nY".to_string());

        // Should be: Text("ab") + PasteBlock("X\nY") + Text("cd")
        assert_eq!(buf.flat_text(), "abX\nYcd");
        assert!(buf.has_paste_blocks());

        // Verify segment structure.
        let text_segments: Vec<&str> = buf
            .segments
            .iter()
            .filter_map(|s| match s {
                InputSegment::Text(t) => Some(t.as_str()),
                InputSegment::PasteBlock { .. } => None,
            })
            .collect();
        assert!(text_segments.contains(&"ab"));
        assert!(text_segments.contains(&"cd"));
    }

    #[test]
    fn input_buffer_insert_paste_at_start() {
        let mut buf = InputBuffer::default();
        buf.insert_char('x');
        buf.move_home();
        buf.insert_paste("P\nQ".to_string());
        assert_eq!(buf.flat_text(), "P\nQx");
    }

    #[test]
    fn input_buffer_insert_paste_at_end() {
        let mut buf = InputBuffer::default();
        buf.insert_char('x');
        buf.insert_paste("P\nQ".to_string());
        assert_eq!(buf.flat_text(), "xP\nQ");
    }

    #[test]
    fn input_buffer_backspace_deletes_paste_block() {
        let mut buf = InputBuffer::default();
        buf.insert_char('a');
        buf.insert_paste("X\nY".to_string());
        buf.insert_char('b');

        // Cursor is at end: after 'b'. Buffer: Text("a") + PasteBlock + Text("b")
        // Backspace should delete 'b'.
        buf.backspace();
        assert!(buf.flat_text().ends_with("X\nY"));

        // Now cursor is after the PasteBlock. Backspace should delete the entire block.
        buf.backspace();
        assert!(!buf.has_paste_blocks());
        assert_eq!(buf.flat_text(), "a");
    }

    #[test]
    fn input_buffer_backspace_paste_block_at_start() {
        let mut buf = InputBuffer::default();
        buf.insert_paste("block\ncontent".to_string());
        // Cursor is after the paste block.
        // Backspace should delete the paste block.
        buf.backspace();
        assert!(!buf.has_paste_blocks());
        assert!(buf.is_empty());
    }

    #[test]
    fn input_buffer_backspace_non_leading_paste_block() {
        let mut buf = InputBuffer::default();
        buf.insert_char('x');
        buf.insert_paste("A\nB".to_string());
        buf.insert_char('y');
        // [Text("x"), PasteBlock("A\nB"), Text("y")], cursor at (2, 1)
        buf.backspace(); // removes 'y'
        assert_eq!(buf.flat_text(), "xA\nB");
        buf.backspace(); // should remove PasteBlock, NOT 'x'
        assert!(!buf.has_paste_blocks());
        assert_eq!(buf.flat_text(), "x");
    }

    #[test]
    fn input_buffer_delete_forward_paste_block() {
        let mut buf = InputBuffer::default();
        buf.insert_char('a');
        buf.insert_paste("X\nY".to_string());
        buf.insert_char('b');

        // Move to end of 'a', before the PasteBlock.
        buf.move_home();
        buf.move_right(); // cursor at (0, 1) = end of "a"

        buf.delete_forward();
        assert!(!buf.has_paste_blocks());
        assert_eq!(buf.flat_text(), "ab");
    }

    #[test]
    fn input_buffer_delete_forward_basic() {
        let mut buf = InputBuffer::default();
        buf.insert_char('a');
        buf.insert_char('b');
        buf.insert_char('c');
        buf.move_home();
        buf.delete_forward();
        assert_eq!(buf.flat_text(), "bc");
    }

    #[test]
    fn input_buffer_cursor_skips_paste_block_left() {
        let mut buf = InputBuffer::default();
        buf.insert_char('a');
        buf.insert_paste("X\nY".to_string());
        buf.insert_char('b');

        // Cursor at end (after 'b'). Move left to before 'b'.
        buf.move_left();
        // Move left should skip over the paste block to end of "a".
        buf.move_left();
        let flat = buf.flat_text();
        let a_pos = flat.find('a').unwrap();
        assert_eq!(buf.cursor.1, a_pos.saturating_add(1));
    }

    #[test]
    fn input_buffer_cursor_skips_paste_block_right() {
        let mut buf = InputBuffer::default();
        buf.insert_char('a');
        buf.insert_paste("X\nY".to_string());
        buf.insert_char('b');

        buf.move_home();
        // At start of "a". Move right past 'a'.
        buf.move_right();
        // Move right should skip over the paste block to start of trailing Text.
        buf.move_right();
        // Should be at start of the Text segment containing "b".
        assert_eq!(buf.cursor.1, 0);
    }

    #[test]
    fn input_buffer_flat_text_preserves_order() {
        let mut buf = InputBuffer::default();
        buf.insert_char('H');
        buf.insert_char('i');
        buf.insert_char(' ');
        buf.insert_paste("code\nhere".to_string());
        buf.insert_char(' ');
        buf.insert_char('!');
        assert_eq!(buf.flat_text(), "Hi code\nhere !");
    }

    #[test]
    fn input_buffer_normalize_merges_adjacent_text() {
        let mut buf = InputBuffer {
            segments: vec![
                InputSegment::Text("aa".to_string()),
                InputSegment::Text("bb".to_string()),
            ],
            cursor: (1, 1),
        };
        buf.normalize();
        assert_eq!(buf.segments.len(), 1);
        assert_eq!(buf.flat_text(), "aabb");
        // Cursor should be adjusted: was at (1, 1) -> (0, 2 + 1) = (0, 3)
        assert_eq!(buf.cursor, (0, 3));
    }

    #[test]
    fn input_buffer_starts_with_slash() {
        let mut buf = InputBuffer::default();
        buf.insert_char('/');
        buf.insert_char('h');
        assert!(buf.starts_with_slash());

        buf.clear();
        buf.insert_char('h');
        assert!(!buf.starts_with_slash());
    }

    #[test]
    fn input_buffer_clear_resets() {
        let mut buf = InputBuffer::default();
        buf.insert_char('x');
        buf.insert_paste("a\nb".to_string());
        buf.clear();
        assert!(buf.is_empty());
        assert_eq!(buf.cursor, (0, 0));
        assert!(buf.segments.is_empty());
    }

    #[test]
    fn input_buffer_set_text() {
        let mut buf = InputBuffer::default();
        buf.insert_paste("old\nblock".to_string());
        buf.set_text("/help ".to_string());
        assert!(!buf.has_paste_blocks());
        assert_eq!(buf.flat_text(), "/help ");
        assert_eq!(buf.cursor, (0, 6));
    }

    #[test]
    fn input_buffer_take_flat_returns_none_on_empty() {
        let mut buf = InputBuffer::default();
        assert_eq!(buf.take_flat(), None);
    }

    #[test]
    fn input_buffer_take_flat_returns_none_on_whitespace() {
        let mut buf = InputBuffer::default();
        buf.insert_char(' ');
        buf.insert_char(' ');
        assert_eq!(buf.take_flat(), None);
    }

    #[test]
    fn input_buffer_take_flat_returns_content() {
        let mut buf = InputBuffer::default();
        buf.insert_char('h');
        buf.insert_char('i');
        let result = buf.take_flat();
        assert_eq!(result, Some("hi".to_string()));
        assert!(buf.is_empty());
    }

    #[test]
    fn input_buffer_text_for_palette() {
        let mut buf = InputBuffer::default();
        buf.insert_char('/');
        buf.insert_char('h');
        assert_eq!(buf.text_for_palette(), "/h");

        buf.clear();
        assert_eq!(buf.text_for_palette(), "");
    }

    #[test]
    fn input_buffer_multiple_paste_blocks() {
        let mut buf = InputBuffer::default();
        buf.insert_paste("A\nB".to_string());
        buf.insert_char(' ');
        buf.insert_paste("C\nD\nE".to_string());
        assert_eq!(buf.paste_block_total_lines(), 5); // 2 + 3
        assert_eq!(buf.flat_text(), "A\nB C\nD\nE");
    }

    #[test]
    fn input_buffer_insert_char_at_paste_block_boundary() {
        let mut buf = InputBuffer::default();
        buf.insert_paste("X\nY".to_string());
        // Cursor is after the paste block in a trailing Text segment.
        buf.insert_char('z');
        assert_eq!(buf.flat_text(), "X\nYz");
    }

    #[test]
    fn input_buffer_backspace_between_two_paste_blocks() {
        let mut buf = InputBuffer::default();
        buf.insert_paste("A\nB".to_string());
        buf.insert_paste("C\nD".to_string());
        // Cursor is after second paste block.
        // Backspace should delete the second paste block.
        buf.backspace();
        assert_eq!(buf.paste_block_total_lines(), 2); // Only first block remains.
        assert_eq!(buf.flat_text(), "A\nB");
    }

    #[test]
    fn input_buffer_delete_forward_at_paste_block() {
        let mut buf = InputBuffer::default();
        buf.insert_char('a');
        buf.insert_paste("X\nY".to_string());
        // Cursor is on the trailing Text after the PasteBlock.
        // Move to end of the first Text segment ("a"), right before the PasteBlock.
        buf.cursor = (0, 1);
        buf.delete_forward();
        assert!(!buf.has_paste_blocks());
        assert_eq!(buf.flat_text(), "a");
    }

    #[test]
    fn input_buffer_palette_not_active_with_paste_blocks() {
        let mut buf = InputBuffer::default();
        buf.insert_char('/');
        buf.insert_char('h');
        buf.insert_paste("block\ndata".to_string());
        // Has paste blocks, so should not be treated as palette input.
        assert!(buf.has_paste_blocks());
        assert!(buf.starts_with_slash());
        // palette_active on App would return false due to has_paste_blocks check.
    }

    #[test]
    fn input_buffer_move_end_then_insert_char_on_trailing_paste() {
        let mut buf = InputBuffer::default();
        buf.insert_paste("A\nB".to_string());
        buf.move_end();
        buf.insert_char('z');
        // 'z' must appear after the paste block, not before it.
        assert_eq!(buf.flat_text(), "A\nBz");
    }

    #[test]
    fn input_buffer_move_home_then_insert_char_on_leading_paste() {
        let mut buf = InputBuffer::default();
        buf.insert_paste("A\nB".to_string());
        buf.insert_char('x'); // after paste
        buf.move_home();
        buf.insert_char('z');
        // Home inserts a Text segment before the paste block, so 'z' goes
        // at the true beginning of the buffer.
        assert_eq!(buf.flat_text(), "zA\nBx");
    }

    #[test]
    fn input_buffer_set_text_empty() {
        let mut buf = InputBuffer::default();
        buf.insert_char('x');
        buf.insert_paste("A\nB".to_string());
        buf.set_text(String::new());
        assert!(buf.is_empty());
        assert_eq!(buf.cursor, (0, 0));
    }

    #[test]
    fn input_buffer_move_left_inserts_text_before_leading_paste() {
        let mut buf = InputBuffer::default();
        buf.insert_paste("X\nY".to_string());
        // Cursor is on trailing Text at (1, 0). Move left skips PasteBlock.
        buf.move_left();
        // Should have inserted a leading Text, cursor is at (0, 0) on that Text.
        assert!(matches!(buf.segments[0], InputSegment::Text(_)));
        assert_eq!(buf.cursor.0, 0);
        // Typing should insert before the PasteBlock.
        buf.insert_char('z');
        assert_eq!(buf.flat_text(), "zX\nY");
    }

    #[test]
    fn input_buffer_move_left_through_consecutive_paste_blocks() {
        let mut buf = InputBuffer::default();
        buf.insert_paste("A\nB".to_string());
        buf.insert_paste("C\nD".to_string());
        // cursor at trailing Text. Move left should skip PasteBlock(B).
        buf.move_left();
        assert!(matches!(buf.segments[buf.cursor.0], InputSegment::Text(_)));
        // Move left again should skip PasteBlock(A) and insert leading Text.
        buf.move_left();
        assert!(matches!(buf.segments[buf.cursor.0], InputSegment::Text(_)));
        buf.insert_char('z');
        assert_eq!(buf.flat_text(), "zA\nBC\nD");
    }

    #[test]
    fn input_buffer_move_right_through_consecutive_paste_blocks() {
        let mut buf = InputBuffer::default();
        buf.insert_paste("A\nB".to_string());
        buf.insert_paste("C\nD".to_string());
        buf.insert_paste("E\nF".to_string());
        buf.move_home();
        // Right should skip all consecutive PasteBlocks and land on trailing Text.
        buf.move_right();
        assert!(matches!(buf.segments[buf.cursor.0], InputSegment::Text(_)));
    }

    #[test]
    fn input_buffer_consecutive_paste_inserts() {
        let mut buf = InputBuffer::default();
        buf.insert_paste("A\nB".to_string());
        buf.insert_paste("C\nD".to_string());
        // Both blocks should be present in order.
        assert_eq!(buf.flat_text(), "A\nBC\nD");
        assert_eq!(buf.paste_block_total_lines(), 4);
    }
}
