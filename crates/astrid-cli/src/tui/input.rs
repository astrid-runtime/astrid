//! Input handling for the TUI — stripped to Nexus-only keys.

use super::state::{App, ApprovalDecisionKind, PALETTE_MAX_VISIBLE, PendingAction, UiState};
use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyModifiers};
use std::io;

/// Maximum length (in bytes) for a single multi-line paste.
const MAX_PASTE_LEN: usize = 32_768;

/// Handle input events.
pub(crate) fn handle_input(app: &mut App) -> io::Result<()> {
    match event::read()? {
        Event::Key(key) => match app.state {
            UiState::Idle => handle_idle_input(app, key),
            UiState::AwaitingApproval => handle_approval_input(app, key),
            UiState::Thinking { .. } | UiState::Streaming { .. } | UiState::ToolRunning { .. } => {
                handle_interruptible_input(app, key);
            },
            UiState::Interrupted => handle_interrupted_input(app, key),
            UiState::CopyMode => handle_copy_input(app, key),
            UiState::Selection { .. } => handle_selection_input(app, key),
            UiState::Onboarding { .. } => handle_onboarding_input(app, key),
            UiState::Error { .. } => handle_error_input(app, key),
        },
        Event::Paste(ref text) => handle_paste(app, text),
        _ => {},
    }
    Ok(())
}

/// Handle a bracketed paste event.
fn handle_paste(app: &mut App, text: &str) {
    // Only accept pastes in states that accept text input.
    match &app.state {
        UiState::Idle | UiState::Onboarding { .. } => {},
        UiState::Interrupted => {
            app.state = UiState::Idle;
        },
        _ => return,
    }

    if text.is_empty() {
        return;
    }

    // Single-line paste: treat as typed text. Use insert_str for O(N) insertion
    // instead of per-character insert_char which is O(N^2).
    if !text.contains('\n') {
        let limit = if text.len() > MAX_PASTE_LEN {
            app.push_notice(&format!(
                "Paste too large ({} bytes, max {MAX_PASTE_LEN}). Truncated.",
                text.len()
            ));
            MAX_PASTE_LEN
        } else {
            text.len()
        };
        // Sanitize: strip \r and \0, then truncate to limit.
        let sanitized: String = text
            .chars()
            .filter(|c| !matches!(c, '\r' | '\0'))
            .scan(0usize, |bytes, c| {
                *bytes = bytes.saturating_add(c.len_utf8());
                if *bytes > limit { None } else { Some(c) }
            })
            .collect();
        app.input_buf.insert_str(&sanitized);
        app.quit_pending = false;
        app.palette_reset();
        return;
    }

    // Multi-line paste in slash command mode is not supported.
    if app.input_buf.starts_with_slash() {
        app.push_notice("Multi-line paste not supported in command mode.");
        app.quit_pending = false;
        return;
    }

    // Multi-line paste in secret/array onboarding fields is not supported.
    // Secret: would leak content in plaintext. Array: each item is single-line.
    if let UiState::Onboarding {
        fields,
        current_idx,
        ..
    } = &app.state
        && fields.get(*current_idx).is_some_and(|f| {
            matches!(
                f.field_type,
                astrid_types::ipc::OnboardingFieldType::Secret
                    | astrid_types::ipc::OnboardingFieldType::Array
            )
        })
    {
        app.push_notice("Multi-line paste not supported in this field type.");
        app.quit_pending = false;
        return;
    }

    // Bound the raw text before sanitization to prevent OOM on massive pastes.
    // Allow 2x headroom for \r\n -> \n shrinkage.
    let raw_limit = text.len().min(MAX_PASTE_LEN.saturating_mul(2));
    let mut raw_end = raw_limit;
    while raw_end > 0 && !text.is_char_boundary(raw_end) {
        raw_end = raw_end.saturating_sub(1);
    }

    // Sanitize: normalize line endings, strip bare CR, strip null bytes.
    let sanitized = text[..raw_end]
        .replace("\r\n", "\n")
        .replace(['\r', '\0'], "");

    let was_pre_truncated = text.len() > raw_limit;
    if was_pre_truncated || sanitized.len() > MAX_PASTE_LEN {
        app.push_notice(&format!(
            "Paste too large ({} bytes, max {MAX_PASTE_LEN}). Truncated.",
            text.len()
        ));
        // Truncate at a char boundary without exceeding MAX_PASTE_LEN.
        let end = sanitized
            .char_indices()
            .take_while(|(i, c)| i.saturating_add(c.len_utf8()) <= MAX_PASTE_LEN)
            .last()
            .map_or(0, |(i, c)| i.saturating_add(c.len_utf8()));
        let truncated = &sanitized[..end];
        app.input_buf.insert_paste(truncated.to_string());
    } else {
        app.input_buf.insert_paste(sanitized);
    }

    app.quit_pending = false;
    app.palette_reset();
}

fn handle_selection_input(app: &mut App, key: KeyEvent) {
    match key.code {
        KeyCode::Esc => {
            app.push_notice("Selection cancelled.");
            app.state = UiState::Idle;
        },
        KeyCode::Up => {
            if let UiState::Selection {
                selected,
                scroll_offset,
                ..
            } = &mut app.state
                && *selected > 0
            {
                *selected = selected.saturating_sub(1);
                if *selected < *scroll_offset {
                    *scroll_offset = *selected;
                }
            }
        },
        KeyCode::Down => {
            if let UiState::Selection {
                selected,
                scroll_offset,
                options,
                ..
            } = &mut app.state
                && selected.saturating_add(1) < options.len()
            {
                *selected = selected.saturating_add(1);
                // Keep selection visible (max 8 visible items)
                if *selected >= scroll_offset.saturating_add(PALETTE_MAX_VISIBLE) {
                    *scroll_offset = selected
                        .saturating_add(1)
                        .saturating_sub(PALETTE_MAX_VISIBLE);
                }
            }
        },
        KeyCode::Enter => {
            if let UiState::Selection {
                options,
                selected,
                callback_topic,
                request_id,
                ..
            } = &app.state
                && let Some(opt) = options.get(*selected)
            {
                app.pending_actions.push(PendingAction::SubmitSelection {
                    callback_topic: callback_topic.clone(),
                    request_id: request_id.clone(),
                    selected_id: opt.id.clone(),
                    selected_label: opt.label.clone(),
                });
            }
            app.state = UiState::Idle;
        },
        _ => {},
    }
}

/// Maximum length (in bytes) for a single onboarding input value.
/// Guards against accidental clipboard paste of very large content.
const MAX_INPUT_LEN: usize = 4096;

/// Maximum array items that fit in 1/3 of the terminal, accounting for the
/// title row and remaining onboarding keys.
fn max_array_items(terminal_height: u16, total_keys: usize) -> usize {
    // 1/3 of terminal, minus 1 title row, minus the key rows themselves
    let budget = (terminal_height as usize) / 3;
    // title(1) + all keys + separator(1) = overhead
    let overhead = total_keys.saturating_add(2);
    budget.saturating_sub(overhead).max(1)
}

fn handle_onboarding_input(app: &mut App, key: KeyEvent) {
    // Determine if the current field is an enum picker.
    let is_enum_field = matches!(
        &app.state,
        UiState::Onboarding { fields, current_idx, .. }
            if fields.get(*current_idx).is_some_and(|f|
                matches!(f.field_type, astrid_types::ipc::OnboardingFieldType::Enum(_))
            )
    );

    if is_enum_field {
        handle_onboarding_enum_input(app, key);
    } else {
        // Text, Secret, and Array fields all use the text input path.
        // Array fields interpret Enter differently (add item vs advance).
        handle_onboarding_text_input(app, key);
    }
}

/// Advance to the next onboarding field or finish, pre-filling defaults.
fn advance_onboarding(app: &mut App) {
    // Check completion with a read-only borrow to avoid conflicts with finish_onboarding.
    let done = matches!(
        &app.state,
        UiState::Onboarding { fields, current_idx, .. } if *current_idx >= fields.len()
    );
    if done {
        finish_onboarding(app);
        return;
    }

    // Reset enum state and extract pre-fill info in a single scoped borrow.
    let (is_enum, is_array, default) = if let UiState::Onboarding {
        fields,
        current_idx,
        enum_selected,
        enum_scroll_offset,
        ..
    } = &mut app.state
    {
        *enum_scroll_offset = 0;

        let field = fields.get(*current_idx);
        let is_enum_field = field.is_some_and(|f| {
            matches!(
                f.field_type,
                astrid_types::ipc::OnboardingFieldType::Enum(_)
            )
        });
        let is_array_field = field
            .is_some_and(|f| matches!(f.field_type, astrid_types::ipc::OnboardingFieldType::Array));

        // Pre-position enum_selected to the default value's index if present.
        *enum_selected = field.map_or(0, default_enum_position);

        let default_val = field.and_then(|f| f.default.clone()).unwrap_or_default();
        (is_enum_field, is_array_field, default_val)
    } else {
        return;
    };

    // Enum and array fields clear the input; text/secret fields get the default pre-filled.
    prefill_field_input(app, is_enum || is_array, &default);
}

/// Compute the initial `enum_selected` index for a field, matching its default
/// to a position in the enum choices. Returns 0 if no match or not an enum.
pub(crate) fn default_enum_position(field: &astrid_types::ipc::OnboardingField) -> usize {
    field
        .default
        .as_deref()
        .and_then(|default_val| match &field.field_type {
            astrid_types::ipc::OnboardingFieldType::Enum(choices) => {
                choices.iter().position(|c| c == default_val)
            },
            _ => None,
        })
        .unwrap_or(0)
}

/// Set the input buffer for a new onboarding field.
/// Enum fields clear the input (the picker handles selection);
/// text/secret fields pre-fill with the default value.
pub(crate) fn prefill_field_input(app: &mut App, is_enum: bool, default: &str) {
    if is_enum {
        app.input_buf.clear();
    } else {
        app.input_buf.set_text(default.to_string());
    }
}

/// Submit onboarding answers and return to Idle.
fn finish_onboarding(app: &mut App) {
    if let UiState::Onboarding {
        capsule_id,
        fields,
        answers,
        current_array_items,
        ..
    } = &app.state
    {
        if let Some(request_id) = app.elicit_request_id.take() {
            // Lifecycle elicit mode: publish ElicitResponse via IPC
            // instead of writing .env.json.
            let field = fields.first();
            let is_array = field.is_some_and(|f| {
                matches!(f.field_type, astrid_types::ipc::OnboardingFieldType::Array)
            });

            let (value, values) = if is_array {
                (None, Some(current_array_items.clone()))
            } else {
                let key = field.map_or("", |f| f.key.as_str());
                (answers.get(key).cloned(), None)
            };

            app.pending_actions
                .push(PendingAction::SubmitElicitResponse {
                    request_id,
                    value,
                    values,
                });
        } else {
            let cid = capsule_id.clone();
            let final_answers = answers.clone();
            app.pending_actions.push(PendingAction::SubmitOnboarding {
                capsule_id: cid,
                answers: final_answers,
            });
        }
    }
    app.state = UiState::Idle;
    app.input_buf.clear();
}

/// Handle text/secret field input during onboarding.
fn handle_onboarding_text_input(app: &mut App, key: KeyEvent) {
    match key.code {
        KeyCode::Esc => {
            if let Some(request_id) = app.elicit_request_id.take() {
                // Publish a cancellation response so the host function unblocks
                app.pending_actions
                    .push(PendingAction::SubmitElicitResponse {
                        request_id,
                        value: None,
                        values: None,
                    });
            }
            app.push_notice("Onboarding cancelled by user.");
            app.state = UiState::Idle;
            app.input_buf.clear();
        },
        KeyCode::Enter => {
            let answer = app.input_buf.flat_text();
            app.input_buf.clear();

            if !answer.is_empty() && answer.len() > MAX_INPUT_LEN {
                app.push_notice("Input too long (max 4096 bytes). Please shorten it.");
                return;
            }

            let mut array_capped = false;

            if let UiState::Onboarding {
                fields,
                current_idx,
                answers,
                current_array_items,
                ..
            } = &mut app.state
            {
                let Some(field) = fields.get(*current_idx) else {
                    app.state = UiState::Idle;
                    return;
                };

                let is_array = matches!(
                    field.field_type,
                    astrid_types::ipc::OnboardingFieldType::Array
                );

                if is_array {
                    if answer.is_empty() {
                        // Empty input finalizes the array field
                        let json_array = serde_json::to_string(&*current_array_items)
                            .unwrap_or_else(|_| "[]".to_string());
                        answers.insert(field.key.clone(), json_array);
                        current_array_items.clear();
                        *current_idx = current_idx.saturating_add(1);
                    } else if current_array_items.len()
                        >= max_array_items(app.terminal_height, fields.len())
                    {
                        array_capped = true;
                    } else {
                        // Non-empty input adds an item
                        current_array_items.push(answer);
                        return;
                    }
                } else {
                    answers.insert(field.key.clone(), answer);
                    *current_idx = current_idx.saturating_add(1);
                }
            }

            if array_capped {
                app.push_notice("Array item limit reached. Press Enter on empty to finish.");
            } else {
                // advance_onboarding checks completion and calls finish_onboarding if done.
                advance_onboarding(app);
            }
        },
        KeyCode::Char(c) => {
            app.input_buf.insert_char(c);
        },
        KeyCode::Backspace => {
            app.input_buf.backspace();
        },
        KeyCode::Left => {
            app.input_buf.move_left();
        },
        KeyCode::Right => {
            app.input_buf.move_right();
        },
        _ => {},
    }
}

/// Handle enum picker input during onboarding.
fn handle_onboarding_enum_input(app: &mut App, key: KeyEvent) {
    match key.code {
        KeyCode::Esc => {
            if let Some(request_id) = app.elicit_request_id.take() {
                // Publish a cancellation response so the host function unblocks
                app.pending_actions
                    .push(PendingAction::SubmitElicitResponse {
                        request_id,
                        value: None,
                        values: None,
                    });
            }
            app.push_notice("Onboarding cancelled by user.");
            app.state = UiState::Idle;
            app.input_buf.clear();
        },
        KeyCode::Up => {
            if let UiState::Onboarding {
                enum_selected,
                enum_scroll_offset,
                ..
            } = &mut app.state
                && *enum_selected > 0
            {
                *enum_selected = enum_selected.saturating_sub(1);
                if *enum_selected < *enum_scroll_offset {
                    *enum_scroll_offset = *enum_selected;
                }
            }
        },
        KeyCode::Down => {
            if let UiState::Onboarding {
                fields,
                current_idx,
                enum_selected,
                enum_scroll_offset,
                ..
            } = &mut app.state
            {
                let choice_count = fields.get(*current_idx).map_or(0, |f| match &f.field_type {
                    astrid_types::ipc::OnboardingFieldType::Enum(v) => v.len(),
                    _ => 0,
                });
                if enum_selected.saturating_add(1) < choice_count {
                    *enum_selected = enum_selected.saturating_add(1);
                    if *enum_selected >= enum_scroll_offset.saturating_add(PALETTE_MAX_VISIBLE) {
                        *enum_scroll_offset = enum_selected
                            .saturating_add(1)
                            .saturating_sub(PALETTE_MAX_VISIBLE);
                    }
                }
            }
        },
        KeyCode::Enter => {
            let skipped = if let UiState::Onboarding {
                fields,
                current_idx,
                enum_selected,
                answers,
                ..
            } = &mut app.state
            {
                // Clamp enum_selected and pick from choices. If enum is empty,
                // the field was already degraded to Text by build_onboarding_field,
                // so this branch shouldn't be reached — but guard defensively.
                // Returns (key, value) from the same .get() call to avoid re-indexing.
                let selection = fields.get(*current_idx).and_then(|f| match &f.field_type {
                    astrid_types::ipc::OnboardingFieldType::Enum(v) if !v.is_empty() => {
                        let clamped = (*enum_selected).min(v.len().saturating_sub(1));
                        Some((f.key.clone(), v[clamped].clone()))
                    },
                    _ => None,
                });

                let was_skipped = if let Some((key, value)) = selection {
                    answers.insert(key, value);
                    false
                } else {
                    true
                };
                *current_idx = current_idx.saturating_add(1);
                was_skipped
            } else {
                false
            };
            if skipped {
                app.push_notice("Skipped field with no available choices.");
            }
            advance_onboarding(app);
        },
        _ => {},
    }
}

#[expect(clippy::too_many_lines)]
fn handle_idle_input(app: &mut App, key: KeyEvent) {
    let palette_is_active = app.palette_active();

    match (key.code, key.modifiers) {
        // Quit: double Ctrl+C/D to confirm
        (KeyCode::Char('c' | 'd'), KeyModifiers::CONTROL) => {
            if app.quit_pending {
                app.should_quit = true;
            } else {
                app.quit_pending = true;
            }
            return; // Don't reset quit_pending below
        },

        // ── Palette navigation ──────────────────────────────────

        // Enter: select palette command and submit, or normal submit
        (KeyCode::Enter, _) => {
            let mut submit_immediately = false;
            let mut selected_from_palette = false;

            if palette_is_active {
                let filtered = app.palette_filtered();
                if let Some(cmd) = filtered.get(app.palette_selected) {
                    if matches!(
                        cmd.name.as_str(),
                        "/help" | "/clear" | "/quit" | "/exit" | "/q" | "/refresh"
                    ) {
                        app.input_buf.set_text(cmd.name.clone());
                        submit_immediately = true;
                    } else {
                        app.input_buf.set_text(format!("{} ", cmd.name));
                    }
                    selected_from_palette = true;
                }
                app.palette_reset();
            }

            // Submit if we aren't using the palette to auto-complete, or if the auto-completed command requires immediate submission.
            // If the user already typed a full command with arguments, `selected_from_palette` will be false because `filtered` is empty.
            if (!palette_is_active || !selected_from_palette || submit_immediately)
                && let Some(content) = app.submit_input()
            {
                app.pending_actions.push(PendingAction::SendInput(content));
            }
        },

        // Tab: fill input with selected command (no submit, allows appending args)
        (KeyCode::Tab, _) if palette_is_active => {
            let filtered = app.palette_filtered();
            if let Some(cmd) = filtered.get(app.palette_selected) {
                // If the command is a simple action that never takes arguments, don't append a space.
                if matches!(
                    cmd.name.as_str(),
                    "/help" | "/clear" | "/quit" | "/exit" | "/q" | "/refresh"
                ) {
                    app.input_buf.set_text(cmd.name.clone());
                } else {
                    app.input_buf.set_text(format!("{} ", cmd.name));
                }
            }
            app.palette_reset();
        },

        // Esc: clear input and close palette
        (KeyCode::Esc, _) if palette_is_active => {
            app.input_buf.clear();
            app.palette_reset();
        },

        // Up: navigate palette selection
        (KeyCode::Up, _) if palette_is_active => {
            let count = app.palette_filtered().len();
            if count > 0 {
                if app.palette_selected == 0 {
                    app.palette_selected = count.saturating_sub(1);
                } else {
                    app.palette_selected = app.palette_selected.saturating_sub(1);
                }
                // Adjust scroll to keep selected visible
                if app.palette_selected < app.palette_scroll_offset {
                    app.palette_scroll_offset = app.palette_selected;
                }
                if app.palette_selected
                    >= app
                        .palette_scroll_offset
                        .saturating_add(PALETTE_MAX_VISIBLE)
                {
                    app.palette_scroll_offset = app
                        .palette_selected
                        .saturating_add(1)
                        .saturating_sub(PALETTE_MAX_VISIBLE);
                }
            }
        },

        // Down: navigate palette selection
        (KeyCode::Down, _) if palette_is_active => {
            let count = app.palette_filtered().len();
            if count > 0 {
                #[expect(clippy::arithmetic_side_effects)] // modulo by count > 0 is safe
                {
                    app.palette_selected = (app.palette_selected.saturating_add(1)) % count;
                }
                // Adjust scroll to keep selected visible
                if app.palette_selected
                    >= app
                        .palette_scroll_offset
                        .saturating_add(PALETTE_MAX_VISIBLE)
                {
                    app.palette_scroll_offset = app
                        .palette_selected
                        .saturating_add(1)
                        .saturating_sub(PALETTE_MAX_VISIBLE);
                }
                if app.palette_selected < app.palette_scroll_offset {
                    app.palette_scroll_offset = app.palette_selected;
                }
            }
        },

        // ── Copy mode ────────────────────────────────────────────
        // Ctrl+Shift+C enters copy mode (capital C = Shift held)
        (KeyCode::Char('C'), m) if m.contains(KeyModifiers::CONTROL) => {
            app.enter_copy_mode();
        },

        // ── Text editing ────────────────────────────────────────
        (KeyCode::Char(c), KeyModifiers::NONE | KeyModifiers::SHIFT) => {
            app.input_buf.insert_char(c);
            app.scroll_offset = 0;
            app.palette_reset();
        },
        (KeyCode::Backspace, _) => {
            app.input_buf.backspace();
            app.palette_reset();
        },
        (KeyCode::Delete, _) => {
            app.input_buf.delete_forward();
            app.palette_reset();
        },

        // Cursor movement
        (KeyCode::Left, _) => {
            app.input_buf.move_left();
        },
        (KeyCode::Right, _) => {
            app.input_buf.move_right();
        },
        (KeyCode::Home, _) if key.modifiers.contains(KeyModifiers::CONTROL) => {
            app.scroll_offset = usize::MAX;
        },
        (KeyCode::End, _) if key.modifiers.contains(KeyModifiers::CONTROL) => {
            app.scroll_offset = 0;
        },
        (KeyCode::Home, _) => app.input_buf.move_home(),
        (KeyCode::End, _) => app.input_buf.move_end(),

        // Scrolling
        (KeyCode::PageUp, _) => {
            app.scroll_offset = app.scroll_offset.saturating_add(10);
        },
        (KeyCode::PageDown, _) => {
            app.scroll_offset = app.scroll_offset.saturating_sub(10);
        },
        (KeyCode::Up, _) if app.input_buf.is_empty() => {
            app.scroll_offset = app.scroll_offset.saturating_add(1);
        },
        (KeyCode::Down, _) if app.input_buf.is_empty() => {
            app.scroll_offset = app.scroll_offset.saturating_sub(1);
        },

        // Clear line
        (KeyCode::Char('u'), KeyModifiers::CONTROL) => {
            app.input_buf.clear();
            app.palette_reset();
        },

        // Toggle last tool expansion
        (KeyCode::Char('e'), KeyModifiers::CONTROL) => {
            if let Some(tool) = app.completed_tools.last_mut() {
                tool.expanded = !tool.expanded;
            }
        },

        _ => {},
    }

    // Any key except Ctrl+C/D resets quit confirmation
    app.quit_pending = false;
}

fn handle_approval_input(app: &mut App, key: KeyEvent) {
    if app.pending_approvals.is_empty() {
        return;
    }

    let id = app.pending_approvals[app
        .selected_approval
        .min(app.pending_approvals.len().saturating_sub(1))]
    .id
    .clone();

    match key.code {
        // Approve once
        KeyCode::Char('y' | 'Y') => {
            app.approve_tool(&id, ApprovalDecisionKind::Once);
        },
        // Approve session
        KeyCode::Char('s' | 'S') => {
            app.approve_tool(&id, ApprovalDecisionKind::Session);
        },
        // Approve always
        KeyCode::Char('a' | 'A') => {
            app.approve_tool(&id, ApprovalDecisionKind::Always);
        },
        // Deny
        KeyCode::Char('n' | 'N') | KeyCode::Esc => {
            app.deny_tool(&id);
        },
        // Navigate between approvals
        KeyCode::Tab | KeyCode::Down if !app.pending_approvals.is_empty() => {
            #[expect(clippy::arithmetic_side_effects)] // modulo by non-empty len is safe
            {
                app.selected_approval =
                    app.selected_approval.saturating_add(1) % app.pending_approvals.len();
            }
        },
        KeyCode::BackTab | KeyCode::Up if !app.pending_approvals.is_empty() => {
            app.selected_approval = app
                .selected_approval
                .checked_sub(1)
                .unwrap_or(app.pending_approvals.len().saturating_sub(1));
        },
        // Quit
        KeyCode::Char('c') if key.modifiers == KeyModifiers::CONTROL => {
            app.should_quit = true;
        },
        _ => {},
    }
}

fn handle_interruptible_input(app: &mut App, key: KeyEvent) {
    match (key.code, key.modifiers) {
        (KeyCode::Char('c'), KeyModifiers::CONTROL) | (KeyCode::Esc, _) => {
            app.state = UiState::Interrupted;
            app.stream_buffer.clear();
            app.pending_actions.push(PendingAction::CancelTurn);
        },
        _ => {},
    }
}

fn handle_interrupted_input(app: &mut App, key: KeyEvent) {
    match (key.code, key.modifiers) {
        (KeyCode::Char('c' | 'd'), KeyModifiers::CONTROL) => {
            if app.quit_pending {
                app.should_quit = true;
            } else {
                app.quit_pending = true;
            }
            return;
        },
        (KeyCode::Char(c), KeyModifiers::NONE | KeyModifiers::SHIFT) => {
            app.state = UiState::Idle;
            app.input_buf.insert_char(c);
        },
        _ => {
            app.state = UiState::Idle;
        },
    }
    app.quit_pending = false;
}

fn handle_copy_input(app: &mut App, key: KeyEvent) {
    match (key.code, key.modifiers) {
        // Navigate up
        (KeyCode::Up, _) => {
            app.copy_cursor = app.copy_cursor.saturating_sub(1);
        },
        // Navigate down
        (KeyCode::Down, _) if app.copy_cursor.saturating_add(1) < app.nexus_stream.len() => {
            app.copy_cursor = app.copy_cursor.saturating_add(1);
        },
        // Jump up by 5
        (KeyCode::PageUp, _) => {
            app.copy_cursor = app.copy_cursor.saturating_sub(5);
        },
        // Jump down by 5
        (KeyCode::PageDown, _) => {
            app.copy_cursor = app
                .copy_cursor
                .saturating_add(5)
                .min(app.nexus_stream.len().saturating_sub(1));
        },
        // Toggle selection on current entry
        (KeyCode::Char(' '), _) => {
            app.toggle_copy_selection();
        },
        // Select all
        (KeyCode::Char('a'), KeyModifiers::CONTROL) => {
            app.select_all_copy();
        },
        // Copy and exit
        (KeyCode::Enter, _) => {
            match app.copy_to_clipboard() {
                Ok(()) => {
                    app.copy_notice = Some(("Copied!".to_string(), std::time::Instant::now()));
                },
                Err(e) => {
                    app.copy_notice = Some((e, std::time::Instant::now()));
                },
            }
            app.exit_copy_mode();
        },
        // Cancel / quit copy mode
        (KeyCode::Esc, _) | (KeyCode::Char('c'), KeyModifiers::CONTROL) => {
            app.exit_copy_mode();
        },
        _ => {},
    }
}

fn handle_error_input(app: &mut App, key: KeyEvent) {
    match key.code {
        KeyCode::Enter | KeyCode::Esc => {
            app.state = UiState::Idle;
        },
        KeyCode::Char('c') if key.modifiers == KeyModifiers::CONTROL => {
            app.should_quit = true;
        },
        _ => {},
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_app() -> App {
        App::new("test".into(), "test-model".into(), "abc".into())
    }

    fn enter_key() -> KeyEvent {
        KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE)
    }

    fn char_key(c: char) -> KeyEvent {
        KeyEvent::new(KeyCode::Char(c), KeyModifiers::NONE)
    }

    fn esc_key() -> KeyEvent {
        KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE)
    }

    fn set_onboarding_with_array(app: &mut App) {
        use astrid_types::ipc::{OnboardingField, OnboardingFieldType};
        app.state = UiState::Onboarding {
            capsule_id: "test-capsule".into(),
            fields: vec![
                OnboardingField {
                    key: "relays".into(),
                    prompt: "Enter relay URLs".into(),
                    description: None,
                    field_type: OnboardingFieldType::Array,
                    default: None,
                    placeholder: None,
                },
                OnboardingField {
                    key: "name".into(),
                    prompt: "Enter name".into(),
                    description: None,
                    field_type: OnboardingFieldType::Text,
                    default: None,
                    placeholder: None,
                },
            ],
            current_idx: 0,
            answers: std::collections::HashMap::new(),
            enum_selected: 0,
            enum_scroll_offset: 0,
            current_array_items: Vec::new(),
        };
    }

    // ── Multi-line paste tests ──────────────────────────────────

    #[test]
    fn paste_multiline_creates_block_with_correct_line_count() {
        let mut app = make_app();
        let content = "line1\nline2\nline3";
        handle_paste(&mut app, content);
        assert!(app.input_buf.has_paste_blocks());
        assert_eq!(app.input_buf.paste_block_total_lines(), 3);
        assert_eq!(app.input_buf.flat_text(), content);
    }

    #[test]
    fn paste_multiline_backspace_deletes_entire_block() {
        let mut app = make_app();
        handle_paste(&mut app, "line1\nline2");
        assert!(app.input_buf.has_paste_blocks());
        // Cursor is on trailing Text after the block. Backspace deletes the block.
        app.input_buf.backspace();
        assert!(!app.input_buf.has_paste_blocks());
        assert!(app.input_buf.is_empty());
    }

    #[test]
    fn paste_home_key_lands_at_true_beginning_with_leading_paste() {
        let mut app = make_app();
        handle_paste(&mut app, "block\ncontent");
        app.input_buf.insert_char('z');
        app.input_buf.move_home();
        // Home should be at segment 0 offset 0 (a Text before the paste block).
        assert_eq!(app.input_buf.cursor, (0, 0));
        app.input_buf.insert_char('a');
        // 'a' should appear before the paste block.
        assert!(app.input_buf.flat_text().starts_with('a'));
    }

    #[test]
    fn paste_slash_command_cursor_offset_adjustment() {
        let mut app = make_app();
        // Type a slash command.
        app.input_buf.insert_char('/');
        app.input_buf.insert_char('h');
        app.input_buf.insert_char('e');
        app.input_buf.insert_char('l');
        app.input_buf.insert_char('p');
        assert_eq!(app.input_buf.flat_text(), "/help");
        // Move cursor to after the slash.
        app.input_buf.cursor.1 = 1;
        app.input_buf.insert_char('X');
        // 'X' inserted at byte offset 1 (after '/').
        assert_eq!(app.input_buf.flat_text(), "/Xhelp");
    }

    #[test]
    fn paste_large_multiline_triggers_truncation_notice() {
        let mut app = make_app();
        // Create a paste larger than MAX_PASTE_LEN (32768 bytes).
        let large = "x".repeat(40_000) + "\nsecond line";
        let original_len = large.len();
        handle_paste(&mut app, &large);
        // Should have a truncation notice in messages.
        let has_notice = app.messages.iter().any(|m| {
            m.content.contains("Paste too large") && m.content.contains(&original_len.to_string())
        });
        assert!(has_notice, "expected truncation notice with original size");
        // The paste block should exist but be truncated.
        assert!(app.input_buf.has_paste_blocks());
    }

    #[test]
    fn paste_single_line_uses_insert_str() {
        let mut app = make_app();
        handle_paste(&mut app, "hello world");
        // Single-line paste should NOT create a paste block.
        assert!(!app.input_buf.has_paste_blocks());
        assert_eq!(app.input_buf.flat_text(), "hello world");
        assert_eq!(app.input_buf.cursor, (0, 11));
    }

    #[test]
    fn paste_sanitizes_cr_and_null() {
        let mut app = make_app();
        handle_paste(&mut app, "line1\r\nline2\rline3\0end");
        let text = app.input_buf.flat_text();
        assert!(!text.contains('\r'));
        assert!(!text.contains('\0'));
        assert!(text.contains("line1\nline2"));
    }

    // ── Onboarding tests ─────────────────────────────────────────

    #[test]
    fn array_field_adds_items_on_enter() {
        let mut app = make_app();
        set_onboarding_with_array(&mut app);

        // Type "wss://relay1" and press Enter
        app.input_buf.set_text("wss://relay1".into());
        handle_onboarding_input(&mut app, enter_key());

        // Should still be on the same field, item added
        if let UiState::Onboarding {
            current_idx,
            current_array_items,
            ..
        } = &app.state
        {
            assert_eq!(*current_idx, 0, "should stay on same field");
            assert_eq!(current_array_items, &["wss://relay1"]);
        } else {
            panic!("expected Onboarding state");
        }

        // Add a second item
        app.input_buf.set_text("wss://relay2".into());
        handle_onboarding_input(&mut app, enter_key());

        if let UiState::Onboarding {
            current_array_items,
            ..
        } = &app.state
        {
            assert_eq!(current_array_items, &["wss://relay1", "wss://relay2"]);
        } else {
            panic!("expected Onboarding state");
        }
    }

    #[test]
    fn array_field_finalizes_on_empty_enter() {
        let mut app = make_app();
        set_onboarding_with_array(&mut app);

        // Add one item
        app.input_buf.set_text("wss://relay1".into());
        handle_onboarding_input(&mut app, enter_key());

        // Press Enter on empty to finalize
        handle_onboarding_input(&mut app, enter_key());

        if let UiState::Onboarding {
            current_idx,
            answers,
            current_array_items,
            ..
        } = &app.state
        {
            assert_eq!(*current_idx, 1, "should advance to next field");
            assert!(current_array_items.is_empty(), "items should be cleared");
            let stored = answers.get("relays").unwrap();
            assert_eq!(stored, r#"["wss://relay1"]"#);
        } else {
            panic!("expected Onboarding state");
        }
    }

    #[test]
    fn array_field_empty_array_stores_empty_json() {
        let mut app = make_app();
        set_onboarding_with_array(&mut app);

        // Press Enter immediately with empty input to finalize empty array
        handle_onboarding_input(&mut app, enter_key());

        if let UiState::Onboarding {
            current_idx,
            answers,
            ..
        } = &app.state
        {
            assert_eq!(*current_idx, 1);
            assert_eq!(answers.get("relays").unwrap(), "[]");
        } else {
            panic!("expected Onboarding state");
        }
    }

    #[test]
    fn non_array_field_submits_immediately() {
        let mut app = make_app();
        set_onboarding_with_array(&mut app);

        // Skip the array field with empty array
        handle_onboarding_input(&mut app, enter_key());

        // Now on "name" (string type), type a value and press Enter
        app.input_buf.set_text("my-name".into());
        handle_onboarding_input(&mut app, enter_key());

        // Should have submitted onboarding (both fields done)
        assert!(
            matches!(app.state, UiState::Idle),
            "should transition to Idle after all fields"
        );
        assert_eq!(app.pending_actions.len(), 1);
        if let PendingAction::SubmitOnboarding { answers, .. } = &app.pending_actions[0] {
            assert_eq!(answers.get("name").unwrap(), "my-name");
            assert_eq!(answers.get("relays").unwrap(), "[]");
        } else {
            panic!("expected SubmitOnboarding action");
        }
    }

    #[test]
    fn onboarding_esc_cancels_typed_input() {
        let mut app = make_app();
        set_onboarding_with_array(&mut app);

        // Type a character but don't submit, then cancel
        app.input_buf.set_text("item1".into());
        handle_onboarding_input(&mut app, char_key('x'));
        handle_onboarding_input(&mut app, esc_key());

        assert!(matches!(app.state, UiState::Idle));
        assert!(app.input_buf.is_empty());
    }

    #[test]
    fn onboarding_esc_cancels_after_accumulated_items() {
        let mut app = make_app();
        set_onboarding_with_array(&mut app);

        // Add two items via Enter
        app.input_buf.set_text("wss://relay1".into());
        handle_onboarding_input(&mut app, enter_key());

        app.input_buf.set_text("wss://relay2".into());
        handle_onboarding_input(&mut app, enter_key());

        // Verify items accumulated
        if let UiState::Onboarding {
            current_array_items,
            ..
        } = &app.state
        {
            assert_eq!(current_array_items.len(), 2);
        } else {
            panic!("expected Onboarding state");
        }

        // Esc should discard everything (state dropped)
        handle_onboarding_input(&mut app, esc_key());

        assert!(matches!(app.state, UiState::Idle));
        assert!(app.pending_actions.is_empty(), "no submit action on cancel");
    }

    #[test]
    fn array_field_capped_by_terminal_height() {
        let mut app = make_app();
        set_onboarding_with_array(&mut app);
        // Default terminal_height is 24, 2 keys in onboarding
        // max_array_items(24, 2) = 24/3 - (2+2) = 4
        let cap = max_array_items(app.terminal_height, 2);
        assert_eq!(cap, 4);

        // Pre-fill to the cap
        if let UiState::Onboarding {
            current_array_items,
            ..
        } = &mut app.state
        {
            for i in 0..cap {
                current_array_items.push(format!("item{i}"));
            }
        }

        // Next item should be rejected
        app.input_buf.set_text("one-too-many".into());
        handle_onboarding_input(&mut app, enter_key());

        if let UiState::Onboarding {
            current_array_items,
            ..
        } = &app.state
        {
            assert_eq!(current_array_items.len(), cap, "should not exceed cap");
        } else {
            panic!("expected Onboarding state");
        }

        // Should have a notice about the cap
        assert!(
            app.messages.iter().any(|m| m.content.contains("limit")),
            "should show cap notice"
        );
    }

    #[test]
    fn array_cap_scales_with_terminal_height() {
        // Tall terminal (60 rows, 2 keys): 60/3 - 4 = 16
        assert_eq!(max_array_items(60, 2), 16);
        // Short terminal (18 rows, 2 keys): 18/3 - 4 = 2
        assert_eq!(max_array_items(18, 2), 2);
        // Very short terminal (9 rows, 2 keys): 9/3 - 4 = 0 -> clamped to 1
        assert_eq!(max_array_items(9, 2), 1);
        // Many keys (24 rows, 8 keys): 24/3 - 10 = 0 -> clamped to 1
        assert_eq!(max_array_items(24, 8), 1);
    }

    #[test]
    fn array_items_with_special_chars_serialize_correctly() {
        let mut app = make_app();
        set_onboarding_with_array(&mut app);

        // Add items with quotes and special characters
        app.input_buf.set_text(r#"value with "quotes""#.into());
        handle_onboarding_input(&mut app, enter_key());

        app.input_buf.set_text("value,with,commas".into());
        handle_onboarding_input(&mut app, enter_key());

        // Finalize
        handle_onboarding_input(&mut app, enter_key());

        if let UiState::Onboarding { answers, .. } = &app.state {
            let stored = answers.get("relays").unwrap();
            let parsed: Vec<String> = serde_json::from_str(stored).unwrap();
            assert_eq!(parsed.len(), 2);
            assert_eq!(parsed[0], r#"value with "quotes""#);
            assert_eq!(parsed[1], "value,with,commas");
        } else {
            panic!("expected Onboarding state");
        }
    }

    #[test]
    fn consecutive_array_fields_clear_items_between() {
        let mut app = make_app();
        // Two array fields back-to-back
        app.state = UiState::Onboarding {
            capsule_id: "test".into(),
            fields: vec![
                astrid_types::ipc::OnboardingField {
                    key: "relays".into(),
                    prompt: "Relays".into(),
                    description: None,
                    field_type: astrid_types::ipc::OnboardingFieldType::Array,
                    default: None,
                    placeholder: None,
                },
                astrid_types::ipc::OnboardingField {
                    key: "peers".into(),
                    prompt: "Peers".into(),
                    description: None,
                    field_type: astrid_types::ipc::OnboardingFieldType::Array,
                    default: None,
                    placeholder: None,
                },
            ],
            current_idx: 0,
            answers: std::collections::HashMap::new(),
            enum_selected: 0,
            enum_scroll_offset: 0,
            current_array_items: Vec::new(),
        };
        app.terminal_height = 60;

        // Add items to first array
        app.input_buf.set_text("relay1".into());
        handle_onboarding_input(&mut app, enter_key());

        // Finalize first array
        handle_onboarding_input(&mut app, enter_key());

        // Should now be on second array with clean items
        if let UiState::Onboarding {
            current_idx,
            current_array_items,
            answers,
            ..
        } = &app.state
        {
            assert_eq!(*current_idx, 1);
            assert!(
                current_array_items.is_empty(),
                "array items should be cleared for next field"
            );
            assert_eq!(answers.get("relays").unwrap(), r#"["relay1"]"#);
        } else {
            panic!("expected Onboarding state");
        }
    }

    // ─── handle_paste integration tests ───────────────────────────

    #[test]
    fn paste_single_line_inserts_as_text() {
        let mut app = make_app();
        app.state = UiState::Idle;
        handle_paste(&mut app, "hello world");
        assert_eq!(app.input_buf.flat_text(), "hello world");
        assert!(!app.input_buf.has_paste_blocks());
    }

    #[test]
    fn paste_multi_line_creates_paste_block() {
        let mut app = make_app();
        app.state = UiState::Idle;
        handle_paste(&mut app, "line1\nline2\nline3");
        assert!(app.input_buf.has_paste_blocks());
        assert_eq!(app.input_buf.flat_text(), "line1\nline2\nline3");
    }

    #[test]
    fn paste_normalizes_crlf_in_multi_line() {
        let mut app = make_app();
        app.state = UiState::Idle;
        handle_paste(&mut app, "line1\r\nline2\r\n");
        assert_eq!(app.input_buf.flat_text(), "line1\nline2\n");
    }

    #[test]
    fn paste_strips_null_bytes_in_multi_line() {
        let mut app = make_app();
        app.state = UiState::Idle;
        handle_paste(&mut app, "a\0b\nc\0d");
        assert_eq!(app.input_buf.flat_text(), "ab\ncd");
    }

    #[test]
    fn paste_single_line_strips_cr_and_null() {
        let mut app = make_app();
        app.state = UiState::Idle;
        handle_paste(&mut app, "foo\rbar\0baz");
        assert_eq!(app.input_buf.flat_text(), "foobarbaz");
    }

    #[test]
    fn paste_in_non_input_state_is_dropped() {
        let mut app = make_app();
        app.state = UiState::Thinking {
            start_time: std::time::Instant::now(),
            dots: 0,
        };
        handle_paste(&mut app, "should not appear");
        assert!(app.input_buf.is_empty());
    }

    #[test]
    fn paste_in_interrupted_transitions_to_idle() {
        let mut app = make_app();
        app.state = UiState::Interrupted;
        handle_paste(&mut app, "after interrupt");
        assert!(matches!(app.state, UiState::Idle));
        assert_eq!(app.input_buf.flat_text(), "after interrupt");
    }

    #[test]
    fn paste_resets_quit_pending() {
        let mut app = make_app();
        app.state = UiState::Idle;
        app.quit_pending = true;
        handle_paste(&mut app, "text");
        assert!(!app.quit_pending);
    }

    #[test]
    fn paste_multi_line_rejected_in_slash_command() {
        let mut app = make_app();
        app.state = UiState::Idle;
        app.input_buf.set_text("/command".into());
        handle_paste(&mut app, "line1\nline2");
        // Should still be just the slash command text, paste rejected.
        assert_eq!(app.input_buf.flat_text(), "/command");
        assert!(
            app.messages
                .iter()
                .any(|m| m.content.contains("Multi-line paste not supported")),
        );
    }

    #[test]
    fn paste_empty_string_is_noop() {
        let mut app = make_app();
        app.state = UiState::Idle;
        handle_paste(&mut app, "");
        assert!(app.input_buf.is_empty());
    }

    #[test]
    fn paste_single_line_truncated_at_max() {
        let mut app = make_app();
        app.state = UiState::Idle;
        let big = "x".repeat(MAX_PASTE_LEN + 100);
        handle_paste(&mut app, &big);
        assert_eq!(app.input_buf.flat_text().len(), MAX_PASTE_LEN);
        assert!(app.messages.iter().any(|m| m.content.contains("Truncated")),);
    }

    #[test]
    fn paste_multi_line_truncated_at_max() {
        let mut app = make_app();
        app.state = UiState::Idle;
        let big = "line\n".repeat(MAX_PASTE_LEN);
        handle_paste(&mut app, &big);
        assert!(app.input_buf.flat_text().len() <= MAX_PASTE_LEN);
        assert!(app.messages.iter().any(|m| m.content.contains("Truncated")),);
    }

    #[test]
    fn paste_multi_line_strips_bare_cr() {
        let mut app = make_app();
        app.state = UiState::Idle;
        handle_paste(&mut app, "foo\r\nbar\rbaz\n");
        // \r\n -> \n, bare \r removed
        assert_eq!(app.input_buf.flat_text(), "foo\nbarbaz\n");
    }

    #[test]
    fn paste_multi_line_rejected_in_secret_field() {
        let mut app = make_app();
        app.state = UiState::Onboarding {
            capsule_id: "test".into(),
            fields: vec![astrid_types::ipc::OnboardingField {
                key: "api_key".into(),
                prompt: "Enter API key".into(),
                description: None,
                field_type: astrid_types::ipc::OnboardingFieldType::Secret,
                default: None,
                placeholder: None,
            }],
            current_idx: 0,
            answers: std::collections::HashMap::new(),
            enum_selected: 0,
            enum_scroll_offset: 0,
            current_array_items: Vec::new(),
        };
        handle_paste(&mut app, "line1\nline2");
        // Multi-line paste rejected, input unchanged.
        assert!(app.input_buf.is_empty());
        assert!(
            app.messages
                .iter()
                .any(|m| m.content.contains("not supported in this field type")),
        );
    }

    #[test]
    fn paste_multi_line_rejected_in_array_field() {
        let mut app = make_app();
        set_onboarding_with_array(&mut app);
        handle_paste(&mut app, "url1\nurl2\nurl3");
        assert!(app.input_buf.is_empty());
        assert!(
            app.messages
                .iter()
                .any(|m| m.content.contains("not supported in this field type")),
        );
    }

    #[test]
    fn array_field_default_not_prefilled() {
        let mut app = make_app();
        app.state = UiState::Onboarding {
            capsule_id: "test".into(),
            fields: vec![astrid_types::ipc::OnboardingField {
                key: "relays".into(),
                prompt: "Relays".into(),
                description: None,
                field_type: astrid_types::ipc::OnboardingFieldType::Array,
                default: Some(r#"["a","b"]"#.into()),
                placeholder: None,
            }],
            current_idx: 0,
            answers: std::collections::HashMap::new(),
            enum_selected: 0,
            enum_scroll_offset: 0,
            current_array_items: Vec::new(),
        };

        // Simulate what advance_onboarding does on field entry
        advance_onboarding(&mut app);

        // Array fields should NOT have the default pre-filled in input
        assert!(
            app.input_buf.is_empty(),
            "array field should start with empty input, not pre-filled default"
        );
    }
}
