mod overlays;
mod report_view;
mod step_detail;
mod step_list;

use crate::app::{App, Focus, Mode, PickerPurpose};
use crate::picker::pretty_path;
use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;

pub const ACCENT: Color = Color::LightBlue;
pub const DIM: Color = Color::DarkGray;

pub fn render(frame: &mut Frame, app: &App) {
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),
            Constraint::Min(5),
            Constraint::Length(1),
        ])
        .split(frame.area());

    render_title(frame, app, rows[0]);

    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Length(22), Constraint::Min(30)])
        .split(rows[1]);

    step_list::render(frame, app, cols[0]);
    if app.focus == Focus::Output {
        report_view::render(frame, app, cols[1]);
    } else {
        step_detail::render(frame, app, cols[1]);
    }

    render_help(frame, app, rows[2]);

    match &app.mode {
        Mode::Normal => {}
        Mode::ValueInput { step, opt, buffer } => overlays::value_input(frame, *step, *opt, buffer),
        Mode::FilePicker { picker, purpose } => overlays::file_picker(frame, picker, *purpose),
        Mode::Doctor { doctor, selected } => overlays::doctor(frame, doctor, *selected),
        Mode::Presets { selected } => overlays::presets(frame, app, *selected),
        Mode::Search { buffer } => overlays::prompt(
            frame,
            " search in output ",
            buffer,
            "case-insensitive, n / N to move between matches",
        ),
        Mode::Hex(view) => overlays::hex(frame, view, None),
        Mode::HexGoto { view, buffer } => overlays::hex(frame, view, Some(buffer)),
        Mode::Triage {
            dir,
            rows,
            selected,
        } => overlays::triage(frame, dir, rows, *selected),
    }
}

fn render_title(frame: &mut Frame, app: &App, area: Rect) {
    let mut spans = vec![
        Span::styled(
            " BinScout ",
            Style::default()
                .fg(Color::Black)
                .bg(ACCENT)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw("  "),
    ];
    match &app.target {
        Some(t) => {
            spans.push(Span::styled("target ", Style::default().fg(DIM)));
            spans.push(Span::styled(
                pretty_path(t, area.width.saturating_sub(50) as usize),
                Style::default()
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD),
            ));
            if let Ok(meta) = std::fs::metadata(t) {
                spans.push(Span::styled(
                    format!("  {}", crate::analysis::human_size(meta.len())),
                    Style::default().fg(DIM),
                ));
            }
        }
        None => spans.push(Span::styled(
            "no target: press @ to pick a file",
            Style::default().fg(Color::Yellow),
        )),
    }
    if let Some((dir, _)) = &app.triage_job {
        spans.push(Span::styled(
            format!("   triaging {}...", dir.display()),
            Style::default().fg(Color::Yellow),
        ));
    }
    if let Some(r) = &app.running {
        let spinner = [
            '\u{280b}', '\u{2819}', '\u{2839}', '\u{2838}', '\u{283c}', '\u{2834}', '\u{2826}',
            '\u{2827}', '\u{2807}', '\u{280f}',
        ];
        let idx = (r.started.elapsed().as_millis() / 80) as usize % spinner.len();
        spans.push(Span::styled(
            format!(
                "   {} running {} ({}s)",
                spinner[idx],
                crate::catalog::step(r.step).name,
                r.started.elapsed().as_secs()
            ),
            Style::default().fg(Color::Yellow),
        ));
        if !app.queue.is_empty() {
            spans.push(Span::styled(
                format!(" (+{} queued)", app.queue.len()),
                Style::default().fg(DIM),
            ));
        }
    }
    frame.render_widget(Paragraph::new(Line::from(spans)), area);
}

fn render_help(frame: &mut Frame, app: &App, area: Rect) {
    let keys: &[(&str, &str)] = match &app.mode {
        Mode::ValueInput { .. } | Mode::Search { .. } => &[
            ("type", "value"),
            ("\u{21b5}", "confirm"),
            ("esc", "cancel"),
            ("^u", "clear"),
        ],
        Mode::Doctor { .. } => &[
            ("\u{2191}\u{2193}", "select"),
            ("\u{21b5}", "install selected"),
            ("a", "install all missing"),
            ("esc", "close"),
        ],
        Mode::Presets { .. } => &[
            ("\u{2191}\u{2193}", "select"),
            ("\u{21b5}", "apply"),
            ("r", "apply and run"),
            ("esc", "close"),
        ],
        Mode::Hex(_) => &[
            ("\u{2191}\u{2193}\u{2190}\u{2192} pgup pgdn", "move"),
            ("g", "go to offset"),
            ("home/end", "start/end"),
            ("esc", "close"),
        ],
        Mode::HexGoto { .. } => &[
            ("type", "offset (0x.. or decimal)"),
            ("\u{21b5}", "go"),
            ("esc", "back"),
        ],
        Mode::Triage { .. } => &[
            ("\u{2191}\u{2193}", "select"),
            ("\u{21b5}", "analyze this file"),
            ("esc", "close"),
        ],
        Mode::FilePicker { purpose, .. } => match purpose {
            PickerPurpose::Target => &[
                ("type", "filter"),
                ("\u{2191}\u{2193}", "select"),
                ("\u{21b5}", "choose"),
                ("esc", "cancel"),
                ("/ or ~", "absolute path"),
            ],
            PickerPurpose::CompareWith => &[
                ("type", "filter"),
                ("\u{2191}\u{2193}", "select"),
                ("\u{21b5}", "compare with"),
                ("esc", "cancel"),
            ],
        },
        Mode::Normal => match app.focus {
            Focus::Steps => &[
                ("\u{2191}\u{2193}", "move"),
                ("\u{21b5}", "options"),
                ("space", "run"),
                ("v", "commands"),
                ("r", "run checked"),
                ("p", "presets"),
                ("@", "file"),
                ("c", "compare"),
                ("x", "hex"),
                ("t", "triage dir"),
                ("i", "doctor"),
                ("q", "quit"),
            ],
            Focus::Options => &[
                ("\u{2191}\u{2193}", "move"),
                ("\u{21b5}", "toggle"),
                ("\u{2190}", "steps"),
                ("space", "run"),
                ("v", "commands"),
                ("o", "output"),
                ("p", "presets"),
                ("@", "file"),
                ("q", "quit"),
            ],
            Focus::Output => &[
                ("\u{2191}\u{2193} pgup pgdn", "scroll"),
                ("/", "search"),
                ("n N", "next/prev"),
                ("e", "editor"),
                ("y", "copy"),
                ("esc", "options"),
                ("space", "rerun"),
                ("q", "quit"),
            ],
        },
    };
    let mut spans = Vec::new();
    for (k, v) in keys {
        spans.push(Span::styled(
            format!(" {k} "),
            Style::default().fg(Color::Black).bg(DIM),
        ));
        spans.push(Span::styled(
            format!(" {v}   "),
            Style::default().fg(ACCENT),
        ));
    }
    let help_line = Line::from(spans);

    let help_width = help_line.width() as u16;
    // Key hints are the priority: the status message only gets the leftover width.
    let status_width = area.width.saturating_sub(help_width + 2);
    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Length(help_width), Constraint::Min(0)])
        .split(area);
    frame.render_widget(Paragraph::new(help_line), cols[0]);
    if status_width >= 12 {
        let status: String = app.status.chars().take(status_width as usize - 1).collect();
        frame.render_widget(
            Paragraph::new(Span::styled(format!(" {status}"), Style::default().fg(DIM))),
            cols[1],
        );
    }
}

pub fn centered(area: Rect, pct_x: u16, pct_y: u16) -> Rect {
    let v = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - pct_y) / 2),
            Constraint::Percentage(pct_y),
            Constraint::Percentage((100 - pct_y) / 2),
        ])
        .split(area);
    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - pct_x) / 2),
            Constraint::Percentage(pct_x),
            Constraint::Percentage((100 - pct_x) / 2),
        ])
        .split(v[1])[1]
}
