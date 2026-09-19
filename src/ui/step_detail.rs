use super::{ACCENT, DIM};
use crate::app::{App, Focus};
use crate::catalog::{OptionKind, STEPS};
use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph, Wrap};

pub fn render(frame: &mut Frame, app: &App, area: Rect) {
    let step = &STEPS[app.selected];
    let focused = app.focus == Focus::Options;
    let mut lines = Vec::new();

    if let Some(tool) = step.tool {
        let (text, style) = if app.missing_tools.contains(tool) {
            (
                format!("`{tool}` is not installed: this step will be skipped"),
                Style::default().fg(Color::Red),
            )
        } else {
            (format!("wraps `{tool}`"), Style::default().fg(DIM))
        };
        lines.push(Line::from(Span::styled(text, style)));
    } else {
        let optional: Vec<&str> = step.options.iter().filter_map(|o| o.tool).collect();
        let text = if optional.is_empty() {
            "native (goblin / Rust)".to_string()
        } else {
            format!("native (Rust), optional tools: {}", optional.join(", "))
        };
        lines.push(Line::from(Span::styled(text, Style::default().fg(DIM))));
    }
    lines.push(Line::from(""));

    for (i, opt) in step.options.iter().enumerate() {
        let checked = app.checked[app.selected][i];
        let highlighted = focused && app.selected_right == i;
        let missing = opt.tool.is_some_and(|t| app.missing_tools.contains(t));
        let style = if highlighted {
            Style::default().fg(Color::Black).bg(Color::White)
        } else if missing {
            Style::default().fg(DIM)
        } else if checked {
            Style::default()
                .fg(Color::White)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(Color::White)
        };
        let box_char = if checked { "\u{25a3}" } else { "\u{25a2}" };
        let mut spans = vec![Span::styled(format!("{box_char} {}", opt.label), style)];
        match opt.kind {
            OptionKind::Value { hint, .. } => {
                let value = &app.values[app.selected][i];
                let extra = if checked {
                    format!("  = {value}")
                } else if value.is_empty() {
                    format!("  ({hint})")
                } else {
                    format!("  (default: {value})")
                };
                spans.push(Span::styled(
                    extra,
                    if highlighted {
                        style
                    } else {
                        Style::default().fg(ACCENT)
                    },
                ));
            }
            OptionKind::Flag => {}
        }
        if let Some(tool) = opt.tool {
            let note = if missing {
                format!("  [{tool} missing]")
            } else {
                format!("  [{tool}]")
            };
            spans.push(Span::styled(
                note,
                if highlighted {
                    style
                } else {
                    Style::default().fg(DIM)
                },
            ));
        }
        if app.show_commands {
            spans.push(Span::styled(
                format!("   \u{2192} {}", opt.cmd),
                if highlighted {
                    style
                } else {
                    Style::default().fg(Color::Magenta)
                },
            ));
        }
        lines.push(Line::from(spans));
    }

    if app.show_commands {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            "would run with the current options:",
            Style::default().fg(Color::Yellow),
        )));
        if app.preview.is_empty() {
            lines.push(Line::from(Span::styled(
                format!("  {}", app.preview_note),
                Style::default().fg(DIM),
            )));
        }
        for cmd in &app.preview {
            lines.push(Line::from(Span::styled(
                format!("  $ {cmd}"),
                Style::default().fg(Color::Magenta),
            )));
        }
    }

    lines.push(Line::from(""));
    let hint = if app.results[app.selected].is_some() {
        "space: run again   o: show last output"
    } else if app.checked[app.selected].iter().any(|c| *c) {
        "space: run with the checked options"
    } else {
        "space: run with defaults (nothing checked)"
    };
    lines.push(Line::from(Span::styled(hint, Style::default().fg(DIM))));

    let border = if focused {
        Style::default().fg(ACCENT)
    } else {
        Style::default().fg(DIM)
    };
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(border)
        .title(format!(" {}. {} ", app.selected + 1, step.title));
    frame.render_widget(
        Paragraph::new(lines)
            .wrap(Wrap { trim: false })
            .block(block),
        area,
    );
}
