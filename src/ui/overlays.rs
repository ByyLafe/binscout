use super::{ACCENT, DIM, centered};
use crate::app::{App, PickerPurpose};
use crate::catalog::{OptionKind, STEPS};
use crate::hex::{BYTES_PER_ROW, HexView};
use crate::picker::FilePicker;
use crate::triage;
use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, Paragraph, Wrap};

pub fn value_input(frame: &mut Frame, step: usize, opt: usize, buffer: &str) {
    let def = &STEPS[step].options[opt];
    let hint = match def.kind {
        OptionKind::Value { hint, .. } => hint,
        OptionKind::Flag => "",
    };
    let area = frame.area();
    let width = area.width.clamp(20, 70);
    let rect = Rect {
        x: area.x + (area.width.saturating_sub(width)) / 2,
        y: area.y + area.height / 2 - 2,
        width,
        height: 5,
    };
    frame.render_widget(Clear, rect);
    let lines = vec![
        Line::from(Span::styled(
            format!(" {}", def.label),
            Style::default().fg(Color::White),
        )),
        Line::from(vec![
            Span::styled(" > ", Style::default().fg(ACCENT)),
            Span::styled(
                buffer.to_string(),
                Style::default()
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled("\u{2588}", Style::default().fg(ACCENT)),
        ]),
        Line::from(Span::styled(format!(" {hint}"), Style::default().fg(DIM))),
    ];
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(ACCENT))
        .title(" value ");
    frame.render_widget(
        Paragraph::new(lines)
            .wrap(Wrap { trim: false })
            .block(block),
        rect,
    );
}

pub fn file_picker(frame: &mut Frame, picker: &FilePicker, purpose: PickerPurpose) {
    let rect = centered(frame.area(), 80, 80);
    frame.render_widget(Clear, rect);
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(ACCENT))
        .title(match purpose {
            PickerPurpose::Target => " pick the file to analyze (@) ",
            PickerPurpose::CompareWith => " pick the file to compare with (c) ",
        });
    let inner = block.inner(rect);
    frame.render_widget(block, rect);

    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Min(1),
        ])
        .split(inner);

    let prompt = Line::from(vec![
        Span::styled("@ ", Style::default().fg(ACCENT)),
        Span::styled(
            picker.query.clone(),
            Style::default()
                .fg(Color::White)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled("\u{2588}", Style::default().fg(ACCENT)),
    ]);
    frame.render_widget(Paragraph::new(prompt), rows[0]);

    let scope = format!(
        "in {}  {} match(es){}",
        picker.root.display(),
        picker.results.len(),
        if picker.truncated {
            "  (index truncated: narrow the path)"
        } else {
            ""
        }
    );
    frame.render_widget(
        Paragraph::new(Span::styled(scope, Style::default().fg(DIM))),
        rows[1],
    );

    let height = rows[2].height as usize;
    let offset = picker.selected.saturating_sub(height.saturating_sub(1));
    let lines: Vec<Line> = picker
        .results
        .iter()
        .enumerate()
        .skip(offset)
        .take(height)
        .map(|(i, rel)| {
            let style = if i == picker.selected {
                Style::default().fg(Color::Black).bg(Color::White)
            } else {
                Style::default().fg(Color::White)
            };
            Line::from(Span::styled(format!(" {}", picker.display(rel)), style))
        })
        .collect();
    let lines = if lines.is_empty() {
        vec![Line::from(Span::styled(
            " no match (type / or ~ to search elsewhere)",
            Style::default().fg(DIM),
        ))]
    } else {
        lines
    };
    frame.render_widget(Paragraph::new(lines), rows[2]);
}

pub fn doctor(frame: &mut Frame, doctor: &crate::doctor::Doctor, selected: usize) {
    let rect = centered(frame.area(), 84, 70);
    frame.render_widget(Clear, rect);
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(ACCENT))
        .title(" doctor: external tools ");
    let inner = block.inner(rect);
    frame.render_widget(block, rect);

    let sys = &doctor.system;
    let mut lines = vec![
        Line::from(vec![
            Span::styled(" system   ", Style::default().fg(DIM)),
            Span::styled(
                format!("{} ({})", sys.os, sys.kernel),
                Style::default().fg(Color::White),
            ),
        ]),
        Line::from(vec![
            Span::styled(" packages ", Style::default().fg(DIM)),
            Span::styled(
                sys.package_manager
                    .map(|p| p.name())
                    .unwrap_or("no package manager detected"),
                Style::default().fg(Color::White),
            ),
            Span::styled("   python ", Style::default().fg(DIM)),
            Span::styled(
                sys.python_installer.unwrap_or("no pip/pipx detected"),
                Style::default().fg(Color::White),
            ),
        ]),
        Line::from(""),
    ];

    for (i, t) in doctor.tools.iter().enumerate() {
        let highlighted = i == selected;
        let (mark, mark_style) = if t.installed() {
            ("\u{2713}", Style::default().fg(Color::Green))
        } else {
            ("\u{2717}", Style::default().fg(Color::Red))
        };
        let row_style = if highlighted {
            Style::default().fg(Color::Black).bg(Color::White)
        } else {
            Style::default().fg(Color::White)
        };
        let detail = match (&t.path, &t.install) {
            (Some(p), _) => p.display().to_string(),
            (None, Some(cmd)) => format!("$ {cmd}"),
            (None, None) => "no known install method for this system".to_string(),
        };
        let detail_style = if highlighted {
            row_style
        } else if t.installed() {
            Style::default().fg(DIM)
        } else {
            Style::default().fg(ACCENT)
        };
        lines.push(Line::from(vec![
            Span::styled(
                format!(" {mark} "),
                if highlighted { row_style } else { mark_style },
            ),
            Span::styled(
                format!(
                    "{:<9}{:<40}",
                    t.def.name,
                    if t.def.optional {
                        format!("{} (optional)", t.def.purpose)
                    } else {
                        t.def.purpose.to_string()
                    }
                ),
                row_style,
            ),
            Span::styled(detail, detail_style),
        ]));
    }

    lines.push(Line::from(""));
    let missing = doctor.missing();
    let summary = if missing.is_empty() {
        Span::styled(
            " all tools are installed",
            Style::default().fg(Color::Green),
        )
    } else {
        Span::styled(
            format!(
                " {} missing. Enter installs the selected tool, `a` installs all of them (sudo may ask for your password).",
                missing.len()
            ),
            Style::default().fg(Color::Yellow),
        )
    };
    lines.push(Line::from(summary));
    if let Some(cmd) = doctor.install_all_command() {
        lines.push(Line::from(Span::styled(
            format!(" $ {cmd}"),
            Style::default().fg(DIM),
        )));
    }
    if sys
        .python_installer
        .is_some_and(|p| p.starts_with("pipx") || p.contains("--user"))
    {
        lines.push(Line::from(Span::styled(
            " Python tools land in ~/.local/bin: make sure it is in your PATH (pipx ensurepath).",
            Style::default().fg(DIM),
        )));
    }
    lines.push(Line::from(Span::styled(
        " Native steps (hashes, entropy, sections, mitigations) need no external tool.",
        Style::default().fg(DIM),
    )));

    frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), inner);
}

pub fn prompt(frame: &mut Frame, title: &str, buffer: &str, hint: &str) {
    let area = frame.area();
    let width = area.width.clamp(20, 70);
    let rect = Rect {
        x: area.x + (area.width.saturating_sub(width)) / 2,
        y: area.y + area.height / 2 - 2,
        width,
        height: 4,
    };
    frame.render_widget(Clear, rect);
    let lines = vec![
        Line::from(vec![
            Span::styled(" > ", Style::default().fg(ACCENT)),
            Span::styled(
                buffer.to_string(),
                Style::default()
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled("\u{2588}", Style::default().fg(ACCENT)),
        ]),
        Line::from(Span::styled(format!(" {hint}"), Style::default().fg(DIM))),
    ];
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(ACCENT))
        .title(title.to_string());
    frame.render_widget(Paragraph::new(lines).block(block), rect);
}

pub fn presets(frame: &mut Frame, app: &App, selected: usize) {
    let rect = centered(frame.area(), 70, 60);
    frame.render_widget(Clear, rect);
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(ACCENT))
        .title(" presets (p) ");
    let inner = block.inner(rect);
    frame.render_widget(block, rect);
    let mut lines = Vec::new();
    for (i, p) in app.presets.iter().enumerate() {
        let n: usize = p
            .checked
            .iter()
            .map(|s| s.iter().filter(|c| **c).count())
            .sum();
        let style = if i == selected {
            Style::default().fg(Color::Black).bg(Color::White)
        } else {
            Style::default().fg(Color::White)
        };
        lines.push(Line::from(vec![
            Span::styled(
                format!(" {:<10}", p.name),
                style.add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                format!(" {:<3} options  ", n),
                if i == selected {
                    style
                } else {
                    Style::default().fg(DIM)
                },
            ),
            Span::styled(
                p.description.clone(),
                if i == selected {
                    style
                } else {
                    Style::default().fg(DIM)
                },
            ),
        ]));
    }
    if let Some(p) = app.presets.get(selected) {
        lines.push(Line::from(""));
        for (s, step) in crate::catalog::STEPS.iter().enumerate() {
            let opts: Vec<&str> = step
                .options
                .iter()
                .enumerate()
                .filter(|(i, _)| p.checked[s][*i])
                .map(|(_, o)| o.label.split(" \u{2014} ").next().unwrap_or(o.label))
                .collect();
            if !opts.is_empty() {
                let text: String = opts
                    .join(", ")
                    .chars()
                    .take(inner.width.saturating_sub(20) as usize)
                    .collect();
                lines.push(Line::from(vec![
                    Span::styled(format!(" {:<16}", step.name), Style::default().fg(ACCENT)),
                    Span::styled(text, Style::default().fg(Color::White)),
                ]));
            }
        }
    }
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        format!(
            " add your own in {}  ([presets.<name>] tables)",
            crate::config::config_path()
                .map(|p| p.display().to_string())
                .unwrap_or_default()
        ),
        Style::default().fg(DIM),
    )));
    frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), inner);
}

pub fn hex(frame: &mut Frame, view: &HexView, goto: Option<&str>) {
    let rect = centered(frame.area(), 90, 90);
    frame.render_widget(Clear, rect);
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(ACCENT))
        .title(format!(
            " hex: {} \u{2014} 0x{:08x} / 0x{:x} ({} bytes) ",
            view.path
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default(),
            view.cursor,
            view.len,
            view.len
        ));
    let inner = block.inner(rect);
    frame.render_widget(block, rect);

    let rows = inner.height.saturating_sub(1) as usize;

    let mut v = HexView {
        path: view.path.clone(),
        len: view.len,
        offset: view.offset,
        cursor: view.cursor,
        rows: rows.max(1),
    };
    let window = v.rows as u64 * BYTES_PER_ROW;
    if v.cursor >= v.offset + window {
        v.offset = v.cursor - v.cursor % BYTES_PER_ROW + BYTES_PER_ROW - window;
    }
    let data = v.read_window();
    let mut lines = Vec::new();
    for (r, chunk) in data.chunks(BYTES_PER_ROW as usize).enumerate() {
        let base = v.offset + r as u64 * BYTES_PER_ROW;
        let mut spans = vec![Span::styled(
            format!("{base:08x}  "),
            Style::default().fg(DIM),
        )];
        for (i, b) in chunk.iter().enumerate() {
            let abs = base + i as u64;
            let style = if abs == v.cursor {
                Style::default().fg(Color::Black).bg(Color::White)
            } else if *b == 0 {
                Style::default().fg(DIM)
            } else if b.is_ascii_graphic() || *b == b' ' {
                Style::default().fg(Color::Green)
            } else {
                Style::default().fg(Color::White)
            };
            spans.push(Span::styled(format!("{b:02x}"), style));
            spans.push(Span::raw(if i == 7 { "  " } else { " " }));
        }
        for _ in chunk.len()..BYTES_PER_ROW as usize {
            spans.push(Span::raw("   "));
        }
        spans.push(Span::raw(" |"));
        for (i, b) in chunk.iter().enumerate() {
            let abs = base + i as u64;
            let c = if b.is_ascii_graphic() || *b == b' ' {
                *b as char
            } else {
                '.'
            };
            let style = if abs == v.cursor {
                Style::default().fg(Color::Black).bg(Color::White)
            } else {
                Style::default().fg(Color::White)
            };
            spans.push(Span::styled(c.to_string(), style));
        }
        spans.push(Span::raw("|"));
        lines.push(Line::from(spans));
    }
    let footer = match goto {
        Some(buf) => Line::from(vec![
            Span::styled(" go to offset > ", Style::default().fg(ACCENT)),
            Span::styled(
                buf.to_string(),
                Style::default()
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled("\u{2588}", Style::default().fg(ACCENT)),
        ]),
        None => {
            let byte = data.get((v.cursor - v.offset) as usize).copied();
            Line::from(Span::styled(
                match byte {
                    Some(b) => format!(
                        " cursor 0x{:x}: 0x{b:02x} = {b} = 0b{b:08b}{}",
                        v.cursor,
                        if b.is_ascii_graphic() {
                            format!(" = '{}'", b as char)
                        } else {
                            String::new()
                        }
                    ),
                    None => " (empty file)".to_string(),
                },
                Style::default().fg(DIM),
            ))
        }
    };
    lines.push(footer);
    frame.render_widget(Paragraph::new(lines), inner);
}

pub fn triage(frame: &mut Frame, dir: &std::path::Path, rows: &[triage::Row], selected: usize) {
    let rect = centered(frame.area(), 94, 85);
    frame.render_widget(Clear, rect);
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(ACCENT))
        .title(format!(
            " triage: {} ({} files) ",
            dir.display(),
            rows.len()
        ));
    let inner = block.inner(rect);
    frame.render_widget(block, rect);
    let has_online = rows.iter().any(|r| r.online.is_some());
    let mut lines = vec![Line::from(Span::styled(
        format!(
            " {:<28} {:>9} {:<20} {:>5} {:<20} {:>4} {:<12}{}",
            "file",
            "size",
            "type",
            "entr",
            "packer",
            "anti",
            "sha256",
            if has_online { " bazaar" } else { "" }
        ),
        Style::default().fg(ACCENT).add_modifier(Modifier::BOLD),
    ))];
    let height = inner.height.saturating_sub(1) as usize;
    let offset = selected.saturating_sub(height.saturating_sub(1));
    for (i, r) in rows.iter().enumerate().skip(offset).take(height) {
        let name: String = r
            .path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default()
            .chars()
            .take(28)
            .collect();
        let style = if i == selected {
            Style::default().fg(Color::Black).bg(Color::White)
        } else if r.anti >= 3
            || r.packer != "-"
            || r.online.as_ref().is_some_and(|o| o.contains("KNOWN"))
        {
            Style::default().fg(Color::Yellow)
        } else {
            Style::default().fg(Color::White)
        };
        lines.push(Line::from(Span::styled(
            format!(
                " {:<28} {:>9} {:<20} {:>5.2} {:<20} {:>4} {:<12}{}",
                name,
                crate::analysis::human_size(r.size),
                r.kind.chars().take(20).collect::<String>(),
                r.entropy,
                r.packer.chars().take(20).collect::<String>(),
                r.anti,
                &r.sha256[..12],
                r.online
                    .as_ref()
                    .map(|o| format!(" {}", o.chars().take(30).collect::<String>()))
                    .unwrap_or_default()
            ),
            style,
        )));
    }
    frame.render_widget(Paragraph::new(lines), inner);
}
