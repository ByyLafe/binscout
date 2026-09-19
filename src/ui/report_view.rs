use super::{ACCENT, DIM};
use crate::app::App;
use crate::catalog::STEPS;
use crate::engine::Status;
use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph, Wrap};

pub fn render(frame: &mut Frame, app: &App, area: Rect) {
    let step = &STEPS[app.selected];
    let inner_height = area.height.saturating_sub(2) as usize;
    let inner_width = area.width.saturating_sub(2).max(1);
    app.output_width.set(inner_width);
    let needle = app.search.as_ref().map(|s| s.to_lowercase());

    let (title, paragraph) = match app.results[app.selected].as_ref() {
        Some(r) => {
            let (label, color) = match r.status {
                Status::Ok => ("ok", Color::Green),
                Status::Failed => ("failed", Color::Red),
                Status::Skipped => ("skipped", Color::Yellow),
            };
            let lines: Vec<Line> = r
                .output
                .lines()
                .map(|l| {
                    let mut style = line_style(l, color);
                    if needle
                        .as_ref()
                        .is_some_and(|n| l.to_lowercase().contains(n.as_str()))
                    {
                        style = style.bg(Color::Rgb(70, 60, 0)).add_modifier(Modifier::BOLD);
                    }
                    Line::from(Span::styled(l.to_string(), style))
                })
                .collect();
            let paragraph = Paragraph::new(lines).wrap(Wrap { trim: false });

            // line_count needs ratatui's unstable-rendered-line-info feature; computing wrapped
            // rows by hand would diverge from the widget's own word wrapping.
            let total = paragraph.line_count(inner_width);
            let max_scroll = total.saturating_sub(inner_height);
            let scroll = (app.output_scroll as usize).min(max_scroll);
            let pos = if total > inner_height {
                format!(
                    "  {}-{}/{}",
                    scroll + 1,
                    (scroll + inner_height).min(total),
                    total
                )
            } else {
                String::new()
            };
            (
                format!(
                    " {} \u{2014} {label} in {} ms{pos} ",
                    step.title, r.duration_ms
                ),
                paragraph.scroll((scroll as u16, 0)),
            )
        }
        None if app.is_running(app.selected) => {
            let mut lines: Vec<Line> = vec![Line::from(Span::styled(
                format!("running... {} line(s) so far", app.live.len()),
                Style::default().fg(Color::Yellow),
            ))];
            let skip = app
                .live
                .len()
                .saturating_sub(inner_height.saturating_sub(1));
            lines.extend(
                app.live
                    .iter()
                    .skip(skip)
                    .map(|l| Line::from(Span::styled(l.clone(), line_style(l, Color::Yellow)))),
            );
            (
                format!(" {} \u{2014} running ", step.title),
                Paragraph::new(lines),
            )
        }
        None => (
            format!(" {} ", step.title),
            Paragraph::new(Line::from(Span::styled(
                "no output yet: press Space to run this step",
                Style::default().fg(DIM),
            ))),
        ),
    };

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(ACCENT))
        .title(title);
    frame.render_widget(paragraph.block(block), area);
}

fn line_style(l: &str, status_color: Color) -> Style {
    if l.starts_with("$ ") {
        Style::default().fg(ACCENT)
    } else if l.starts_with("== ")
        || l.starts_with("---- ")
        || l.starts_with("# ")
        || l.starts_with("## ")
    {
        Style::default().fg(Color::Yellow)
    } else if l.starts_with("[FAIL]")
        || l.starts_with("[exit code")
        || l.starts_with("[stderr]")
        || l.contains("KNOWN MALWARE")
    {
        Style::default().fg(Color::Red)
    } else if l.starts_with("[ OK ]") {
        Style::default().fg(Color::Green)
    } else if l.starts_with("[note]")
        || l.starts_with("[ ?? ]")
        || l.starts_with("verdict")
        || l.starts_with("  verdict")
        || status_color == Color::Yellow
    {
        Style::default().fg(Color::Yellow)
    } else {
        Style::default().fg(Color::White)
    }
}
