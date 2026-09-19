use super::{ACCENT, DIM};
use crate::app::{App, Focus};
use crate::catalog::STEPS;
use crate::engine::Status;
use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph};

pub fn render(frame: &mut Frame, app: &App, area: Rect) {
    let focused = app.focus == Focus::Steps;
    let mut lines = Vec::new();
    for (i, step) in STEPS.iter().enumerate() {
        let (marker, marker_style) = if app.is_running(i) {
            ("\u{25cf}", Style::default().fg(Color::Yellow))
        } else {
            match app.results[i].as_ref().map(|r| &r.status) {
                Some(Status::Ok) => ("\u{2713}", Style::default().fg(Color::Green)),
                Some(Status::Failed) => ("\u{2717}", Style::default().fg(Color::Red)),
                Some(Status::Skipped) => ("\u{2013}", Style::default().fg(Color::Yellow)),
                None => (" ", Style::default()),
            }
        };
        let checked = app.checked[i].iter().filter(|c| **c).count();
        let missing = step.tool.is_some_and(|t| app.missing_tools.contains(t));
        let label_style = if app.selected == i && focused {
            Style::default().fg(Color::Black).bg(Color::White)
        } else if app.selected == i {
            Style::default().fg(ACCENT).add_modifier(Modifier::BOLD)
        } else if missing {
            Style::default().fg(DIM)
        } else {
            Style::default().fg(Color::White)
        };
        let count = if checked > 0 {
            format!(" {checked}")
        } else {
            String::new()
        };
        lines.push(Line::from(vec![
            Span::styled(format!("{marker} "), marker_style),
            Span::styled(format!("{:>2} {:<15}", i + 1, step.name), label_style),
            Span::styled(count, Style::default().fg(DIM)),
        ]));
    }
    let border = if focused {
        Style::default().fg(ACCENT)
    } else {
        Style::default().fg(DIM)
    };
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(border)
        .title(" Steps ");
    frame.render_widget(Paragraph::new(lines).block(block), area);
}
