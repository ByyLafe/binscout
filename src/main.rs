use crossterm::event;
use crossterm::event::Event;
use crossterm::event::KeyCode;
use ratatui::{
    DefaultTerminal, Frame,
    layout::{Constraint, Direction, Layout},
    style::{Color, Style},
    text::Line,
    text::Span,
    widgets::Wrap,
    widgets::{Block, Borders, Paragraph},
};

static NUMBERS_OF_STEPS: usize = 10;
struct App {
    selected: usize,
}

fn main() -> color_eyre::Result<()> {
    color_eyre::install()?;

    let mut terminal = ratatui::init();
    let mut app = App { selected: 0 };

    loop {
        terminal.draw(|f| render(f, &app))?;

        if let Event::Key(key) = event::read()? {
            match key.code {
                KeyCode::Tab => {
                    app.selected = (app.selected + 1) % NUMBERS_OF_STEPS;
                }
                KeyCode::Esc => break,
                _ => {}
            }
        }
    }

    ratatui::restore();
    Ok(())
}

fn render(frame: &mut Frame, app: &App) {
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(20), Constraint::Percentage(80)])
        .split(frame.area());

    let items = vec![
        "file",
        "hashes",
        "binwalk",
        "entropie",
        "sections",
        "mitigations",
        "strings / floss",
        "yara",
        "capa",
        "final report",
    ];

    let mut text = Vec::new();

    for (index, item) in items.iter().enumerate() {
        let style = if app.selected == index {
            Style::default().fg(Color::Black).bg(Color::White)
        } else {
            Style::default().fg(Color::White)
        };

        text.push(Line::from(Span::styled(format!("- {}", item), style)));
    }
    let left_block = Paragraph::new(text).wrap(Wrap { trim: (true) }).block(
        Block::default()
            .border_style(Style::new().dark_gray())
            .title("Steps")
            .borders(Borders::ALL),
    );
    frame.render_widget(left_block, chunks[0]);

    let right_content = Block::default()
        .border_style(Style::new().dark_gray())
        .title("binscout")
        .borders(Borders::ALL);

    frame.render_widget(right_content, chunks[1]);
}
