use ratatui::{
    DefaultTerminal, Frame,
    layout::{Constraint, Direction, Layout},
    style::{Color, Style},
    text::Span,
    widgets::Wrap,
    widgets::{Block, Borders, Paragraph},
};

fn main() -> color_eyre::Result<()> {
    color_eyre::install()?;

    let original_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |panic_info| {
        let _ = ratatui::restore();
        original_hook(panic_info);
    }));
    ratatui::run(app).map_err(|e| color_eyre::eyre::eyre!(e))?;
    Ok(())
}

fn app(terminal: &mut DefaultTerminal) -> std::io::Result<()> {
    loop {
        terminal.draw(render)?;
        if crossterm::event::read()?.is_key_press() {
            break Ok(());
        }
    }
}

fn render(frame: &mut Frame) {
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(20), Constraint::Percentage(80)])
        .split(frame.area());

    let text_span = Span::styled(
        "file",
        Style::default().fg(Color::White),
    );
    let left_block = Paragraph::new(text_span).wrap(Wrap { trim: (true) }).block(
        Block::default()
            .border_style(Style::new().dark_gray())
            .title("Steps")
            .borders(Borders::ALL),
    );
    frame.render_widget(left_block, chunks[0]);

    let right_content = Block::default().border_style(Style::new().dark_gray()).title("binscout").borders(Borders::ALL);

    frame.render_widget(right_content, chunks[1]);
}
