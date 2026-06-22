use crossterm::event;
use crossterm::event::Event;
use crossterm::event::KeyCode;
use ratatui::{
    Frame,
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
                KeyCode::Up => {
                    if app.selected == 0 {
                        app.selected = NUMBERS_OF_STEPS - 1;
                    } else {
                        app.selected -= 1;
                    }
                }
                KeyCode::Down => {
                    app.selected = (app.selected + 1) % NUMBERS_OF_STEPS;
                }
                KeyCode::Esc | KeyCode::Char('q') | KeyCode::Char('Q') => break,
                _ => {}
            }
        }
    }

    ratatui::restore();
    Ok(())
}

fn render(frame: &mut Frame, app: &App) {
    let vertical_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Percentage(95), Constraint::Percentage(5)])
        .split(frame.area());

    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(20), Constraint::Percentage(80)])
        .split(vertical_chunks[0]);

    let help_display_array = vec!["espace valid", "↵ launch", "tab switch", "q exit"];

    let help_text = help_display_array.join("       ");

    let help = Paragraph::new(help_text);
    frame.render_widget(help, vertical_chunks[1]);

    let items = [
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

    let left_block = Paragraph::new(text).wrap(Wrap { trim: true }).block(
        Block::default()
            .border_style(Style::new().dark_gray())
            .title("Steps")
            .borders(Borders::ALL),
    );

    frame.render_widget(left_block, chunks[0]);

    let content_file_tab = [
        "- Search for signatures of known files",
        "- Automatically extract detected files",
        "- Recursively analyze the extracted files",
        "- Analyze entropy to identify compressed areas",
        "- Display a graph of entropy",
        "- Search for a specific pattern",
    ];

    let content_file = Paragraph::new(content_file_tab.join("\n"));

    let choose = match app.selected {
        0 => vec![
            "- Search for signatures of known files",
            "- Automatically extract detected files",
            "- Recursively analyze the extracted files",
            "- Analyze entropy to identify compressed areas",
            "- Display a graph of entropy",
            "- Search for a specific pattern",
        ],
        1 => vec![
            "- Calculate MD5 hash",
            "- Calculate SHA1 hash",
            "- Calculate SHA256 hash",
            "- Compare hashes with known databases",
        ],
        2 => vec![
            "- Run binwalk analysis",
            "- Detect embedded files",
            "- Extract firmware content",
        ],
        3 => vec![
            "- Calculate file entropy",
            "- Detect packed or encrypted areas",
            "- Display entropy score",
        ],
        4 => vec![
            "- Display PE sections",
            "- Show section permissions",
            "- Detect suspicious sections",
        ],
        5 => vec![
            "- Check binary mitigations",
            "- NX",
            "- ASLR",
            "- PIE",
            "- RELRO",
        ],
        6 => vec![
            "- Extract strings",
            "- Run FLOSS",
            "- Detect obfuscated strings",
        ],
        7 => vec![
            "- Run YARA rules",
            "- Detect malware patterns",
            "- Display matching rules",
        ],
        8 => vec![
            "- Run capa analysis",
            "- Detect capabilities",
            "- Display ATT&CK techniques",
        ],
        9 => vec![
            "- Generate final report",
            "- Export results",
            "- Summarize findings",
        ],
        _ => vec!["Unknown step"],
    };

    let right_content = Paragraph::new(choose.join("\n"));

    let right_content = right_content.block(
        Block::default()
            .border_style(Style::new().dark_gray())
            .title("binscout")
            .borders(Borders::ALL),
    );

    frame.render_widget(right_content, chunks[1]);
}
