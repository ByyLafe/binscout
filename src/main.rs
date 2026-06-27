use crossterm::event;
use crossterm::event::Event;
use crossterm::event::KeyCode;
use ratatui::prelude::Stylize;
use ratatui::{
    Frame,
    layout::{Constraint, Direction, Layout},
    style::{Color, Style},
    text::Line,
    text::Span,
    widgets::Wrap,
    widgets::{Block, Borders, Paragraph},
};
use std::collections::HashMap;
use std::collections::HashSet;

#[derive(PartialEq)]
pub enum Focus {
    Steps,
    Options,
}

pub struct App {
    pub focus: Focus,
    pub checked: HashMap<String, HashSet<String>>,
    pub should_quit: bool,
    pub selected: usize,
    pub selected_right: usize,
}

static NUMBERS_OF_STEPS: usize = 10;

fn main() -> color_eyre::Result<()> {
    color_eyre::install()?;

    let mut terminal = ratatui::init();
    let mut app = App {
        selected: 0,
        focus: Focus::Steps,
        checked: HashMap::new(),
        should_quit: false,
        selected_right: 1,
    };

    loop {
        terminal.draw(|f| render(f, &app))?;
        if let Event::Key(key) = event::read()? {
            match key.code {
                KeyCode::Tab => {
                    app.selected = (app.selected + 1) % NUMBERS_OF_STEPS;
                }
                KeyCode::Up => {
                    if app.focus == Focus::Steps {
                        if app.selected == 0 {
                            app.selected = NUMBERS_OF_STEPS - 1;
                        } else {
                            app.selected -= 1;
                        }
                    } else if app.focus == Focus::Options {
                        if app.selected_right == 0 {
                            app.selected_right = calculate_number_of_options(&app) - 1;
                        } else {
                            app.selected_right -= 1;
                            println!("{:?}", app.selected_right);
                        }
                    }
                }
                KeyCode::Down => {
                    if app.focus == Focus::Steps {
                        app.selected = (app.selected + 1) % NUMBERS_OF_STEPS;
                        app.selected_right = 1;
                    } else if app.focus == Focus::Options {
                        app.selected_right = (app.selected_right + 1) % calculate_number_of_options(&app);

                        println!("{:?}", app.selected_right);
                    }
                }
                KeyCode::Enter => {
                    app.selected_right = 0;
                    app.focus = match app.focus {
                        Focus::Steps => Focus::Options,
                        Focus::Options => Focus::Steps,
                    };

                    if app.focus == Focus::Steps {
                        // Validate
                    }
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

    let help_display_array = ["espace valid", "↵ launch", "tab switch", "q exit"];

    let help_text = help_display_array.join("       ");

    let help = Paragraph::new(help_text)
        .fg(Color::LightBlue)
        .bg(Color::Black);
    frame.render_widget(help, vertical_chunks[1]);

    let items = [
        "file",
        "hashes",
        "binwalk",
        "entropy",
        "sections",
        "mitigations",
        "strings / floss",
        "yara",
        "capa",
        "final report",
    ];

    let mut text = Vec::new();

    for (index, item) in items.iter().enumerate() {
        let style = if app.selected == index && app.focus == Focus::Steps {
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

    let choose = match app.selected {
        0 => vec![
            " Show MIME type instead of textual description",
            " Look inside compressed files",
            " List all possible matches (useful to detect a polyglot file)",
            " Follow symbolic links",
            " Suggest the appropriate file extension",
        ],
        1 => vec![
            " sha256",
            " md5",
            " sha1",
            " Fuzzy hash (ssdeep) — find nearidentical variants",
            " Imphash — signature based on the import table",
            " Check online reputation (VirusTotal)",
        ],
        2 => vec![
            " Automatically extract detected files",
            " Recursively scan extracted files",
            " Search for known file signatures",
            " Search for executable signatures and machine code",
            " Run an entropy analysis to spot compressed/encrypted regions",
            " Display an entropy graph",
            " Attempt to decompress detected data",
            " Search for a specific pattern",
            " Only show a given signature type",
            " Exclude certain signature types",
        ],
        3 => vec![
            " Entropy per section",
            " Overall file entropy",
            " Sliding window size to locate a highentropy region",
            " Show an ASCII graph along the file",
            " Custom alert threshold",
        ],
        4 => vec![
            " General header (architecture, type, entry point)",
            " List sections with sizes and permissions",
            " Program headers / segments table | ELF Only",
            " Detailed import/export table",
            " Show virtual addresses instead of file offsets",
        ],
        5 => vec![
            " NX — non-executable stack",
            " PIE — randomized base address",
            " RELRO (partial/full)",
            " Stack canary",
            " Fortify Source",
            " Flag calls to dangerous functions (strcpy, gets, sprintf...)",
        ],
        6 => vec![
            " Classic strings",
            " Include UTF-16 encoded strings",
            " Minimum strings length",
            " Decoded in-memory strings (auto-decryption)",
        ],
        7 => vec![
            " Default community rules",
            " Custom rules",
            " Show matched strings, not just the rule name",
            " Also scan files extracted by binwalk",
        ],
        8 => vec![
            "Capabilities with confidence score",
            "Show the exact location each detection",
            "Filter by category, (network, persistance, etc...)",
        ],
        9 => vec![
            "Markdown export",
            "JSON Export",
            "Include raw tool output as an appendix",
            "Mention steps that weren't run",
        ],
        _ => vec!["Unknown step"],
    };

    let mut text_right = Vec::new();

    for (index, item) in choose.iter().enumerate() {
        let style_options = if app.selected_right == index && app.focus == Focus::Options {
            Style::default().fg(Color::Black).bg(Color::White)
        } else {
            Style::default().fg(Color::White)
        };
        text_right.push(Line::from(Span::styled(
            format!("- {}", item),
            style_options,
        )));
    }
    let right_content_paragraph = Paragraph::new(text_right);
    let right_content = right_content_paragraph.block(
        Block::default()
            .border_style(Style::new().dark_gray())
            .title("binscout")
            .borders(Borders::ALL),
    );

    frame.render_widget(right_content, chunks[1]);
}


// !! WARNING !! Don't forget to match these steps when changing display Options
fn calculate_number_of_options(app: &App) -> usize {
    let choose = match app.selected {
        0 => 5,
        1 => 6,
        2 => 10,
        3 => 5,
        4 => 5,
        5 => 6,
        6 => 4,
        7 => 4,
        8 => 3,
        9 => 4,
        _ => 1,
    };
    choose
}
