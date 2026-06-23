# 🔍 BinScout - The Rust's TUI Cyber Wrapper

> *Cyber tooling, without the command line.*

![Rust](https://img.shields.io/badge/Made%20with-Rust-orange?logo=rust&logoColor=white)
![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20macOS-blue)
![Status](https://img.shields.io/badge/Status-In%20Development-yellow)
![License](https://img.shields.io/github/license/ByyLafe/binscout)
![Last Commit](https://img.shields.io/github/last-commit/ByyLafe/binscout)
![Stars](https://img.shields.io/github/stars/ByyLafe/binscout?style=social)

---

## ✰ Highlights

- ☕︎ **Interactive Terminal User Interface** : fully keyboard-driven, no commands to memorize
- ▶ **Unified wrapper** around the most popular binary analysis tools
- ▶ **Step-by-step guided workflow**, from file identification to the final report
- 🦀 **Written in Rust** : fast, reliable, and lightweight
- ▶ Built for **malware analysts, pentesters, and CTF players**
- ▶ Report export in **Markdown and JSON**

---

## ⓘ Overview

BinScout is a TUI *(Terminal User Interface)* wrapper written in Rust that brings together the most common binary analysis tools into a single interactive, guided interface. No more long commands to retype, forgotten flags, or unreadable output: BinScout walks you through every step of an analysis, from the raw file all the way to the final report.

Under the hood, BinScout is built with [`ratatui`](https://github.com/ratatui-org/ratatui) and [`crossterm`](https://github.com/crossterm-rs/crossterm), giving it a snappy and responsive terminal experience.

<!-- Remplace ce lien par ton screenshot principal -->
<p align="center">
  <img src="docs/main-menu.png" alt="BinScout main interface" width="800">
</p>

The interface is split into **10 analysis steps**:

| Step | Tool / Action |
|------|---------------|
| 1  | File identification (`file`) |
| 2  | Hashes (MD5, SHA1, SHA256, ssdeep, imphash, VirusTotal) |
| 3  | Structure carving (`binwalk`) |
| 4  | Entropy analysis |
| 5  | Sections & headers |
| 6  | Mitigations (NX, PIE, RELRO, stack canary...) |
| 7  | Strings & FLOSS |
| 8  | YARA |
| 9  | capa |
| 10 | Final report |

Each step exposes **configurable options** directly from the interface: you check what you want, and BinScout handles the underlying command for you.

### 🎯 Who is it for?

BinScout is built for:

- **Malware analysts** who run regular triage and investigation
- **Pentesters** who need quick binary inspection without context-switching to the man pages
- **CTF players** looking to speed up the reverse-engineering grind
- **Students** discovering binary analysis tooling without the steep CLI learning curve

### ✍️ Author

Created and maintained by Jorg Hunter. BinScout started as a way to stop memorizing dozens of flags across half a dozen tools and turn the whole workflow into something approachable and fast.

---

## ✈︎ Usage instructions

Launch BinScout from your terminal:

```bash
binscout
```

Then navigate entirely with the keyboard:

| Key         | Action                              |
|-------------|-------------------------------------|
| `↑` / `↓`   | Move between analysis steps         |
| `Tab`       | Cycle to the next step              |
| `Enter`     | Switch focus to the step's options  |
| `Space`     | Toggle an option *(coming soon)*    |
| `q` / `Esc` | Quit                                |

The interface is laid out in two panes:

- **Left pane (`Steps`)** : the list of the 10 analysis stages
- **Right pane (`Options`)** : the configurable options for the currently selected step

<!-- Remplace ce lien par ton GIF de démo -->
<p align="center">
  <img src="docs/demo.gif" alt="BinScout demo" width="800">
</p>

---

## ￬ Installation instructions

> **Status:** BinScout is in early development. Build from source for now.

### Requirements

- [Rust toolchain](https://rustup.rs/) (stable)
- A Unix-like terminal (Linux / macOS recommended)
- The underlying analysis tools available in your `PATH` *(e.g. `file`, `binwalk`, `yara`, `capa`, `floss`, `ssdeep`)*

### Build from source

```bash
git clone https://github.com/ByyLafe/binscout
cd binscout
cargo build --release
```

The compiled binary will be available at `target/release/binscout`.

To run it directly during development:

```bash
cargo run
```

---

## 🗺️ Roadmap

BinScout is still a work in progress. Planned features include:

- [ ] Option toggling with `Space` and persistent selection state
- [ ] Actual execution of the underlying tools (`Enter` to launch)
- [ ] Live output rendering inside the TUI
- [ ] Markdown & JSON report generation
- [ ] VirusTotal integration for hash reputation
- [ ] Configurable tool paths and presets

---

## 💭 Feedback & contributions

Found a bug, have an idea, or want to add support for another tool? Open an [issue](https://github.com/ByyLafe/binscout/issues) or start a [discussion](https://github.com/ByyLafe/binscout/discussions): contributions are very welcome!

If you'd like to contribute code, fork the repo, create a feature branch, and open a pull request.

---

## 📖 Further reading

- [ratatui : Rust TUI library](https://github.com/ratatui-org/ratatui)
- [crossterm : cross-platform terminal manipulation](https://github.com/crossterm-rs/crossterm)
- [binwalk](https://github.com/ReFirmLabs/binwalk)
- [YARA](https://github.com/VirusTotal/yara)
- [capa](https://github.com/mandiant/capa)
- [FLOSS](https://github.com/mandiant/flare-floss)

---

*Made with 🦀 and a healthy dislike for typing the same flags over and over.*
