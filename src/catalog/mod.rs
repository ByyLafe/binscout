#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OptionKind {
    Flag,

    Value {
        hint: &'static str,

        default: &'static str,
    },
}

#[derive(Debug, Clone, Copy)]
pub struct OptionDef {
    pub label: &'static str,
    pub kind: OptionKind,

    pub tool: Option<&'static str>,

    pub cmd: &'static str,
}

impl OptionDef {
    const fn cmd(mut self, cmd: &'static str) -> Self {
        self.cmd = cmd;
        self
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Step {
    pub name: &'static str,

    pub title: &'static str,

    pub tool: Option<&'static str>,
    pub options: &'static [OptionDef],
}

const fn flag(label: &'static str) -> OptionDef {
    OptionDef {
        label,
        kind: OptionKind::Flag,
        tool: None,
        cmd: "",
    }
}

const fn flag_tool(label: &'static str, tool: &'static str) -> OptionDef {
    OptionDef {
        label,
        kind: OptionKind::Flag,
        tool: Some(tool),
        cmd: "",
    }
}

const fn value(label: &'static str, hint: &'static str, default: &'static str) -> OptionDef {
    OptionDef {
        label,
        kind: OptionKind::Value { hint, default },
        tool: None,
        cmd: "",
    }
}

// Option indexes are the contract between the catalog, App state and the runners;
// labels are for humans only.
pub const STEP_FILE: usize = 0;
pub const STEP_HASHES: usize = 1;
pub const STEP_PACKER: usize = 2;
pub const STEP_CONTAINER: usize = 3;
pub const STEP_BINWALK: usize = 4;
pub const STEP_ENTROPY: usize = 5;
pub const STEP_SECTIONS: usize = 6;
pub const STEP_MITIGATIONS: usize = 7;
pub const STEP_ANTI: usize = 8;
pub const STEP_STRINGS: usize = 9;
pub const STEP_IOCS: usize = 10;
pub const STEP_YARA: usize = 11;
pub const STEP_CAPA: usize = 12;
pub const STEP_DISASM: usize = 13;
pub const STEP_COMPARE: usize = 14;
pub const STEP_REPORT: usize = 15;

pub const STEPS: &[Step] = &[
    Step {
        name: "file",
        title: "File identification",
        tool: Some("file"),
        options: &[
            flag("Show MIME type instead of textual description").cmd("file -i"),
            flag("Look inside compressed files").cmd("file -z"),
            flag("List all possible matches (useful to detect a polyglot file)").cmd("file -k"),
            flag("Follow symbolic links").cmd("file -L"),
            flag("Suggest the appropriate file extension").cmd("file --extension"),
        ],
    },
    Step {
        name: "hashes",
        title: "Hashes",
        tool: None,
        options: &[
            flag("sha256").cmd("native sha2"),
            flag("md5").cmd("native md-5"),
            flag("sha1").cmd("native sha1"),
            flag_tool(
                "Fuzzy hash (ssdeep) \u{2014} find near-identical variants",
                "ssdeep",
            )
            .cmd("ssdeep -b <file>"),
            flag("Imphash \u{2014} signature based on the import table (PE only)")
                .cmd("native (goblin PE imports)"),
            flag("Check online reputation (VirusTotal, needs an API key)")
                .cmd("GET virustotal.com/api/v3/files/<sha256>"),
            flag("Check MalwareBazaar (abuse.ch, needs an Auth-Key)")
                .cmd("POST mb-api.abuse.ch/api/v1/ query=get_info"),
        ],
    },
    Step {
        name: "packer",
        title: "Packer & compiler detection",
        tool: None,
        options: &[
            flag("Known packer signatures (UPX, ASPack, Themida, VMProtect...)")
                .cmd("native: section names + byte signatures"),
            flag("Compiler / toolchain (GCC, MSVC, Go, Rust, .NET, PyInstaller...)")
                .cmd("native: markers, .comment, Rich header, CLR"),
            flag("Packing heuristics (entropy, tiny import table, overlay, W+X sections)")
                .cmd("native: entropy, imports, overlay, W+X"),
            flag_tool("Unpack with UPX (writes <file>.unpacked)", "upx")
                .cmd("upx -d -o <file>.unpacked <file>"),
        ],
    },
    Step {
        name: "container",
        title: "Archive / container",
        tool: None,
        options: &[
            flag("List the archive members (zip, jar, apk, tar, 7z, deb, rpm...)")
                .cmd("unzip -l | tar -tvf | 7z l | dpkg-deb -c ..."),
            flag("Extract members to _<file>.container/ (then pick one with @)")
                .cmd("unzip -o -d | tar -xf -C | 7z x -o ..."),
        ],
    },
    Step {
        name: "binwalk",
        title: "Structure carving (binwalk)",
        tool: Some("binwalk"),
        options: &[
            flag("Automatically extract detected files").cmd("binwalk -e"),
            flag("Recursively scan extracted files").cmd("binwalk -M"),
            flag("Search for known file signatures").cmd("binwalk -B"),
            flag("Search for executable signatures and machine code").cmd("binwalk -A"),
            flag("Run an entropy analysis to spot compressed/encrypted regions")
                .cmd("binwalk -E (-N without -J)"),
            flag("Save the entropy graph as a PNG").cmd("binwalk -J"),
            flag("Carve data without running external extractors").cmd("binwalk -z"),
            value(
                "Search for a specific byte sequence",
                "bytes, e.g. \\x7fELF",
                "",
            )
            .cmd("binwalk -R=<bytes>"),
            value("Only show a given signature type", "e.g. zip", "").cmd("binwalk -y=<type>"),
            value("Exclude certain signature types", "e.g. lzma", "").cmd("binwalk -x=<type>"),
        ],
    },
    Step {
        name: "entropy",
        title: "Entropy analysis",
        tool: None,
        options: &[
            flag("Entropy per section").cmd("native: shannon per section (goblin)"),
            flag("Overall file entropy").cmd("native: shannon whole file"),
            value(
                "Sliding window to locate high-entropy regions",
                "window size in bytes",
                "256",
            )
            .cmd("native: shannon per window"),
            flag("Show an ASCII graph along the file").cmd("native: 64-column profile"),
            value("Custom alert threshold", "bits per byte, 0-8", "7.0")
                .cmd("native: threshold for ! marks and ^"),
        ],
    },
    Step {
        name: "sections",
        title: "Sections & headers",
        tool: None,
        options: &[
            flag("General header (architecture, type, entry point)").cmd("native (goblin header)"),
            flag("List sections with sizes and permissions").cmd("native (goblin sections)"),
            flag("Program headers / segments table | ELF only")
                .cmd("native (goblin program headers)"),
            flag("Detailed import/export table").cmd("native (goblin symbols)"),
            flag("Show virtual addresses instead of file offsets")
                .cmd("native: address column = VA"),
        ],
    },
    Step {
        name: "mitigations",
        title: "Mitigations",
        tool: None,
        options: &[
            flag("NX \u{2014} non-executable stack").cmd("native: PT_GNU_STACK / NX_COMPAT"),
            flag("PIE \u{2014} randomized base address").cmd("native: ET_DYN / DYNAMIC_BASE"),
            flag("RELRO (partial/full)").cmd("native: PT_GNU_RELRO + BIND_NOW"),
            flag("Stack canary").cmd("native: __stack_chk_fail import"),
            flag("Fortify Source").cmd("native: __*_chk imports"),
            flag("Flag calls to dangerous functions (strcpy, gets, sprintf...)")
                .cmd("native: import list vs table"),
        ],
    },
    Step {
        name: "anti-analysis",
        title: "Anti-analysis indicators",
        tool: None,
        options: &[
            flag("Debugger detection (IsDebuggerPresent, ptrace, TracerPid...)")
                .cmd("native: imports + strings rules"),
            flag("VM / sandbox detection (VirtualBox, VMware, QEMU, Sandboxie...)")
                .cmd("native: imports + strings rules"),
            flag("Timing checks & evasion (Sleep, GetTickCount, rdtsc...)")
                .cmd("native: imports + strings rules"),
            flag("Process enumeration & injection primitives").cmd("native: imports rules"),
            flag("TLS callbacks and other pre-entry-point code (PE)")
                .cmd("native: PE TLS data directory"),
            flag("Analysis tool names in strings (ida, x64dbg, wireshark...)")
                .cmd("native: strings rules"),
        ],
    },
    Step {
        name: "strings / floss",
        title: "Strings & FLOSS",
        tool: None,
        options: &[
            flag("Classic strings").cmd("strings -a <file>"),
            flag("Include UTF-16 encoded strings").cmd("strings -a -e l <file>"),
            value("Minimum strings length", "characters", "4").cmd("strings -n <N> / floss -n <N>"),
            flag_tool("Decoded in-memory strings (FLOSS auto-decryption)", "floss")
                .cmd("floss <file> --no static"),
        ],
    },
    Step {
        name: "iocs",
        title: "Indicators of compromise",
        tool: None,
        options: &[
            flag("URLs").cmd("native regex"),
            flag("IP addresses").cmd("native regex"),
            flag("Domain names").cmd("native regex + TLD filter"),
            flag("Email addresses").cmd("native regex"),
            flag("File paths (Windows & Unix)").cmd("native regex"),
            flag("Windows registry keys").cmd("native regex"),
            flag("Base64 blobs").cmd("native regex"),
            flag("Crypto wallets, user agents, mutex-like names").cmd("native regex"),
        ],
    },
    Step {
        name: "yara",
        title: "YARA",
        tool: Some("yara"),
        options: &[
            value(
                "Default community rules",
                "rules file or directory",
                "~/.config/binscout/rules",
            )
            .cmd("yara <rules> <file> (index.yar or every .yar)"),
            value("Custom rules", "rules file or directory", "").cmd("yara <rules> <file>"),
            flag("Show matched strings, not just the rule name").cmd("yara -s"),
            flag("Also scan files extracted by binwalk").cmd("yara -r <rules> _<file>.extracted/"),
        ],
    },
    Step {
        name: "capa",
        title: "capa",
        tool: Some("capa"),
        options: &[
            flag("Capabilities summary").cmd("capa <file>"),
            flag("Show the exact location of each detection").cmd("capa -v"),
            value("Filter by tag (network, persistence, ...)", "tag", "").cmd("capa -t <tag>"),
        ],
    },
    Step {
        name: "disasm",
        title: "Disassembly",
        tool: Some("objdump"),
        options: &[
            value("Disassemble around the entry point", "bytes", "512")
                .cmd("objdump -d --start-address=<entry> --stop-address=<entry+N>"),
            flag("Intel syntax instead of AT&T").cmd("objdump -M intel"),
            flag("Function list (rizin / radare2 if installed, else symbols)")
                .cmd("rizin -q -c 'aaa; afl' | objdump -t -T"),
            flag("Full disassembly of the code section (can be long)")
                .cmd("objdump -d --start/stop = code section"),
        ],
    },
    Step {
        name: "compare",
        title: "Compare with another binary",
        tool: None,
        options: &[
            value("Other binary (or press c to pick it)", "path", "")
                .cmd("native: second file path"),
            flag("Sections: added / removed / entropy changes").cmd("native (goblin)"),
            flag("Imports & exports diff").cmd("native (goblin)"),
            flag("Strings diff").cmd("native strings"),
            flag_tool("ssdeep similarity score", "ssdeep").cmd("ssdeep -d -b <A> <B>"),
        ],
    },
    Step {
        name: "final report",
        title: "Final report",
        tool: None,
        options: &[
            flag("Markdown export").cmd("native: writes binscout-report-<file>.md"),
            flag("JSON export").cmd("native: writes binscout-report-<file>.json"),
            flag("Include raw tool output as an appendix").cmd("native: appendix"),
            flag("Mention steps that weren't run").cmd("native: not-run table"),
        ],
    },
];

pub fn step(index: usize) -> &'static Step {
    &STEPS[index]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_option_documents_its_command() {
        for step in STEPS {
            for o in step.options {
                assert!(
                    !o.cmd.is_empty(),
                    "{}: \"{}\" has no cmd hint",
                    step.name,
                    o.label
                );
            }
        }
    }
}
