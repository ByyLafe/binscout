use std::path::PathBuf;
use std::process::Command;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PackageManager {
    Apt,
    Dnf,
    Pacman,
    Zypper,
    Apk,
    Brew,
}

impl PackageManager {
    pub fn name(self) -> &'static str {
        match self {
            Self::Apt => "apt",
            Self::Dnf => "dnf",
            Self::Pacman => "pacman",
            Self::Zypper => "zypper",
            Self::Apk => "apk",
            Self::Brew => "brew",
        }
    }

    fn install_prefix(self) -> &'static str {
        match self {
            Self::Apt => "sudo apt install -y",
            Self::Dnf => "sudo dnf install -y",
            Self::Pacman => "sudo pacman -S --noconfirm",
            Self::Zypper => "sudo zypper install -y",
            Self::Apk => "sudo apk add",
            Self::Brew => "brew install",
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub enum Source {
    System {
        pkg: &'static str,
        apt: Option<&'static str>,
    },

    Python(&'static str),
}

impl Source {
    fn package(self, pm: PackageManager) -> Option<&'static str> {
        match self {
            Self::System { pkg, apt } => Some(if pm == PackageManager::Apt {
                apt.unwrap_or(pkg)
            } else {
                pkg
            }),
            Self::Python(_) => None,
        }
    }
}

const fn sys(pkg: &'static str) -> Source {
    Source::System { pkg, apt: None }
}

#[derive(Debug, Clone, Copy)]
pub struct ToolDef {
    pub name: &'static str,
    pub purpose: &'static str,
    pub source: Source,

    pub optional: bool,
}

const fn tool(name: &'static str, purpose: &'static str, source: Source) -> ToolDef {
    ToolDef {
        name,
        purpose,
        source,
        optional: false,
    }
}

const fn opt(name: &'static str, purpose: &'static str, source: Source) -> ToolDef {
    ToolDef {
        name,
        purpose,
        source,
        optional: true,
    }
}

pub const TOOLS: &[ToolDef] = &[
    tool("file", "file identification", sys("file")),
    tool("binwalk", "structure carving", sys("binwalk")),
    tool(
        "strings",
        "printable strings (native fallback exists)",
        sys("binutils"),
    ),
    tool("objdump", "disassembly", sys("binutils")),
    tool("yara", "YARA rule scanning", sys("yara")),
    tool("ssdeep", "fuzzy hashing", sys("ssdeep")),
    tool(
        "upx",
        "UPX unpacking",
        Source::System {
            pkg: "upx",
            apt: Some("upx-ucl"),
        },
    ),
    tool(
        "floss",
        "decoded strings (FLARE)",
        Source::Python("flare-floss"),
    ),
    tool(
        "capa",
        "capability detection (FLARE)",
        Source::Python("flare-capa"),
    ),
    opt(
        "7z",
        "archives: 7z, cab, iso, msi, rpm",
        Source::System {
            pkg: "p7zip",
            apt: Some("p7zip-full"),
        },
    ),
    opt("unzip", "archives: zip, jar, apk", sys("unzip")),
    opt(
        "rizin",
        "function recovery in the disassembly step",
        sys("rizin"),
    ),
];

#[derive(Debug, Clone)]
pub struct System {
    pub os: String,
    pub kernel: &'static str,
    pub package_manager: Option<PackageManager>,

    pub python_installer: Option<&'static str>,
}

#[derive(Debug, Clone)]
pub struct ToolStatus {
    pub def: ToolDef,
    pub path: Option<PathBuf>,
    pub install: Option<String>,
}

impl ToolStatus {
    pub fn installed(&self) -> bool {
        self.path.is_some()
    }
}

#[derive(Debug, Clone)]
pub struct Doctor {
    pub system: System,
    pub tools: Vec<ToolStatus>,
}

fn has(cmd: &str) -> bool {
    which::which(cmd).is_ok()
}

pub fn detect_system() -> System {
    let kernel = std::env::consts::OS;
    let os = match kernel {
        "linux" => std::fs::read_to_string("/etc/os-release")
            .ok()
            .and_then(|s| {
                s.lines()
                    .find_map(|l| l.strip_prefix("PRETTY_NAME="))
                    .map(|v| v.trim_matches('"').to_string())
            })
            .unwrap_or_else(|| "Linux".to_string()),
        "macos" => Command::new("sw_vers")
            .arg("-productVersion")
            .output()
            .ok()
            .map(|o| format!("macOS {}", String::from_utf8_lossy(&o.stdout).trim()))
            .unwrap_or_else(|| "macOS".to_string()),
        other => other.to_string(),
    };
    let package_manager = [
        ("apt-get", PackageManager::Apt),
        ("dnf", PackageManager::Dnf),
        ("pacman", PackageManager::Pacman),
        ("zypper", PackageManager::Zypper),
        ("apk", PackageManager::Apk),
        ("brew", PackageManager::Brew),
    ]
    .into_iter()
    .find(|(cmd, _)| has(cmd))
    .map(|(_, pm)| pm);
    // pipx first: it isolates each tool's dependencies (capa and floss pin conflicting
    // versions of vivisect) and puts the entry points in ~/.local/bin.
    let python_installer = if has("pipx") {
        Some("pipx install")
    } else if has("pip3") {
        Some("pip3 install --user")
    } else if has("python3") {
        Some("python3 -m pip install --user")
    } else {
        None
    };
    System {
        os,
        kernel,
        package_manager,
        python_installer,
    }
}

impl Doctor {
    pub fn run() -> Self {
        let system = detect_system();
        let tools = TOOLS
            .iter()
            .map(|def| ToolStatus {
                def: *def,
                path: which::which(def.name).ok(),
                install: install_command(def, &system),
            })
            .collect();
        Self { system, tools }
    }

    pub fn missing(&self) -> Vec<&ToolStatus> {
        self.tools.iter().filter(|t| !t.installed()).collect()
    }

    pub fn install_all_command(&self) -> Option<String> {
        let mut system_pkgs = Vec::new();
        let mut python_pkgs = Vec::new();
        for t in self.missing() {
            match t.def.source {
                Source::System { .. } => {
                    if let Some(pm) = self.system.package_manager
                        && let Some(p) = t.def.source.package(pm)
                        && !system_pkgs.contains(&p)
                    {
                        system_pkgs.push(p);
                    }
                }
                Source::Python(p) => python_pkgs.push(p),
            }
        }
        let mut parts = Vec::new();
        if !system_pkgs.is_empty() {
            let pm = self.system.package_manager?;
            parts.push(format!("{} {}", pm.install_prefix(), system_pkgs.join(" ")));
        }
        if !python_pkgs.is_empty() {
            let py = self.system.python_installer?;
            parts.push(format!("{py} {}", python_pkgs.join(" ")));
        }
        (!parts.is_empty()).then(|| parts.join(" && "))
    }

    pub fn report(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!(
            "system           {} ({})\n",
            self.system.os, self.system.kernel
        ));
        out.push_str(&format!(
            "package manager  {}\n",
            self.system
                .package_manager
                .map(|p| p.name())
                .unwrap_or("none detected")
        ));
        out.push_str(&format!(
            "python installer {}\n\n",
            self.system.python_installer.unwrap_or("none detected")
        ));
        for t in &self.tools {
            let mark = if t.installed() {
                "ok      "
            } else if t.def.optional {
                "optional"
            } else {
                "MISSING "
            };
            let where_ = t
                .path
                .as_ref()
                .map(|p| p.display().to_string())
                .unwrap_or_default();
            out.push_str(&format!(
                "{mark}  {:<8} {:<30} {where_}\n",
                t.def.name, t.def.purpose
            ));
        }
        let missing = self.missing();
        if missing.is_empty() {
            out.push_str("\nall tools are installed\n");
        } else {
            out.push_str(&format!(
                "\n{} tool(s) missing. To install:\n",
                missing.len()
            ));
            match self.install_all_command() {
                Some(cmd) => out.push_str(&format!("  {cmd}\n")),
                None => {
                    for t in missing {
                        out.push_str(&format!(
                            "  {:<8} {}\n",
                            t.def.name,
                            t.install.as_deref().unwrap_or("no known install method")
                        ));
                    }
                }
            }
        }
        out
    }
}

pub fn install_command(def: &ToolDef, system: &System) -> Option<String> {
    match def.source {
        Source::System { .. } => system.package_manager.map(|pm| {
            format!(
                "{} {}",
                pm.install_prefix(),
                def.source.package(pm).unwrap_or("?")
            )
        }),
        Source::Python(pkg) => system.python_installer.map(|py| format!("{py} {pkg}")),
    }
}

#[cfg(test)]
pub fn unknown_catalog_tools() -> Vec<&'static str> {
    crate::catalog::STEPS
        .iter()
        .flat_map(|s| {
            s.tool
                .into_iter()
                .chain(s.options.iter().filter_map(|o| o.tool))
        })
        .filter(|t| !TOOLS.iter().any(|d| d.name == *t))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn doctor_covers_every_catalog_tool() {
        assert!(
            unknown_catalog_tools().is_empty(),
            "{:?}",
            unknown_catalog_tools()
        );
    }

    #[test]
    fn install_all_groups_packages() {
        let system = System {
            os: "test".into(),
            kernel: "linux",
            package_manager: Some(PackageManager::Apt),
            python_installer: Some("pipx install"),
        };
        let tools = TOOLS
            .iter()
            .map(|def| ToolStatus {
                def: *def,
                path: (def.name == "file").then(|| PathBuf::from("/usr/bin/file")),
                install: install_command(def, &system),
            })
            .collect();
        let d = Doctor { system, tools };
        assert_eq!(
            d.install_all_command().unwrap(),
            "sudo apt install -y binwalk binutils yara ssdeep upx-ucl p7zip-full unzip rizin && pipx install flare-floss flare-capa"
        );
    }
}
