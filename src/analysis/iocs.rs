use crate::analysis::{read_target, strings};
use crate::engine::{StepRequest, StepResult};
use regex::Regex;
use std::collections::BTreeSet;
use std::sync::OnceLock;

const NOT_TLDS: &[&str] = &[
    "dll", "exe", "sys", "so", "dylib", "txt", "log", "ini", "cfg", "conf", "json", "xml", "yml",
    "yaml", "png", "jpg", "jpeg", "gif", "bmp", "ico", "svg", "pdb", "obj", "lib", "h", "c", "cpp",
    "hpp", "rs", "go", "py", "pyc", "js", "ts", "css", "html", "htm", "php", "asp", "aspx", "jsp",
    "class", "jar", "zip", "rar", "gz", "tar", "bz2", "xz", "7z", "cab", "msi", "bat", "cmd",
    "ps1", "vbs", "sh", "pl", "rb", "lua", "dat", "bin", "db", "sqlite", "pem", "key", "crt",
    "cer", "der", "pfx", "p12", "tmp", "bak", "old", "manifest", "mui", "cat", "inf", "drv", "ocx",
    "cpl", "scr", "lnk", "url", "reg", "wav", "mp3", "mp4", "avi", "mkv", "ttf", "otf", "woff",
    "woff2", "eot", "md", "rst", "csv", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "pdf", "rtf",
    "nls", "res", "rc", "def", "map", "sym", "dmp", "cc", "cxx", "hxx", "inl", "tcc", "text",
    "data", "rodata", "bss", "init", "fini", "plt", "got", "dynamic", "interp", "comment", "note",
    "eh_frame", "rela", "dynsym", "dynstr", "symtab", "strtab", "shstrtab", "idata", "edata",
    "rsrc", "reloc", "tls", "crt", "xdata", "pdata", "so.", "a", "o", "d", "s", "cs", "vb",
    "swift",
];

const VALID_TLDS: &[&str] = &[
    "com",
    "net",
    "org",
    "io",
    "info",
    "biz",
    "ru",
    "cn",
    "de",
    "fr",
    "uk",
    "us",
    "eu",
    "co",
    "me",
    "tv",
    "xyz",
    "top",
    "site",
    "online",
    "club",
    "pw",
    "cc",
    "to",
    "ws",
    "in",
    "br",
    "jp",
    "kr",
    "nl",
    "it",
    "es",
    "pl",
    "ua",
    "by",
    "kz",
    "ir",
    "tr",
    "vn",
    "id",
    "au",
    "ca",
    "ch",
    "se",
    "no",
    "fi",
    "dk",
    "be",
    "at",
    "cz",
    "sk",
    "hu",
    "ro",
    "bg",
    "gr",
    "pt",
    "mx",
    "ar",
    "cl",
    "za",
    "ng",
    "ke",
    "eg",
    "sa",
    "ae",
    "il",
    "hk",
    "tw",
    "sg",
    "my",
    "th",
    "ph",
    "nz",
    "onion",
    "bit",
    "app",
    "dev",
    "cloud",
    "shop",
    "store",
    "tech",
    "link",
    "live",
    "life",
    "world",
    "today",
    "space",
    "fun",
    "icu",
    "buzz",
    "gov",
    "edu",
    "mil",
    "int",
    "su",
    "tk",
    "ml",
    "ga",
    "cf",
    "gq",
    "ly",
    "sh",
    "am",
    "fm",
    "is",
    "ie",
    "lu",
    "li",
    "lv",
    "lt",
    "ee",
    "md",
    "rs",
    "si",
    "hr",
    "ba",
    "mk",
    "al",
    "ge",
    "az",
    "uz",
    "kg",
    "tj",
    "mn",
    "pk",
    "bd",
    "lk",
    "np",
    "ai",
    "gg",
    "im",
    "je",
    "st",
    "so",
    "re",
    "zone",
    "digital",
    "network",
    "download",
    "email",
    "host",
    "press",
    "systems",
    "solutions",
    "services",
    "support",
    "center",
];

struct Patterns {
    url: Regex,
    ipv4: Regex,
    ipv6: Regex,
    domain: Regex,
    email: Regex,
    win_path: Regex,
    unix_path: Regex,
    registry: Regex,
    base64: Regex,
    btc: Regex,
    eth: Regex,
    xmr: Regex,
    user_agent: Regex,
    mutex: Regex,
}

fn patterns() -> &'static Patterns {
    static P: OnceLock<Patterns> = OnceLock::new();
    P.get_or_init(|| Patterns {
        url: Regex::new(r#"(?i)\b(?:https?|ftp|ftps|ws|wss|tcp|udp|smb|ldap|irc)://[^\s"'<>{}|\\^`\[\]]{3,}"#).unwrap(),
        ipv4: Regex::new(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?::\d{1,5})?\b").unwrap(),
        ipv6: Regex::new(r"\b(?:[0-9a-fA-F]{1,4}:){4,7}[0-9a-fA-F]{1,4}\b").unwrap(),
        domain: Regex::new(r"(?i)\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}\b").unwrap(),
        email: Regex::new(r"(?i)\b[a-z0-9._%+-]+@(?:[a-z0-9-]+\.)+[a-z]{2,24}\b").unwrap(),
        win_path: Regex::new(r#"(?i)(?:[a-z]:\\|\\\\[^\s\\]+\\|%[a-z_]+%\\)[^\s"'<>|*?]{2,}"#).unwrap(),
        unix_path: Regex::new(r#"(?:^|[\s"'=:(])(/(?:usr|etc|tmp|var|home|root|bin|sbin|opt|proc|dev|sys|lib|lib64|mnt|media|run|srv|boot|data|private|Library|Applications|Users)/[^\s"'<>|*?:)]*)"#).unwrap(),
        registry: Regex::new(r"(?i)\b(?:HKEY_(?:LOCAL_MACHINE|CURRENT_USER|CLASSES_ROOT|USERS|CURRENT_CONFIG)|HK(?:LM|CU|CR|U|CC))\\[^\s\x22']{2,}").unwrap(),
        base64: Regex::new(r"\b(?:[A-Za-z0-9+/]{4}){10,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?").unwrap(),
        btc: Regex::new(r"\b(?:bc1[a-z0-9]{25,62}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b").unwrap(),
        eth: Regex::new(r"\b0x[a-fA-F0-9]{40}\b").unwrap(),
        xmr: Regex::new(r"\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b").unwrap(),
        user_agent: Regex::new(r"(?i)\b(?:Mozilla|curl|Wget|python-requests|Java|okhttp|Go-http-client)/[0-9][^\r\n\x00]{0,120}").unwrap(),
        mutex: Regex::new(r"(?i)\b(?:Global|Local)\\[A-Za-z0-9_\-{}.]{4,}").unwrap(),
    })
}

fn boring_domain(d: &str) -> bool {
    let lower = d.to_lowercase();
    let tld = lower.rsplit('.').next().unwrap_or("");
    // File extensions win over TLDs (.cc, .so, .sh are both): a binary's strings contain
    // far more file names than hostnames.
    if NOT_TLDS.contains(&tld) || !VALID_TLDS.contains(&tld) {
        return true;
    }

    lower.chars().all(|c| c.is_ascii_digit() || c == '.')
        || lower.starts_with("www.w3.org")
        || lower.contains("schemas.microsoft.com")
        || lower.contains("schemas.xmlsoap.org")
        || lower.ends_with(".microsoft.com")
        || lower.ends_with("crl.microsoft.com")
        || lower.ends_with("ocsp.digicert.com")
        || lower.ends_with("digicert.com")
        || lower.ends_with("verisign.com")
        || lower.ends_with("sectigo.com")
        || lower.ends_with("comodoca.com")
        || lower.ends_with("globalsign.com")
        || lower.ends_with("golang.org")
        || lower.ends_with("google.golang.org")
        || lower.ends_with("gnu.org")
        || lower.ends_with("apache.org")
        || lower.ends_with("rust-lang.org")
        || lower.ends_with("crates.io")
        || lower.ends_with("github.com")
        || lower.ends_with("python.org")
        || lower.ends_with("openssl.org")
        || lower.ends_with("sourceforge.net")
        || lower.ends_with("mozilla.org")
        || lower.ends_with("apple.com")
        || lower.ends_with("ubuntu.com")
        || lower.ends_with("debian.org")
}

fn boring_ip(ip: &str) -> bool {
    let host = ip.split(':').next().unwrap_or(ip);
    let octets: Vec<u8> = host.split('.').filter_map(|o| o.parse().ok()).collect();
    if octets.len() != 4 {
        return true;
    }
    matches!(octets[0], 0 | 127 | 255)
        || (octets[0] == 169 && octets[1] == 254)
        || octets == [1, 0, 0, 0]
        || octets.iter().all(|o| *o == octets[0])
        || host.starts_with("1.0.")
        || host.starts_with("2.0.")
        || host.starts_with("3.0.")
}

fn add(set: &mut BTreeSet<String>, re: &Regex, text: &str, keep: impl Fn(&str) -> bool) {
    for m in re.find_iter(text) {
        let s = m.as_str().trim_end_matches(['.', ',', ';', ')', '"', '\'']);
        if keep(s) {
            set.insert(s.to_string());
        }
    }
}

#[derive(Debug, Default)]
pub struct Iocs {
    pub urls: BTreeSet<String>,
    pub ips: BTreeSet<String>,
    pub domains: BTreeSet<String>,
    pub emails: BTreeSet<String>,
    pub paths: BTreeSet<String>,
    pub registry: BTreeSet<String>,
    pub base64: BTreeSet<String>,
    pub misc: BTreeSet<String>,
}

pub fn extract(strings: &[String]) -> Iocs {
    let p = patterns();
    let mut iocs = Iocs::default();
    for s in strings {
        add(&mut iocs.urls, &p.url, s, |_| true);
        add(&mut iocs.ips, &p.ipv4, s, |ip| !boring_ip(ip));
        add(&mut iocs.ips, &p.ipv6, s, |ip| {
            !ip.eq_ignore_ascii_case("::1") && ip.matches(':').count() >= 4
        });
        add(&mut iocs.emails, &p.email, s, |_| true);
        add(&mut iocs.paths, &p.win_path, s, |_| true);
        for c in p.unix_path.captures_iter(s) {
            iocs.paths.insert(c[1].to_string());
        }
        add(&mut iocs.registry, &p.registry, s, |_| true);
        add(&mut iocs.base64, &p.base64, s, |b| {
            let upper = b.chars().filter(|c| c.is_ascii_uppercase()).count();
            let lower = b.chars().filter(|c| c.is_ascii_lowercase()).count();
            let digit = b.chars().filter(|c| c.is_ascii_digit()).count();
            // Long identifiers and padding also match the base64 alphabet; real blobs mix cases and digits.
            upper > 2 && lower > 2 && digit > 1 && !b.contains("AAAAAAAA")
        });
        add(&mut iocs.misc, &p.btc, s, |w| {
            w.len() >= 26 && has_mixed_case(w)
        });
        add(&mut iocs.misc, &p.eth, s, |_| true);
        add(&mut iocs.misc, &p.xmr, s, |_| true);
        add(&mut iocs.misc, &p.user_agent, s, |_| true);
        add(&mut iocs.misc, &p.mutex, s, |_| true);

        for m in p.domain.find_iter(s) {
            let d = m.as_str();
            let inside_url = iocs.urls.iter().any(|u| u.contains(d))
                || iocs.emails.iter().any(|e| e.ends_with(d));
            if !inside_url && !boring_domain(d) {
                iocs.domains.insert(d.to_string());
            }
        }
    }
    iocs
}

fn has_mixed_case(s: &str) -> bool {
    s.chars().any(|c| c.is_ascii_uppercase()) && s.chars().any(|c| c.is_ascii_lowercase())
}

impl Iocs {
    pub fn total(&self) -> usize {
        self.urls.len()
            + self.ips.len()
            + self.domains.len()
            + self.emails.len()
            + self.paths.len()
            + self.registry.len()
            + self.base64.len()
            + self.misc.len()
    }
}

pub fn run(req: &StepRequest) -> StepResult {
    let mut result = StepResult::new(req.step);
    let data = match read_target(&req.target) {
        Ok(d) => d,
        Err(e) => return StepResult::failed(req.step, e),
    };
    let strs = strings::all(&data, 6);
    let iocs = extract(&strs);
    let none = !req.any_checked();
    let want = |i: usize| none || req.is_checked(i);

    let sections: [(&str, &BTreeSet<String>, usize); 8] = [
        ("URLs", &iocs.urls, 0),
        ("IP addresses", &iocs.ips, 1),
        ("Domain names", &iocs.domains, 2),
        ("Email addresses", &iocs.emails, 3),
        ("File paths", &iocs.paths, 4),
        ("Registry keys", &iocs.registry, 5),
        ("Base64 blobs", &iocs.base64, 6),
        ("Wallets, user agents, mutexes", &iocs.misc, 7),
    ];
    let mut shown = 0;
    for (title, set, idx) in sections {
        if !want(idx) {
            continue;
        }
        result.push_line(format!("== {title} ({}) ==", set.len()));
        for item in set.iter().take(300) {
            let item: String = item.chars().take(200).collect();
            result.push_line(format!("  {item}"));
        }
        if set.len() > 300 {
            result.push_line(format!("  ... {} more", set.len() - 300));
        }
        result.push_line("");
        shown += set.len();
    }
    result.push_line(format!(
        "{shown} indicator(s) from {} strings (total found: {})",
        strs.len(),
        iocs.total()
    ));
    result.push_line(
        "note: strings of a benign program also match; treat these as leads, not verdicts",
    );
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_common_iocs() {
        let strs = vec![
            "connect to http://evil.example.com/gate.php?id=1 now".to_string(),
            "backup 185.220.101.4:8080 and kernel32.dll".to_string(),
            "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run".to_string(),
            "C:\\Users\\Public\\payload.exe".to_string(),
            "mail admin@example.org".to_string(),
            "Global\\MyMutex_123".to_string(),
        ];
        let i = extract(&strs);
        assert!(
            i.urls
                .iter()
                .any(|u| u.starts_with("http://evil.example.com/gate.php"))
        );
        assert!(i.ips.contains("185.220.101.4:8080"));
        assert!(i.registry.iter().any(|r| r.starts_with("HKLM\\Software")));
        assert!(i.paths.contains("C:\\Users\\Public\\payload.exe"));
        assert!(i.emails.contains("admin@example.org"));
        assert!(i.misc.contains("Global\\MyMutex_123"));
        assert!(!i.domains.contains("kernel32.dll"));
        assert!(
            !i.domains.contains("evil.example.com"),
            "domain inside a URL is not repeated"
        );
    }
}
