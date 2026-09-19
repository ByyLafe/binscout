use crate::analysis::{read_target, strings};
use crate::engine::{StepRequest, StepResult};
use goblin::Object;
use std::collections::BTreeSet;

struct Rule {
    category: usize,

    needle: &'static str,

    import_only: bool,
    why: &'static str,
}

const fn imp(category: usize, needle: &'static str, why: &'static str) -> Rule {
    Rule {
        category,
        needle,
        import_only: true,
        why,
    }
}
const fn s(category: usize, needle: &'static str, why: &'static str) -> Rule {
    Rule {
        category,
        needle,
        import_only: false,
        why,
    }
}

const CATEGORIES: [&str; 6] = [
    "Debugger detection",
    "VM / sandbox detection",
    "Timing & evasion",
    "Process enumeration & injection",
    "Pre-entry-point code",
    "Analysis tools named in strings",
];

const RULES: &[Rule] = &[
    imp(0, "IsDebuggerPresent", "classic PEB.BeingDebugged check"),
    imp(
        0,
        "CheckRemoteDebuggerPresent",
        "debugger check via NtQueryInformationProcess",
    ),
    imp(
        0,
        "NtQueryInformationProcess",
        "ProcessDebugPort / DebugFlags / DebugObjectHandle",
    ),
    imp(
        0,
        "ZwQueryInformationProcess",
        "ProcessDebugPort / DebugFlags",
    ),
    imp(0, "NtSetInformationThread", "ThreadHideFromDebugger"),
    imp(0, "ZwSetInformationThread", "ThreadHideFromDebugger"),
    imp(0, "OutputDebugStringA", "OutputDebugString trick"),
    imp(0, "OutputDebugStringW", "OutputDebugString trick"),
    imp(
        0,
        "NtQuerySystemInformation",
        "SystemKernelDebuggerInformation",
    ),
    imp(
        0,
        "DebugActiveProcess",
        "self-debugging to block other debuggers",
    ),
    imp(0, "DebugBreak", "breakpoint trick (weak signal)"),
    imp(
        0,
        "AddVectoredExceptionHandler",
        "exception-based anti-debug / SEH tricks (weak signal)",
    ),
    imp(
        0,
        "SetUnhandledExceptionFilter",
        "exception-based anti-debug (weak signal: also CRT startup)",
    ),
    imp(
        0,
        "RaiseException",
        "exception-based anti-debug (weak signal: also CRT)",
    ),
    imp(
        0,
        "CloseHandle",
        "invalid handle exception trick (weak signal)",
    ),
    imp(0, "NtClose", "invalid handle exception trick (weak signal)"),
    imp(
        0,
        "GetThreadContext",
        "hardware breakpoint detection (DR0-DR7) (weak signal: also SEH runtimes)",
    ),
    imp(
        0,
        "SetThreadContext",
        "hardware breakpoint clearing (weak signal: also SEH runtimes)",
    ),
    imp(0, "BlockInput", "blocks keyboard/mouse while running"),
    imp(0, "ptrace", "ptrace(PTRACE_TRACEME) self-attach check"),
    s(0, "TracerPid", "/proc/self/status TracerPid check"),
    s(
        0,
        "/proc/self/status",
        "reads own process status (weak signal)",
    ),
    s(0, "LD_PRELOAD", "checks for hooked libraries"),
    imp(0, "prctl", "PR_SET_DUMPABLE / ptrace hardening"),
    imp(0, "sysctl", "P_TRACED check (macOS/BSD)"),
    s(0, "BeingDebugged", "PEB field name in strings"),
    s(0, "NtGlobalFlag", "PEB NtGlobalFlag check"),
    s(1, "VirtualBox", "VirtualBox artefact"),
    s(1, "VBoxService", "VirtualBox guest service"),
    s(1, "VBoxTray", "VirtualBox guest tray"),
    s(1, "VBoxGuest", "VirtualBox guest driver"),
    s(1, "VBoxMouse", "VirtualBox guest driver"),
    s(1, "VBOX__", "VirtualBox ACPI table"),
    s(1, "vmware", "VMware artefact"),
    s(1, "VMware", "VMware artefact"),
    s(1, "vmtoolsd", "VMware Tools service"),
    s(1, "vmmouse", "VMware guest driver"),
    s(1, "vmhgfs", "VMware shared folders"),
    s(1, "VMwareService", "VMware Tools service"),
    s(1, "QEMU", "QEMU artefact"),
    s(1, "qemu-ga", "QEMU guest agent"),
    s(1, "XenVMM", "Xen hypervisor"),
    s(1, "Hyper-V", "Hyper-V"),
    s(1, "KVMKVMKVM", "KVM CPUID vendor string"),
    s(1, "Microsoft Hv", "Hyper-V CPUID vendor string"),
    s(1, "VMwareVMware", "VMware CPUID vendor string"),
    s(1, "XenVMMXenVMM", "Xen CPUID vendor string"),
    s(1, "prl hyperv", "Parallels CPUID vendor string"),
    s(1, "Parallels", "Parallels"),
    s(1, "sbiedll", "Sandboxie DLL check"),
    s(1, "SbieDll", "Sandboxie DLL check"),
    s(1, "cuckoo", "Cuckoo sandbox"),
    s(1, "cuckoomon", "Cuckoo monitor DLL"),
    s(1, "joebox", "Joe Sandbox"),
    s(1, "anubis", "Anubis sandbox"),
    s(1, "threatexpert", "ThreatExpert sandbox"),
    s(1, "sandbox", "generic sandbox string (weak signal)"),
    s(1, "SANDBOX", "generic sandbox string (weak signal)"),
    s(1, "wine_get_unix_file_name", "Wine detection"),
    s(
        1,
        "HARDWARE\\DEVICEMAP\\Scsi",
        "disk vendor check via registry",
    ),
    s(
        1,
        "SYSTEM\\CurrentControlSet\\Services\\Disk\\Enum",
        "disk vendor check via registry",
    ),
    s(
        1,
        "HARDWARE\\Description\\System",
        "BIOS / SystemBiosVersion check",
    ),
    s(1, "SystemBiosVersion", "BIOS vendor check"),
    s(1, "VideoBiosVersion", "video BIOS vendor check"),
    s(1, "MAC address", "MAC OUI check"),
    s(1, "08:00:27", "VirtualBox MAC OUI"),
    s(1, "00:05:69", "VMware MAC OUI"),
    s(1, "00:0C:29", "VMware MAC OUI"),
    s(1, "00:1C:14", "VMware MAC OUI"),
    s(1, "00:50:56", "VMware MAC OUI"),
    s(1, "/sys/class/dmi/id", "DMI vendor check (Linux)"),
    s(1, "/proc/cpuinfo", "CPU flags / hypervisor check (Linux)"),
    s(1, "hypervisor", "CPUID hypervisor bit check (weak signal)"),
    s(1, "innotek", "VirtualBox DMI vendor"),
    imp(1, "GetSystemInfo", "CPU count check (weak signal)"),
    imp(1, "GlobalMemoryStatusEx", "RAM size check (weak signal)"),
    imp(1, "GetDiskFreeSpaceExA", "disk size check (weak signal)"),
    imp(1, "GetDiskFreeSpaceExW", "disk size check (weak signal)"),
    imp(
        1,
        "GetCursorPos",
        "mouse movement check (sandbox has no user)",
    ),
    imp(1, "GetLastInputInfo", "user idle time check"),
    imp(
        1,
        "GetForegroundWindow",
        "user activity check (weak signal)",
    ),
    imp(1, "EnumDisplayDevicesA", "GPU vendor check"),
    imp(1, "SetupDiGetClassDevsA", "device enumeration (VM drivers)"),
    imp(1, "SetupDiGetClassDevsW", "device enumeration (VM drivers)"),
    imp(1, "GetAdaptersInfo", "MAC OUI check"),
    imp(1, "GetAdaptersAddresses", "MAC OUI check"),
    imp(1, "GetComputerNameA", "hostname check (sandbox names)"),
    imp(1, "GetComputerNameW", "hostname check (sandbox names)"),
    imp(1, "GetUserNameA", "username check (sandbox names)"),
    imp(1, "GetUserNameW", "username check (sandbox names)"),
    imp(
        1,
        "GetModuleHandleA",
        "checks for sandbox/hook DLLs (weak signal)",
    ),
    imp(2, "GetTickCount", "timing check (weak signal)"),
    imp(2, "GetTickCount64", "timing check (weak signal)"),
    imp(
        2,
        "QueryPerformanceCounter",
        "high-resolution timing check (weak signal: also CRT)",
    ),
    imp(2, "timeGetTime", "timing check (weak signal)"),
    imp(2, "NtDelayExecution", "sleep to outlast sandboxes"),
    imp(2, "SleepEx", "sleep to outlast sandboxes (weak signal)"),
    imp(2, "Sleep", "sleep to outlast sandboxes (weak signal)"),
    imp(2, "NtQueryPerformanceCounter", "timing check (weak signal)"),
    imp(2, "GetSystemTimeAsFileTime", "timing check (weak signal)"),
    imp(2, "SetTimer", "delayed execution (weak signal)"),
    imp(2, "CreateWaitableTimerA", "delayed execution"),
    imp(2, "CreateWaitableTimerW", "delayed execution"),
    imp(2, "WaitForSingleObject", "delayed execution (weak signal)"),
    imp(2, "nanosleep", "sleep to outlast sandboxes (weak signal)"),
    imp(2, "clock_gettime", "timing check (weak signal)"),
    s(2, "rdtsc", "rdtsc timing check"),
    s(2, "RDTSC", "rdtsc timing check"),
    imp(
        2,
        "GetKeyboardLayout",
        "locale/keyboard check (geo-evasion)",
    ),
    imp(
        2,
        "GetUserDefaultUILanguage",
        "language check (geo-evasion)",
    ),
    imp(2, "GetSystemDefaultLangID", "language check (geo-evasion)"),
    imp(2, "GetLocaleInfoA", "locale check (geo-evasion)"),
    imp(2, "GetLocaleInfoW", "locale check (geo-evasion)"),
    imp(
        2,
        "IsProcessorFeaturePresent",
        "CPU feature check (weak signal)",
    ),
    imp(3, "CreateToolhelp32Snapshot", "process enumeration"),
    imp(3, "Process32First", "process enumeration"),
    imp(3, "Process32FirstW", "process enumeration"),
    imp(3, "Process32Next", "process enumeration"),
    imp(3, "Process32NextW", "process enumeration"),
    imp(3, "Module32First", "module enumeration"),
    imp(3, "Module32Next", "module enumeration"),
    imp(3, "EnumProcesses", "process enumeration"),
    imp(3, "EnumWindows", "window enumeration (weak signal)"),
    imp(3, "FindWindowA", "looks for analysis tool windows"),
    imp(3, "FindWindowW", "looks for analysis tool windows"),
    imp(3, "FindWindowExA", "looks for analysis tool windows"),
    imp(3, "FindWindowExW", "looks for analysis tool windows"),
    imp(3, "OpenProcess", "opens another process (weak signal)"),
    imp(
        3,
        "TerminateProcess",
        "kills processes (weak signal: also CRT abort)",
    ),
    imp(3, "VirtualAllocEx", "remote memory allocation (injection)"),
    imp(3, "WriteProcessMemory", "remote memory write (injection)"),
    imp(3, "ReadProcessMemory", "remote memory read (weak signal)"),
    imp(3, "CreateRemoteThread", "remote thread (injection)"),
    imp(3, "CreateRemoteThreadEx", "remote thread (injection)"),
    imp(3, "NtCreateThreadEx", "remote thread (injection)"),
    imp(3, "RtlCreateUserThread", "remote thread (injection)"),
    imp(3, "QueueUserAPC", "APC injection"),
    imp(3, "NtQueueApcThread", "APC injection"),
    imp(3, "SetWindowsHookExA", "hook injection / keylogging"),
    imp(3, "SetWindowsHookExW", "hook injection / keylogging"),
    imp(3, "NtMapViewOfSection", "section mapping injection"),
    imp(3, "NtUnmapViewOfSection", "process hollowing"),
    imp(3, "ZwUnmapViewOfSection", "process hollowing"),
    imp(
        3,
        "ResumeThread",
        "process hollowing / suspended start (weak signal)",
    ),
    imp(3, "SetThreadContext", "process hollowing (weak signal)"),
    imp(
        3,
        "VirtualProtectEx",
        "remote memory protection change (injection)",
    ),
    imp(
        3,
        "VirtualProtect",
        "changes memory protection (weak signal: also runtimes)",
    ),
    imp(3, "NtProtectVirtualMemory", "changes memory protection"),
    imp(3, "AdjustTokenPrivileges", "privilege change (weak signal)"),
    imp(3, "LookupPrivilegeValueA", "privilege change (weak signal)"),
    imp(3, "LookupPrivilegeValueW", "privilege change (weak signal)"),
    imp(3, "LoadLibraryA", "dynamic API resolution (weak signal)"),
    imp(3, "LoadLibraryW", "dynamic API resolution (weak signal)"),
    imp(3, "GetProcAddress", "dynamic API resolution (weak signal)"),
    imp(3, "LdrLoadDll", "low-level DLL loading"),
    imp(3, "LdrGetProcedureAddress", "low-level API resolution"),
    imp(3, "mmap", "memory mapping (weak signal)"),
    imp(3, "mprotect", "changes memory protection (weak signal)"),
    imp(3, "memfd_create", "fileless execution (Linux)"),
    imp(3, "fexecve", "fileless execution (Linux)"),
    imp(3, "dlopen", "dynamic library loading (weak signal)"),
    imp(3, "dlsym", "dynamic API resolution (weak signal)"),
    s(3, "/proc/self/mem", "self memory patching (Linux)"),
    s(3, "/proc/self/exe", "self path (weak signal)"),
    s(3, "SeDebugPrivilege", "privilege escalation"),
    s(5, "ollydbg", "OllyDbg"),
    s(5, "OLLYDBG", "OllyDbg"),
    s(5, "x64dbg", "x64dbg"),
    s(5, "x32dbg", "x32dbg"),
    s(5, "windbg", "WinDbg"),
    s(5, "WinDbg", "WinDbg"),
    s(5, "idaq", "IDA"),
    s(5, "ida64", "IDA"),
    s(5, "idag", "IDA"),
    s(5, "ImmunityDebugger", "Immunity Debugger"),
    s(5, "procmon", "Process Monitor"),
    s(5, "ProcessHacker", "Process Hacker"),
    s(5, "procexp", "Process Explorer"),
    s(5, "wireshark", "Wireshark"),
    s(5, "Wireshark", "Wireshark"),
    s(5, "fiddler", "Fiddler"),
    s(5, "Fiddler", "Fiddler"),
    s(5, "tcpview", "TCPView"),
    s(5, "regmon", "Regmon"),
    s(5, "filemon", "Filemon"),
    s(5, "dnSpy", "dnSpy"),
    s(5, "ghidra", "Ghidra"),
    s(5, "radare", "radare2"),
    s(5, "pestudio", "PEStudio"),
    s(5, "PEiD", "PEiD"),
    s(5, "ollydbg.exe", "OllyDbg"),
    s(5, "HookExplorer", "HookExplorer"),
    s(5, "ImportREC", "ImportREC"),
    s(5, "PETools", "PE Tools"),
    s(5, "LordPE", "LordPE"),
    s(5, "SysInspector", "ESET SysInspector"),
    s(5, "autoruns", "Autoruns"),
    s(5, "Autoruns", "Autoruns"),
    s(5, "sysmon", "Sysmon"),
    s(5, "frida", "Frida"),
    s(5, "gdb", "GDB (weak signal: also debug info)"),
    s(5, "strace", "strace (weak signal)"),
    s(5, "ltrace", "ltrace (weak signal)"),
    s(5, "vboxservice", "VBoxService"),
];

fn imports_of(data: &[u8]) -> Vec<String> {
    match Object::parse(data) {
        Ok(Object::PE(pe)) => pe.imports.iter().map(|i| i.name.to_string()).collect(),
        Ok(Object::Elf(elf)) => elf
            .dynsyms
            .iter()
            .filter(|s| s.is_import())
            .filter_map(|s| elf.dynstrtab.get_at(s.st_name))
            .map(|n| n.split('@').next().unwrap_or(n).to_string())
            .collect(),
        Ok(Object::Mach(goblin::mach::Mach::Binary(m))) => m
            .imports()
            .map(|v| {
                v.iter()
                    .map(|i| i.name.trim_start_matches('_').to_string())
                    .collect()
            })
            .unwrap_or_default(),
        _ => Vec::new(),
    }
}

fn pe_tls(data: &[u8]) -> Option<String> {
    match Object::parse(data) {
        Ok(Object::PE(pe)) => {
            let opt = pe.header.optional_header?;
            let tls = opt.data_directories.get_tls_table()?;
            Some(format!(
                "TLS directory at RVA 0x{:x} ({} bytes): TLS callbacks run before the entry point",
                tls.virtual_address, tls.size
            ))
        }
        _ => None,
    }
}

pub struct Hit {
    pub category: usize,
    pub needle: &'static str,
    pub why: &'static str,
    pub source: &'static str,
}

pub fn scan(data: &[u8]) -> Vec<Hit> {
    let imports: BTreeSet<String> = imports_of(data)
        .into_iter()
        .map(|s| s.to_lowercase())
        .collect();

    // UTF-16 strings are decoded separately because the raw bytes hide them
    // (one NUL between every character).
    let text = String::from_utf8_lossy(data);
    let wide = strings::utf16le(data, 5).join("\n");
    let mut hits = Vec::new();
    for r in RULES {
        let needle_l = r.needle.to_lowercase();
        if imports.contains(&needle_l) {
            hits.push(Hit {
                category: r.category,
                needle: r.needle,
                why: r.why,
                source: "import",
            });
            continue;
        }
        if !r.import_only && (text.contains(r.needle) || wide.contains(r.needle)) {
            hits.push(Hit {
                category: r.category,
                needle: r.needle,
                why: r.why,
                source: "string",
            });
        }
    }
    hits
}

pub fn run(req: &StepRequest) -> StepResult {
    let mut result = StepResult::new(req.step);
    let data = match read_target(&req.target) {
        Ok(d) => d,
        Err(e) => return StepResult::failed(req.step, e),
    };
    let none = !req.any_checked();
    let hits = scan(&data);
    let mut strong_total = 0;

    for (cat, title) in CATEGORIES.iter().enumerate() {
        if !(none || req.is_checked(cat)) {
            continue;
        }
        let mut lines: Vec<String> = Vec::new();
        if cat == 4
            && let Some(tls) = pe_tls(&data)
        {
            lines.push(format!("  {tls} (weak signal: standard in many runtimes)"));
        }
        for h in hits.iter().filter(|h| h.category == cat) {
            let weak = h.why.contains("weak signal");
            if !weak {
                strong_total += 1;
            }
            lines.push(format!("  {:<32} {:<7} {}", h.needle, h.source, h.why));
        }
        result.push_line(format!("== {title} ({}) ==", lines.len()));
        if lines.is_empty() {
            result.push_line("  nothing found");
        }
        for l in lines {
            result.push_line(l);
        }
        result.push_line("");
    }

    // Only strong rules drive the verdict: CRT startup alone imports GetTickCount,
    // SetUnhandledExceptionFilter, TerminateProcess... and would flag every MSVC/MinGW binary.
    let weak_total = hits
        .iter()
        .filter(|h| h.why.contains("weak signal"))
        .count();
    result.push_line(match strong_total {
        0 => format!("verdict: no notable anti-analysis indicator ({weak_total} weak signals, usual runtime imports)"),
        1..=2 => format!("verdict: {strong_total} strong indicator(s), seen in legitimate software too ({weak_total} weak)"),
        3..=6 => format!("verdict: {strong_total} strong indicators, the sample probably checks its environment ({weak_total} weak)"),
        _ => format!("verdict: {strong_total} strong indicators, heavy anti-analysis / evasion ({weak_total} weak)"),
    });
    result
}
