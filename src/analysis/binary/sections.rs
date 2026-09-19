use crate::analysis::{human_size, read_target};
use crate::engine::{StepRequest, StepResult};
use goblin::Object;
use goblin::elf::{self, Elf};
use goblin::mach::{Mach, MachO};
use goblin::pe::PE;

struct Opts {
    header: bool,
    sections: bool,
    segments: bool,
    symbols: bool,
    virtual_addr: bool,
}

pub fn run(req: &StepRequest) -> StepResult {
    let mut result = StepResult::new(req.step);
    let data = match read_target(&req.target) {
        Ok(d) => d,
        Err(e) => return StepResult::failed(req.step, e),
    };
    let none = !req.any_checked();
    let opts = Opts {
        header: none || req.is_checked(0),
        sections: req.is_checked(1),
        segments: req.is_checked(2),
        symbols: req.is_checked(3),
        virtual_addr: req.is_checked(4),
    };

    let lines = match Object::parse(&data) {
        Ok(Object::Elf(elf)) => describe_elf(&elf, &opts),
        Ok(Object::PE(pe)) => describe_pe(&pe, &opts),
        Ok(Object::Mach(Mach::Binary(macho))) => describe_macho(&macho, &opts),
        Ok(Object::Mach(Mach::Fat(fat))) => vec![format!(
            "Mach-O fat binary with {} architecture(s); analyze a thin slice",
            fat.narches
        )],
        Ok(Object::Archive(a)) => vec![format!("Unix archive with {} member(s)", a.len())],
        Ok(Object::COFF(_)) => vec!["COFF object file (no full support yet)".to_string()],
        Ok(Object::Unknown(magic)) => vec![format!(
            "unknown format (magic 0x{magic:X}): not an ELF/PE/Mach-O executable"
        )],
        Ok(_) => vec!["unsupported object format".to_string()],
        Err(e) => return StepResult::failed(req.step, format!("not a parseable executable: {e}")),
    };
    for l in lines {
        result.push_line(l);
    }
    result
}

fn perm(r: bool, w: bool, x: bool) -> String {
    format!(
        "{}{}{}",
        if r { 'r' } else { '-' },
        if w { 'w' } else { '-' },
        if x { 'x' } else { '-' }
    )
}

fn describe_elf(elf: &Elf, o: &Opts) -> Vec<String> {
    use elf::program_header::{PF_R, PF_W, PF_X, pt_to_str};
    use elf::section_header::{SHF_ALLOC, SHF_EXECINSTR, SHF_WRITE, sht_to_str};
    let mut out = Vec::new();
    let h = &elf.header;

    if o.header {
        out.push("== ELF header ==".to_string());
        out.push(format!(
            "class        ELF{}, {}",
            if elf.is_64 { 64 } else { 32 },
            if elf.little_endian {
                "little-endian"
            } else {
                "big-endian"
            }
        ));
        out.push(format!("type         {}", elf::header::et_to_str(h.e_type)));
        out.push(format!(
            "machine      {}",
            elf::header::machine_to_str(h.e_machine)
        ));
        out.push(format!("entry point  0x{:x}", h.e_entry));
        out.push(format!(
            "interpreter  {}",
            elf.interpreter.unwrap_or("none (static)")
        ));
        if let Some(soname) = elf.soname {
            out.push(format!("soname       {soname}"));
        }
        if !elf.libraries.is_empty() {
            out.push(format!("needed       {}", elf.libraries.join(", ")));
        }
        if !elf.rpaths.is_empty() {
            out.push(format!("rpath        {}", elf.rpaths.join(":")));
        }
        out.push(format!(
            "sections     {}   segments {}",
            elf.section_headers.len(),
            elf.program_headers.len()
        ));
        out.push(format!(
            "symbols      {} static, {} dynamic",
            elf.syms.len(),
            elf.dynsyms.len()
        ));
        out.push(String::new());
    }

    if o.sections {
        out.push(format!("== Sections ({}) ==", elf.section_headers.len()));
        let col = if o.virtual_addr { "address" } else { "offset" };
        out.push(format!(
            "{:>3} {:<24} {:<14} {:>16} {:>10} {:>5}",
            "#", "name", "type", col, "size", "perm"
        ));
        for (i, sh) in elf.section_headers.iter().enumerate() {
            let name = elf.shdr_strtab.get_at(sh.sh_name).unwrap_or("?");
            let flags = sh.sh_flags as u32;
            let addr = if o.virtual_addr {
                sh.sh_addr
            } else {
                sh.sh_offset
            };
            out.push(format!(
                "{i:>3} {:<24} {:<14} {:>#16x} {:>10} {:>5}",
                name,
                sht_to_str(sh.sh_type).trim_start_matches("SHT_"),
                addr,
                human_size(sh.sh_size),
                perm(
                    flags & SHF_ALLOC != 0,
                    flags & SHF_WRITE != 0,
                    flags & SHF_EXECINSTR != 0
                )
            ));
        }
        out.push(String::new());
    }

    if o.segments {
        out.push(format!(
            "== Program headers ({}) ==",
            elf.program_headers.len()
        ));
        out.push(format!(
            "{:<14} {:>16} {:>16} {:>10} {:>10} {:>5}",
            "type", "offset", "vaddr", "filesz", "memsz", "perm"
        ));
        for ph in &elf.program_headers {
            out.push(format!(
                "{:<14} {:>#16x} {:>#16x} {:>10} {:>10} {:>5}",
                pt_to_str(ph.p_type).trim_start_matches("PT_"),
                ph.p_offset,
                ph.p_vaddr,
                human_size(ph.p_filesz),
                human_size(ph.p_memsz),
                perm(
                    ph.p_flags & PF_R != 0,
                    ph.p_flags & PF_W != 0,
                    ph.p_flags & PF_X != 0
                )
            ));
        }
        out.push(String::new());
    }

    if o.symbols {
        let mut imports = Vec::new();
        let mut exports = Vec::new();
        for sym in elf.dynsyms.iter() {
            let name = elf.dynstrtab.get_at(sym.st_name).unwrap_or("?");
            if name.is_empty() {
                continue;
            }
            if sym.is_import() {
                imports.push(name.to_string());
            } else if sym.st_bind() == elf::sym::STB_GLOBAL || sym.st_bind() == elf::sym::STB_WEAK {
                exports.push(format!("{name} @ {:#x}", sym.st_value));
            }
        }
        imports.sort();
        imports.dedup();
        out.push(format!("== Imports ({}) ==", imports.len()));
        out.extend(imports.iter().map(|s| format!("  {s}")));
        out.push(String::new());
        out.push(format!("== Exports ({}) ==", exports.len()));
        out.extend(exports.iter().map(|s| format!("  {s}")));
        out.push(String::new());
    }
    out
}

fn describe_pe(pe: &PE, o: &Opts) -> Vec<String> {
    use goblin::pe::section_table::{
        IMAGE_SCN_MEM_EXECUTE, IMAGE_SCN_MEM_READ, IMAGE_SCN_MEM_WRITE,
    };
    let mut out = Vec::new();
    let coff = &pe.header.coff_header;

    if o.header {
        out.push("== PE header ==".to_string());
        out.push(format!(
            "format       PE{}{}",
            if pe.is_64 { "32+" } else { "32" },
            if pe.is_lib { " (DLL)" } else { "" }
        ));
        out.push(format!(
            "machine      {}",
            goblin::pe::header::machine_to_str(coff.machine)
        ));
        out.push(format!("entry point  0x{:x} (RVA)", pe.entry));
        out.push(format!("image base   0x{:x}", pe.image_base));
        if let Some(opt) = &pe.header.optional_header {
            out.push(format!("subsystem    {}", opt.windows_fields.subsystem));
            out.push(format!(
                "dll chars    0x{:04x}",
                opt.windows_fields.dll_characteristics
            ));
        }
        if let Some(name) = pe.name {
            out.push(format!("name         {name}"));
        }
        if let Some(ts) = chrono::DateTime::from_timestamp(coff.time_date_stamp as i64, 0) {
            out.push(format!(
                "compiled     {}",
                ts.format("%Y-%m-%d %H:%M:%S UTC")
            ));
        }
        if !pe.libraries.is_empty() {
            out.push(format!("libraries    {}", pe.libraries.join(", ")));
        }
        out.push(format!(
            "sections     {}   imports {}   exports {}",
            pe.sections.len(),
            pe.imports.len(),
            pe.exports.len()
        ));
        out.push(String::new());
    }

    if o.sections {
        out.push(format!("== Sections ({}) ==", pe.sections.len()));
        let col = if o.virtual_addr {
            "virt addr"
        } else {
            "raw offset"
        };
        out.push(format!(
            "{:>3} {:<10} {:>12} {:>10} {:>10} {:>5}",
            "#", "name", col, "raw size", "virt size", "perm"
        ));
        for (i, s) in pe.sections.iter().enumerate() {
            let addr = if o.virtual_addr {
                pe.image_base + s.virtual_address as u64
            } else {
                s.pointer_to_raw_data as u64
            };
            let c = s.characteristics;
            out.push(format!(
                "{i:>3} {:<10} {:>#12x} {:>10} {:>10} {:>5}",
                s.name().unwrap_or("?"),
                addr,
                human_size(s.size_of_raw_data as u64),
                human_size(s.virtual_size as u64),
                perm(
                    c & IMAGE_SCN_MEM_READ != 0,
                    c & IMAGE_SCN_MEM_WRITE != 0,
                    c & IMAGE_SCN_MEM_EXECUTE != 0
                )
            ));
        }
        out.push(String::new());
    }

    if o.segments {
        out.push("== Program headers: not applicable to PE (see sections) ==".to_string());
        out.push(String::new());
    }

    if o.symbols {
        out.push(format!("== Imports ({}) ==", pe.imports.len()));
        let mut current = "";
        for imp in &pe.imports {
            if imp.dll != current {
                current = imp.dll;
                out.push(format!("  [{current}]"));
            }
            let addr = if o.virtual_addr {
                pe.image_base + imp.rva as u64
            } else {
                imp.offset as u64
            };
            let name = if imp.name.is_empty() {
                format!("ordinal {}", imp.ordinal)
            } else {
                imp.name.to_string()
            };
            out.push(format!("    {name:<40} {addr:#x}"));
        }
        out.push(String::new());
        out.push(format!("== Exports ({}) ==", pe.exports.len()));
        for exp in &pe.exports {
            let addr = if o.virtual_addr {
                pe.image_base + exp.rva as u64
            } else {
                exp.offset.unwrap_or(0) as u64
            };
            out.push(format!(
                "    {:<40} {addr:#x}",
                exp.name.unwrap_or("(unnamed)")
            ));
        }
        out.push(String::new());
    }
    out
}

fn describe_macho(m: &MachO, o: &Opts) -> Vec<String> {
    let mut out = Vec::new();
    if o.header {
        out.push("== Mach-O header ==".to_string());
        out.push(format!(
            "class        {}",
            if m.is_64 { "64-bit" } else { "32-bit" }
        ));
        out.push(format!(
            "cpu          {}",
            goblin::mach::cputype::get_arch_name_from_types(m.header.cputype, m.header.cpusubtype)
                .unwrap_or("?")
        ));
        out.push(format!(
            "filetype     {}",
            goblin::mach::header::filetype_to_str(m.header.filetype)
        ));
        out.push(format!("entry point  0x{:x}", m.entry));
        if let Some(name) = m.name {
            out.push(format!("name         {name}"));
        }
        if !m.libs.is_empty() {
            out.push(format!("libraries    {}", m.libs.join(", ")));
        }
        out.push(String::new());
    }
    if o.sections || o.segments {
        out.push(format!("== Segments ({}) ==", m.segments.len()));
        out.push(format!(
            "{:<18} {:>16} {:>16} {:>10} {:>10}",
            "name", "fileoff", "vmaddr", "filesize", "vmsize"
        ));
        for s in &m.segments {
            out.push(format!(
                "{:<18} {:>#16x} {:>#16x} {:>10} {:>10}",
                s.name().unwrap_or("?"),
                s.fileoff,
                s.vmaddr,
                human_size(s.filesize),
                human_size(s.vmsize)
            ));
            if o.sections
                && let Ok(sections) = s.sections()
            {
                for (sec, _) in sections {
                    let addr = if o.virtual_addr {
                        sec.addr
                    } else {
                        sec.offset as u64
                    };
                    out.push(format!(
                        "  {:<16} {:>#16x} {:>10}",
                        sec.name().unwrap_or("?"),
                        addr,
                        human_size(sec.size)
                    ));
                }
            }
        }
        out.push(String::new());
    }
    if o.symbols {
        let imports = m.imports().unwrap_or_default();
        out.push(format!("== Imports ({}) ==", imports.len()));
        out.extend(
            imports
                .iter()
                .map(|i| format!("  {:<40} {}", i.name, i.dylib)),
        );
        out.push(String::new());
        let exports = m.exports().unwrap_or_default();
        out.push(format!("== Exports ({}) ==", exports.len()));
        out.extend(
            exports
                .iter()
                .map(|e| format!("  {:<40} {:#x}", e.name, e.offset)),
        );
        out.push(String::new());
    }
    out
}
