pub mod anti;
pub mod entropy;
pub mod mitigations;
pub mod packer;
pub mod sections;

use goblin::Object;

#[derive(Debug, Clone)]
pub struct Region {
    pub name: String,
    pub offset: usize,
    pub size: usize,
}

pub fn file_regions(data: &[u8]) -> Result<Vec<Region>, String> {
    let obj = Object::parse(data).map_err(|e| format!("not a parseable executable: {e}"))?;
    let regions = match obj {
        Object::Elf(elf) => elf
            .section_headers
            .iter()
            .filter(|sh| sh.sh_type != goblin::elf::section_header::SHT_NOBITS && sh.sh_size > 0)
            .map(|sh| Region {
                name: elf
                    .shdr_strtab
                    .get_at(sh.sh_name)
                    .unwrap_or("?")
                    .to_string(),
                offset: sh.sh_offset as usize,
                size: sh.sh_size as usize,
            })
            .collect(),
        Object::PE(pe) => pe
            .sections
            .iter()
            .filter(|s| s.size_of_raw_data > 0)
            .map(|s| Region {
                name: s.name().unwrap_or("?").to_string(),
                offset: s.pointer_to_raw_data as usize,
                size: s.size_of_raw_data as usize,
            })
            .collect(),
        Object::Mach(goblin::mach::Mach::Binary(macho)) => macho
            .segments
            .iter()
            .filter(|s| s.filesize > 0)
            .map(|s| Region {
                name: s.name().unwrap_or("?").to_string(),
                offset: s.fileoff as usize,
                size: s.filesize as usize,
            })
            .collect(),
        _ => return Err("unsupported format (only ELF, PE and Mach-O have sections)".into()),
    };
    Ok(regions)
}
