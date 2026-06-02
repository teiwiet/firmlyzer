use goblin::elf::*;
use walkdir::WalkDir;
use std::collections::HashSet;
use serde::{Deserialize, Serialize};
use rayon::prelude::*;
use std::{
    fs,
    path::{Path, PathBuf},
};
#[derive(Debug, Clone, Serialize, Deserialize)]
enum Arch {
    X86,
    X86_64,
    Mips,
    MipsEl,
    Arm32,
    Arm64,
    Unknown(u32),
}

impl Arch {
    fn from_elf_machine(machine: u16) -> Self {
        match machine {
            0x03 => Arch::X86,
            0x3E => Arch::X86_64,
            0x08 => Arch::Mips,
            0x0A => Arch::MipsEl,
            0x28 => Arch::Arm32,
            0xB7 => Arch::Arm64,
            other => Arch::Unknown(other as u32),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BinaryReport {
    pub path: PathBuf,
    pub danger_funcs: Vec<String>,
    pub input_funcs: Vec<String>,
    pub arch: Arch,
    pub score: u32,
}

const DANGER_FUNCS: &[&str] = &[
    "system", "popen", "wordexp",
    "execl", "execlp", "execle", "execv", "execvp", "execvpe",
    "execve", "execveat", "fexecve",
    "posix_spawn", "posix_spawnp",
    "strcpy", "stpcpy", "strcat", "wcscpy", "wcscat",
    "sprintf", "vsprintf",
    "gets",
];

const INPUT_FUNCS: &[&str] = &[
    "read", "pread", "readv", "preadv",
    "fread", "fgets", "getline", "getdelim",
    "getc", "getchar", "fgetc",
    "scanf", "fscanf", "sscanf",
    "vscanf", "vfscanf", "vsscanf",
    "recv", "recvfrom", "recvmsg", "recvmmsg",
    "getenv", "secure_getenv", "getopt", "getopt_long",
    "getpass", "msgrcv", "mq_receive",
];
fn extract_names(elf: &Elf) -> Vec<String> {
    let mut names = vec![];

    for sym in &elf.dynsyms {
        if let Some(name) = elf.dynstrtab.get_at(sym.st_name) {
            if !name.is_empty() {
                names.push(name.to_string());
            }
        }
    }
    for sym in &elf.syms {
        if let Some(name) = elf.strtab.get_at(sym.st_name) {
            if !name.is_empty() {
                names.push(name.to_string());
            }
        }
    }
    names
}

pub fn analyze_binary(path: &Path) -> Option<BinaryReport> {
    let data = fs::read(&path).ok()?;
    let elf = Elf::parse(&data).ok()?;

    let arch = Arch::from_elf_machine(elf.header.e_machine);
    
    let all_names: Vec<String> = extract_names(&elf);
    let all_names : HashSet<String> = extract_names(&elf).into_iter().collect();
    let danger_funcs: Vec<String> = all_names
        .iter()
        .filter(|f| DANGER_FUNCS.iter().any(|n| f.contains(n)))
        .cloned()
        .collect();
    let input_funcs: Vec<String> = all_names
        .iter()
        .filter(|n| INPUT_FUNCS.iter().any(|f| n.contains(f)))
        .cloned()
        .collect();

    if danger_funcs.is_empty() && input_funcs.is_empty(){
        return None;
    }

    let score = (danger_funcs.len() + input_funcs.len()*2) as u32;

    Some(BinaryReport{
        path : path.to_path_buf(),
        arch,
        danger_funcs,
        input_funcs,
        score
    })


}
pub fn scan_directory(dir: &Path) -> Vec<BinaryReport> {
    let paths: Vec<_> = WalkDir::new(dir)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
        .map(|e| e.path().to_path_buf())
        .collect();

    let mut reports: Vec<BinaryReport> = paths
        .par_iter()
        .filter_map(|p| analyze_binary(p))
        .collect();

    // Sort theo score cao nhất
    reports.sort_by(|a, b| b.score.cmp(&a.score));
    reports
}
