use std::fs;
use std::process::Command;

use regex::Regex;
use walkdir::WalkDir;

const SENSITIVE: &[&str] = &[
    "passwd",
    "shadow",
    ".key",
    ".crt",
    ".pem",
    "wpa_supplicant",
    "hostapd",
    "dropbear",
];

pub fn extract(firmware: &str) {
    let status = Command::new("binwalk")
        .arg("-e")
        .arg(firmware)
        .status()
        .expect("Failed to run binwalk");
    if !status.success() {
        eprintln!("[!] binwalk return {:?}", status.code());
    }
}

pub fn scan(dir: &str) {
    let re_key = Regex::new(r"-----BEGIN .*PRIVATE KEY-----").unwrap();
    let re_pass = Regex::new(r"(?i)(password|passwd|pwd)\s*[:=]\s*\S+").unwrap();

    for entry in WalkDir::new(dir).into_iter().filter_map(|e| e.ok()) {
        if !entry.file_type().is_file() {
            continue;
        }
        let path = entry.path();
        let name = path.to_string_lossy().to_lowercase();

        // check extension
        for kw in SENSITIVE {
            if name.contains(kw) {
                println!("[FILE] {}", path.display());
                break;
            }
        }

        // grep nội dung
        if let Ok(bytes) = fs::read(path) {
            let text = String::from_utf8_lossy(&bytes);
            for (i, line) in text.lines().enumerate() {
                if re_key.is_match(line) {
                    println!("[KEY]  {}:{}", path.display(), i + 1);
                }
                if re_pass.is_match(line) {
                    println!("[PASS] {}:{}  {}", path.display(), i + 1, line.trim());
                }
            }
        }
    }
}
