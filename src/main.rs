mod analyzer;
mod harness;
mod fuzzer;
mod mutator;
mod extractor;

use std::env;
use std::fs;
use std::path::Path;
use std::process;

use fuzzer::Fuzzer;
use harness::Harness;

fn usage(prog: &str) {
    eprintln!("usage:");
    eprintln!("  {prog} analyze <firmware.bin> [report.json]");
    eprintln!("  {prog} fuzz    <report.json> [crash_dir] [max_iters]");
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        usage(&args[0]);
        process::exit(1);
    }

    match args[1].as_str() {
        "analyze" => {
            if args.len() < 3 {
                usage(&args[0]);
                process::exit(1);
            }
            let firmware = &args[2];
            let report_path = args.get(3).map(String::as_str).unwrap_or("report.json");
            cmd_analyze(firmware, report_path);
        }
        "fuzz" => {
            if args.len() < 3 {
                usage(&args[0]);
                process::exit(1);
            }
            let report_path = &args[2];
            let crash_dir = args.get(3).map(String::as_str).unwrap_or("crashes");
            let max_iters = args
                .get(4)
                .and_then(|s| s.parse().ok())
                .unwrap_or(100_000u64);
            cmd_fuzz(report_path, crash_dir, max_iters);
        }
        other => {
            eprintln!("[!] unknown command: {other}");
            usage(&args[0]);
            process::exit(1);
        }
    }
}

fn cmd_analyze(firmware: &str, report_path: &str) {
    println!("[*] extracting {firmware} ...");
    extractor::extract(firmware);

    let basename = Path::new(firmware)
        .file_name()
        .expect("firmware path has no file name")
        .to_string_lossy();
    let extracted = format!("_{basename}.extracted");

    println!("[*] scanning secrets in {extracted} ...");
    extractor::scan(&extracted);

    println!("[*] analyzing binaries in {extracted} ...");
    let reports = analyzer::scan_directory(Path::new(&extracted));
    println!("[*] found {} interesting binaries", reports.len());

    for r in reports.iter().take(10) {
        println!(
            "    score={:<4} {}  (danger={}, input={})",
            r.score,
            r.path.display(),
            r.danger_funcs.len(),
            r.input_funcs.len()
        );
    }

    let json = serde_json::to_string_pretty(&reports).expect("failed to serialize report");
    fs::write(report_path, json).expect("failed to write report file");
    println!("[+] report written to {report_path}");
}

fn cmd_fuzz(report_path: &str, crash_dir: &str, max_iters: u64) {
    let data = fs::read_to_string(report_path).expect("cannot read report file");
    let reports: Vec<analyzer::BinaryReport> =
        serde_json::from_str(&data).expect("invalid report json");

    let Some(top) = reports.first() else {
        eprintln!("[!] report rỗng, không có target để fuzz");
        return;
    };

    let target = top.path.to_string_lossy().to_string();
    println!("[*] fuzzing target: {target} (score={})", top.score);

    let seeds: Vec<Vec<u8>> = vec![b"AAAA".to_vec()];

    let harness = Harness::new(&target, vec![], 1000);
    let mut fuzzer = Fuzzer::new(harness, crash_dir, seeds);
    fuzzer.run(max_iters);
}
