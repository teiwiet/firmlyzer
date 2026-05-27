mod analyzer;
mod harness;
mod fuzzer;
mod mutator;

use harness::Harness;
use fuzzer::Fuzzer;

fn main() {
    let harness = Harness::new(
        "qemu-mips",
        vec!["-L", "/home/teiwiet/firmwares/tplink/_tplink.bin.extracted/squashfs-root", "bin/busybox", "cat"],
        2000,
    );

    let seeds = vec![
        b"hello\n".to_vec(),
        b"world\n".to_vec(),
    ];

    let mut fuzzer = Fuzzer::new(harness, "./crashes", seeds);

    println!("[*] Fuzzing busybox cat via QEMU MIPS");
    println!("[*] Running 10,000 iterations...\n");

    fuzzer.run(10_000);
}