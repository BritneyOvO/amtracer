use anyhow::{Context, Result, bail, ensure};
use sha2::{Digest, Sha256};
use std::{
    env, fs,
    path::{Path, PathBuf},
    process::Command,
};

fn main() -> Result<()> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .context("workspace root")?;
    let mut args = env::args().skip(1);
    match args.next().as_deref() {
        Some("build") => build(root),
        Some("sync-uapi") => {
            let kernel = PathBuf::from(
                args.next()
                    .context("usage: cargo xtask sync-uapi KERNEL_ROOT")?,
            );
            sync_uapi(root, &kernel)
        }
        Some("gen-uapi") => generate_uapi(root),
        _ => bail!("usage: cargo xtask {{build|sync-uapi KERNEL_ROOT|gen-uapi}}"),
    }
}

fn ndk(root: &Path) -> Result<PathBuf> {
    let path = env::var_os("ANDROID_NDK_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| root.join("../../../prebuilts/ndk-r23"));
    path.canonicalize()
        .context("set ANDROID_NDK_HOME to the Android NDK")
}

fn run(command: &mut Command) -> Result<()> {
    eprintln!("{command:?}");
    ensure!(
        command.status().context("starting command")?.success(),
        "command failed"
    );
    Ok(())
}

fn build(root: &Path) -> Result<()> {
    run(Command::new("cargo").current_dir(root).args([
        "+nightly",
        "build",
        "-p",
        "amtracer-ebpf",
        "--target",
        "bpfel-unknown-none",
        "--release",
        "-Z",
        "build-std=core",
        "--locked",
    ]))?;
    let linker =
        ndk(root)?.join("toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android30-clang");
    run(Command::new("cargo")
        .current_dir(root)
        .env("CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER", linker)
        .args([
            "build",
            "-p",
            "amtracer",
            "--release",
            "--target",
            "aarch64-linux-android",
            "--locked",
        ]))?;
    let output = root.join("artifacts");
    fs::create_dir_all(&output)?;
    fs::copy(
        root.join("target/aarch64-linux-android/release/amtracer"),
        output.join("amtracer"),
    )?;
    fs::copy(
        root.join("target/bpfel-unknown-none/release/amtracer-ebpf"),
        output.join("amtracer-ebpf.o"),
    )?;
    eprintln!("Android artifacts: {}", output.display());
    Ok(())
}

fn sync_uapi(root: &Path, kernel: &Path) -> Result<()> {
    let names = ["ktools.h", "syscall_trace.h", "binder_trace.h", "prctl.h"];
    fs::create_dir_all(root.join("uapi/linux"))?;
    let mut provenance = String::from(
        "# UAPI source snapshot\n\nExplicitly refreshed by cargo xtask sync-uapi.\n\n",
    );
    let revision = Command::new("git")
        .args(["-C"])
        .arg(kernel)
        .args(["rev-parse", "HEAD"])
        .output()?;
    if revision.status.success() {
        provenance.push_str(&format!("Kernel HEAD: `{}`. Working tree may contain changes; hashes identify the exact files.\n\n", String::from_utf8_lossy(&revision.stdout).trim()));
    }
    for name in names {
        let source = kernel.join("include/uapi/linux").join(name);
        let bytes = fs::read(&source).with_context(|| format!("reading {}", source.display()))?;
        fs::write(root.join("uapi/linux").join(name), &bytes)?;
        let hash: String = Sha256::digest(&bytes)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        provenance.push_str(&format!("* include/uapi/linux/{name}: `{hash}`\n"));
    }
    let syscall_header = kernel.join("include/uapi/asm-generic/unistd.h");
    let bytes = fs::read(syscall_header)?;
    fs::create_dir_all(root.join("uapi/asm-generic"))?;
    fs::write(root.join("uapi/asm-generic/unistd.h"), &bytes)?;
    let hash: String = Sha256::digest(&bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    provenance.push_str(&format!("* include/uapi/asm-generic/unistd.h: `{hash}`\n"));
    fs::write(root.join("uapi/SOURCE.md"), provenance)?;
    generate_uapi(root)
}

fn generate_uapi(root: &Path) -> Result<()> {
    let sysroot = ndk(root)?.join("toolchains/llvm/prebuilt/linux-x86_64/sysroot");
    let bindings = bindgen::Builder::default()
        .header(root.join("uapi/wrapper.h").to_string_lossy())
        .clang_arg("--target=aarch64-linux-android30")
        .clang_arg(format!("--sysroot={}", sysroot.display()))
        .clang_arg(format!("-I{}", root.join("uapi").display()))
        .allowlist_type("(kt_info|kt_trace_stats|sct_.*|bt_.*)")
        .allowlist_var(
            "(AMT_.*|SCT_.*|BT_.*|KT_FEATURE_.*|KT_ABI_VERSION|KT_OPEN_CONTROL|PR_KTOOLS)",
        )
        .derive_default(true)
        .layout_tests(true)
        .generate_comments(true)
        .generate()
        .context("generating ARM64 UAPI bindings")?;
    bindings.write_to_file(root.join("crates/amtracer/src/ktools/bindings.rs"))?;
    Ok(())
}
