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
        "debugplz-ebpf",
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
            "debugplz",
            "--release",
            "--target",
            "aarch64-linux-android",
            "--locked",
        ]))?;
    let output = root.join("artifacts");
    fs::create_dir_all(&output)?;
    fs::copy(
        root.join("target/aarch64-linux-android/release/debugplz"),
        output.join("debugplz"),
    )?;
    fs::copy(
        root.join("target/bpfel-unknown-none/release/debugplz-ebpf"),
        output.join("debugplz-ebpf.o"),
    )?;
    fs::copy(
        root.join("target/bpfel-unknown-none/release/debugplz-itrace"),
        output.join("debugplz-itrace.o"),
    )?;
    eprintln!("Android artifacts: {}", output.display());
    Ok(())
}

fn sync_uapi(root: &Path, kernel: &Path) -> Result<()> {
    let names = [
        "ktools.h",
        "syscall_trace.h",
        "binder_trace.h",
        "prctl.h",
        "uxn_probe.h",
    ];
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
    for name in ["asm-generic/unistd.h", "asm/unistd.h"] {
        let source = if name == "asm/unistd.h" {
            kernel.join("arch/arm64/include/uapi/asm/unistd.h")
        } else {
            kernel.join("include/uapi").join(name)
        };
        let bytes = fs::read(&source)?;
        let destination = root.join("uapi").join(name);
        fs::create_dir_all(destination.parent().context("UAPI directory")?)?;
        fs::write(destination, &bytes)?;
        let hash: String = Sha256::digest(&bytes)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        let path = source.strip_prefix(kernel)?;
        provenance.push_str(&format!("* {}: `{hash}`\n", path.display()));
    }
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
        .allowlist_type("(kt_info|kt_trace_stats|sct_.*|bt_.*|uxn_probe_.*)")
        .allowlist_var(
            "(AMT_.*|SCT_.*|BT_.*|KT_FEATURE_.*|KT_ABI_VERSION|KT_OPEN_CONTROL|PR_KTOOLS|PR_UXN_PROBE|UXN_.*)",
        )
        .derive_default(true)
        .layout_tests(true)
        .generate_comments(true)
        .generate()
        .context("generating ARM64 UAPI bindings")?;
    bindings.write_to_file(root.join("crates/debugplz/src/ktools/bindings.rs"))?;
    generate_syscall_names(root)?;
    Ok(())
}

fn generate_syscall_names(root: &Path) -> Result<()> {
    let compiler =
        ndk(root)?.join("toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android30-clang");
    let output = Command::new(compiler)
        .args(["-E", "-dM", "-x", "c", "-include"])
        .arg(root.join("uapi/asm/unistd.h"))
        .arg(format!("-I{}", root.join("uapi").display()))
        .arg("/dev/null")
        .output()?;
    ensure!(
        output.status.success(),
        "preprocessing syscall UAPI: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let text = String::from_utf8(output.stdout)?;
    let definitions = text
        .lines()
        .filter_map(|line| {
            let mut fields = line.split_whitespace();
            if fields.next()? != "#define" {
                return None;
            }
            Some((fields.next()?, fields.next()?))
        })
        .collect::<std::collections::BTreeMap<_, _>>();
    let mut names = Vec::new();
    for (name, value) in &definitions {
        let Some(name) = name.strip_prefix("__NR_") else {
            continue;
        };
        if matches!(name, "syscalls" | "arch_specific_syscall") {
            continue;
        }
        let mut value = *value;
        for _ in 0..8 {
            if let Some(next) = definitions.get(value) {
                value = next;
            } else {
                break;
            }
        }
        let number = value
            .parse::<i32>()
            .with_context(|| format!("syscall {name}: {value}"))?;
        names.push((number, name));
    }
    names.sort_unstable();
    let mut source =
        String::from("// Generated by cargo xtask gen-uapi from the vendored ARM64 unistd.h.\n");
    source.push_str("pub const NAMES: &[(i32, &str)] = &[\n");
    for (number, name) in names {
        source.push_str(&format!("    ({number}, \"{name}\"),\n"));
    }
    source.push_str("];\n");
    fs::write(
        root.join("crates/debugplz/src/ktools/syscall_names.rs"),
        source,
    )?;
    Ok(())
}
