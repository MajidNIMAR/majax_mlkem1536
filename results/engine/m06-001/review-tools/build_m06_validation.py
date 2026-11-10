"""Build and preserve M06 research, delivery and timing binaries on both hosts.

Run from Windows; Linux builds use the existing project-local WSL toolchain.
This does not install tools, update lockfiles, or run performance measurements.
"""

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[1]


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def linux(path):
    path = path.resolve()
    return "/mnt/" + path.drive[0].lower() + str(path)[2:].replace("\\", "/")


def source_files():
    paths = [ROOT / name for name in ("Cargo.toml", "Cargo.lock", "rust-toolchain.toml", ".cargo/config.toml")]
    for folder in ("crates", "profiles"):
        paths.extend(p for p in (ROOT / folder).rglob("*") if p.is_file()
                     and "target" not in p.relative_to(ROOT / folder).parts)
    # Rust incorporates files outside crates/ through literal include macros,
    # including the standardized witness's public ACVP JSON. Preserve those
    # project inputs as well, not just the .rs files referring to them.
    included = set()
    for path in paths:
        if path.suffix == ".rs":
            for name in re.findall(r'\binclude_(?:str|bytes)!\(\s*"([^"]+)"\s*\)', path.read_text(encoding="utf-8")):
                member = (path.parent / name).resolve()
                if not member.is_relative_to(ROOT) or not member.is_file():
                    raise ValueError("included Rust input must exist within the project")
                included.add(member)
    return sorted(set(paths) | included)


def build(output, target):
    if os.name != "nt":
        raise ValueError("this coordinator requires Windows and its configured WSL distribution")
    for path in (output, target):
        if not path.is_relative_to(ROOT) or path == ROOT or path.exists():
            raise ValueError("new project-local output and target directories are required")
    output.mkdir(parents=True)
    target.mkdir(parents=True)
    originals = {p.relative_to(ROOT).as_posix(): digest(p) for p in source_files()}
    for name in originals:
        dest = output / "sources" / name
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / name, dest)
    env = dict(os.environ, CARGO_HOME=str(ROOT / ".tools/cargo"),
               RUSTUP_HOME=str(ROOT / ".tools/rustup"),
               CARGO_TARGET_DIR=str(target / "windows"), RUSTUP_AUTO_INSTALL="0")
    cargo = ROOT / ".tools/cargo/bin/cargo.exe"
    rustc = ROOT / ".tools/cargo/bin/rustc.exe"
    sysroot = Path(subprocess.check_output([str(rustc), "--print", "sysroot"], env=env, text=True).strip())
    tool_dirs = [ROOT / ".tools/native-tools", sysroot / "lib/rustlib/x86_64-pc-windows-gnu/bin",
                 sysroot / "lib/rustlib/x86_64-pc-windows-gnu/bin/self-contained", cargo.parent]
    env["PATH"] = os.pathsep.join(map(str, tool_dirs)) + os.pathsep + env.get("PATH", "")
    linux_env = ["env", "RUSTUP_AUTO_INSTALL=0", "CARGO_HOME=" + linux(ROOT / ".tools/linux-cargo"),
                 "RUSTUP_HOME=" + linux(ROOT / ".tools/linux-rustup"),
                 "CARGO_TARGET_DIR=" + linux(target / "linux"),
                 "PATH=" + linux(ROOT / ".tools/linux-cargo/bin") + ":/usr/local/bin:/usr/bin:/bin"]
    linux_cargo = linux(ROOT / ".tools/linux-cargo/bin/cargo")
    results = {}
    configurations = (("research", "kem1536-cli", "kem1536", ["--features", "research-vectors"]),
                      ("delivered", "kem1536-cli", "kem1536", []),
                      ("timing", "kem1536-bench", "kem1536-bench", []))
    for host in ("windows", "linux"):
        folder = output / host
        folder.mkdir()
        if host == "windows":
            version_cmd = [str(rustc), "-Vv"]
        else:
            version_cmd = ["wsl", "-d", "Ubuntu-22.04", "--", *linux_env,
                           linux(ROOT / ".tools/linux-cargo/bin/rustc"), "-Vv"]
        versions = subprocess.check_output(version_cmd, cwd=ROOT, env=env, text=True)
        (folder / "rustc.txt").write_text(versions, encoding="utf-8", newline="\n")
        results[host] = {}
        for label, package, binary, features in configurations:
            args = ["build", "--locked", "--offline", "--release", "-p", package, "--bin", binary, *features]
            command = ([str(cargo), *args] if host == "windows" else
                       ["wsl", "-d", "Ubuntu-22.04", "--", *linux_env, linux_cargo, *args])
            log = folder / (label + "-build.log")
            print(f"building {host}/{label}", flush=True)
            with log.open("xb") as stream:
                subprocess.run(command, cwd=ROOT, env=env, stdout=stream, stderr=subprocess.STDOUT, check=True)
            suffix = ".exe" if host == "windows" else ""
            source = target / host / "release" / (binary + suffix)
            dest = folder / (label + suffix)
            shutil.copyfile(source, dest)
            results[host][label] = dict(path=dest.relative_to(ROOT).as_posix(), sha256=digest(dest),
                                        command=command, log_sha256=digest(log))
    if originals != {name: digest(ROOT / name) for name in originals}:
        raise ValueError("a compiled source changed during the validation builds")
    receipt = dict(created_utc=datetime.now(timezone.utc).isoformat(), source_sha256=originals,
                   builds=results, tools_installed=False, profile="KEM1536-DEV-Q7681-R1")
    (output / "builds.json").write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8", newline="\n")
    print(json.dumps({host: {label: row["sha256"] for label, row in values.items()}
                      for host, values in results.items()}, indent=2))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--target", type=Path, required=True)
    args = parser.parse_args()
    build(args.output.resolve(), args.target.resolve())
