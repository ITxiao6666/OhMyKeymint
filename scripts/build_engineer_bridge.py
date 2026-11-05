"""Build pinned app-local LSPlant glue and its in-memory Java callback DEX."""
from __future__ import annotations

import argparse
import hashlib
import io
import os
from pathlib import Path, PurePosixPath
import shutil
import subprocess
import tarfile
import urllib.request
import zipfile

ROOT = Path(__file__).resolve().parents[1]
CACHE = ROOT / "target" / "engineer-deps"
SOURCES = {
    "lsplant": ("LSPosed/LSPlant", "06bd3412d639d6b0d76fe6c7388066fe44e8963d", "831fbf63b5932cb01fbc6f5dd84c5e68a725c47948250118e8f69f82c82e00f9"),
    "dexbuilder": ("LSPosed/DexBuilder", "ac7fb2230954ee311808bad469b0db501f31bfb8", "23fdcd5e92acb74b4d0b1b77554c93077ec7255538d852124c9b794d88284efc"),
    "phmap": ("greg7mdp/parallel-hashmap", "0cd57d29a959256ed66b2afdd1009928fc625d09", "88f37e8c06b034e972b65abcd55ebc753d49374be801006d98faec3f16512684"),
    "dobby": ("jmpews/Dobby", "5dfc8546954ce3b3198132ab13fddb89ee92cdd7", "01a417233c40929aa21098c8a9724c00f6f05b5cde3f11abcac84b8e00053748"),
}
CXX_URL = "https://repo.maven.apache.org/maven2/org/lsposed/libcxx/libcxx/30.0.16248370/libcxx-30.0.16248370.aar"
CXX_HASH = "8bb6839964cdd5b814255c2674a9bb4a7ba5a6b2e15284c307694a571e8d5f7c"
DOBBY_URL = "https://repo.maven.apache.org/maven2/io/github/vvb2060/ndk/dobby/1.2/dobby-1.2.aar"
DOBBY_HASH = "251f48ae21686d7f69276c50644ca345f450e45110057437f7d76bb14cddf3a1"


def download(name: str, url: str, digest: str) -> bytes:
    CACHE.mkdir(parents=True, exist_ok=True)
    path = CACHE / name
    raw = path.read_bytes() if path.is_file() else urllib.request.urlopen(url, timeout=60).read()
    if hashlib.sha256(raw).hexdigest() != digest:
        raise ValueError(f"Dependency digest mismatch: {name}")
    if not path.exists():
        path.write_bytes(raw)
    return raw


def source(name: str) -> Path:
    repo, revision, digest = SOURCES[name]
    destination = CACHE / f"{name}-{revision}"
    archive = download(f"{name}-{revision}.tar.gz", f"https://codeload.github.com/{repo}/tar.gz/{revision}", digest)
    if not destination.is_dir():
        with tarfile.open(fileobj=io.BytesIO(archive), mode="r:gz") as tar:
            members = tar.getmembers()
            prefix = members[0].name.split("/")[0]
            for member in members:
                path = PurePosixPath(member.name)
                if path.is_absolute() or ".." in path.parts or not (member.isfile() or member.isdir()):
                    raise ValueError("Unsafe dependency archive member")
            tar.extractall(CACHE)
        (CACHE / prefix).rename(destination)
    return destination


def run(args: list[str | Path]) -> None:
    subprocess.run([str(arg) for arg in args], cwd=ROOT, check=True)


def build(target: str, sdk: Path, ndk: Path) -> Path:
    abi = {"aarch64-linux-android": "arm64-v8a", "x86_64-linux-android": "x86_64"}[target]
    out = ROOT / "target" / "engineer-bridge" / target
    out.mkdir(parents=True, exist_ok=True)
    lsplant, dex, phmap, dobby = (source(name) for name in SOURCES)
    for origin, destination in [
        (dex, lsplant / "lsplant/src/main/jni/external/dex_builder"),
        (phmap, lsplant / "lsplant/src/main/jni/external/dex_builder/external/parallel_hashmap"),
    ]:
        if not (destination / "CMakeLists.txt").exists():
            shutil.copytree(origin, destination, dirs_exist_ok=True)
    cxx = CACHE / f"cxx-{CXX_HASH[:12]}"
    raw = download("libcxx-r30.aar", CXX_URL, CXX_HASH)
    if not cxx.is_dir():
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            archive.extractall(cxx)
    dobby_prefab = CACHE / f"dobby-prefab-{DOBBY_HASH[:12]}"
    raw = download("dobby-1.2.aar", DOBBY_URL, DOBBY_HASH)
    if not dobby_prefab.is_dir():
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            archive.extractall(dobby_prefab)
    cmake_dir = sdk / "cmake/4.1.2/bin"
    suffix = ".exe" if os.name == "nt" else ""
    cmake = cmake_dir / f"cmake{suffix}"
    ninja = cmake_dir / f"ninja{suffix}"
    if not cmake.is_file():
        cmake = Path(shutil.which("cmake") or "cmake")
        ninja = Path(shutil.which("ninja") or "ninja")
    java_root = Path(os.environ["JAVA_HOME"]) if os.environ.get("JAVA_HOME") else None
    java = java_root / f"bin/java{suffix}" if java_root else Path(shutil.which("java") or "java")
    javac = java_root / f"bin/javac{suffix}" if java_root else Path(shutil.which("javac") or "javac")
    classes = out / "classes"
    classes.mkdir(exist_ok=True)
    run([javac, "--release", "8", "-d", classes, ROOT / "runtime/engineer/EngineerDisplay.java"])
    d8 = sdk / "build-tools/35.0.0/lib/d8.jar"
    jar = out / "engineer.jar"
    run([java, "-cp", d8, "com.android.tools.r8.D8", "--release", "--no-desugaring", "--min-api", "26",
         "--output", jar, classes / "omk/engineer/EngineerDisplay.class"])
    with zipfile.ZipFile(jar) as archive:
        (out / "classes.dex").write_bytes(archive.read("classes.dex"))
    data = (out / "classes.dex").read_bytes()
    (out / "engineer_dex.h").write_text("static const unsigned char omk_engineer_dex[] = {" +
        ",".join(str(byte) for byte in data) + "};\n", encoding="ascii")
    run([cmake, "-S", ROOT / "runtime/engineer", "-B", out / "native", "-G", "Ninja",
         f"-DCMAKE_MAKE_PROGRAM={ninja}", f"-DCMAKE_TOOLCHAIN_FILE={ndk}/build/cmake/android.toolchain.cmake",
         f"-DANDROID_ABI={abi}", "-DANDROID_PLATFORM=android-26", "-DANDROID_STL=none",
         "-DCMAKE_BUILD_TYPE=Release", f"-DOMK_LSPLANT={lsplant}", f"-DOMK_DOBBY={dobby_prefab}",
         f"-DOMK_CXX={cxx}", f"-DOMK_GENERATED={out}"])
    run([cmake, "--build", out / "native", "--target", "omk_engineer", "--parallel", "4"])
    licenses = out / "licenses"
    licenses.mkdir(exist_ok=True)
    for name, path in [("LSPlant", lsplant / "LICENSE"), ("Dobby", dobby / "LICENSE"),
                       ("DexBuilder", dex / "LICENSE"), ("parallel-hashmap", phmap / "LICENSE")]:
        shutil.copyfile(path, licenses / f"{name}.txt")
    llvm_license = download("LLVM-LICENSE-7f0a601b.txt",
        "https://raw.githubusercontent.com/LSPosed/libcxx/7f0a601bc96423a02d8cf141f0cfe1f398aeda01/LICENSE.TXT",
        "539dd7aed86e8a4f12cbdd0e6c50c189c7d74847e4fecc64ce2c6ee3a01da38b")
    (licenses / "LLVM.txt").write_bytes(llvm_license)
    return out


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", required=True)
    parser.add_argument("--sdk", type=Path, required=True)
    parser.add_argument("--ndk", type=Path, required=True)
    args = parser.parse_args()
    build(args.target, args.sdk, args.ndk)
