use std::{env, fs, path::PathBuf, process::Command, vec};

fn main() {
    println!("cargo:rustc-link-lib=static=c++_static");

    println!("cargo:rerun-if-changed=aidl");
    println!("cargo:rerun-if-changed=src/proto");
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=runtime/rkp/RkpV1Bridge.java");
    for name in [
        "ANDROID_HOME",
        "ANDROID_SDK_ROOT",
        "ANDROID_BUILD_TOOLS_VERSION",
        "JAVA_HOME",
        "LOCALAPPDATA",
    ] {
        println!("cargo:rerun-if-env-changed={name}");
    }

    let out_dir = "src/proto";

    fs::create_dir_all(out_dir).unwrap();

    prost_build::Config::new()
        .out_dir(out_dir)
        .compile_protos(&["proto/storage.proto"], &["proto/"])
        .expect("Failed to compile .proto files");

    let mod_file = format!("{}/mod.rs", out_dir);
    let mod_content = ["storage.rs"]
        .iter()
        .map(|file| format!("pub mod {};", file.trim_end_matches(".rs")))
        .collect::<Vec<_>>()
        .join("\n");

    std::fs::write(&mod_file, mod_content).unwrap();
    let _ = Command::new("rustfmt")
        .args([&mod_file, &format!("{}/storage.rs", out_dir)])
        .status();

    let mut aidl = rsbinder_aidl::Builder::new()
        .include_dir(PathBuf::from("aidl/android/system/keystore2"))
        .include_dir(PathBuf::from("aidl/android/hardware/security/keymint"))
        .include_dir(PathBuf::from("aidl/android/hardware/security/secureclock"))
        .include_dir(PathBuf::from("aidl/android/security/authorization"))
        .include_dir(PathBuf::from("aidl/android/security/maintenance"))
        .include_dir(PathBuf::from("aidl/android/content/pm"))
        .include_dir(PathBuf::from("aidl/android/os"))
        .output(PathBuf::from("aidl.rs"));

    let dirs = vec![
        "aidl/android/system/keystore2",
        "aidl/android/hardware/security/keymint",
        "aidl/android/hardware/security/secureclock",
        "aidl/android/security/authorization",
        "aidl/android/security/maintenance",
        "aidl/android/security/metrics",
        "aidl/android/security/keystore",
        "aidl/android/apex",
        "aidl/android/content/pm",
        "aidl/android/os",
        "aidl/top/qwq2333/ohmykeymint",
    ];
    for dir in dirs {
        println!("Processing AIDL files in directory: {}", dir);
        let dir = fs::read_dir(dir).unwrap();

        for entry in dir {
            let entry = entry.unwrap();
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) == Some("aidl") {
                aidl = aidl.source(path);
            }
        }
    }
    aidl.generate().unwrap();

    let generated_path = PathBuf::from(format!("{}/aidl.rs", std::env::var("OUT_DIR").unwrap()));
    let content = fs::read_to_string(&generated_path).unwrap();

    let patched_content = content.replace(
        "\npub mod top {",
        "\n#[allow(clippy::all)]\n#[allow(unused_imports)]\npub mod top {",
    );

    println!("Generated AIDL content:\n{}", generated_path.display());

    fs::write(&generated_path, &patched_content).unwrap();

    build_rkp_v1_bridge();
}

fn build_rkp_v1_bridge() {
    if env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("android")
        || env::var("CARGO_CFG_TARGET_ARCH").as_deref() != Ok("aarch64")
    {
        return;
    }

    let sdk = env::var_os("ANDROID_HOME")
        .filter(|root| !root.is_empty())
        .or_else(|| env::var_os("ANDROID_SDK_ROOT").filter(|root| !root.is_empty()))
        .map(PathBuf::from)
        .or_else(|| {
            env::var_os("LOCALAPPDATA")
                .filter(|root| !root.is_empty())
                .map(|root| PathBuf::from(root).join("Android/Sdk"))
        })
        .expect("Android arm64 RKP bridge build requires an Android SDK");

    let build_tools = env::var("ANDROID_BUILD_TOOLS_VERSION")
        .ok()
        .filter(|version| !version.is_empty())
        .map(|version| sdk.join("build-tools").join(version).join("lib/d8.jar"))
        .or_else(|| latest_d8(&sdk))
        .expect("install Android SDK Build Tools with lib/d8.jar");
    assert!(
        build_tools.is_file(),
        "Android D8 was not found at {}",
        build_tools.display()
    );

    let out = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR"));
    let classes = out.join("rkp-v1-classes");
    fs::create_dir_all(&classes).expect("create RKP V1 bridge classes directory");

    let java_tool = |name: &str| {
        let name = if cfg!(windows) {
            format!("{name}.exe")
        } else {
            name.to_owned()
        };
        env::var_os("JAVA_HOME")
            .filter(|root| !root.is_empty())
            .map(|root| PathBuf::from(root).join("bin").join(&name))
            .unwrap_or_else(|| PathBuf::from(name))
    };

    run_build_command(
        Command::new(java_tool("javac"))
            .args(["--release", "8", "-encoding", "UTF-8", "-d"])
            .arg(&classes)
            .arg("runtime/rkp/RkpV1Bridge.java"),
    );
    let jar = out.join("rkp-v1.jar");
    run_build_command(
        Command::new(java_tool("java"))
            .arg("-cp")
            .arg(&build_tools)
            .args([
                "com.android.tools.r8.D8",
                "--release",
                "--no-desugaring",
                "--min-api",
                "26",
                "--output",
            ])
            .arg(&jar)
            .arg(classes.join("duck/rkp/RkpV1Bridge.class")),
    );
    println!("cargo:rustc-env=OMK_RKP_V1_BRIDGE_JAR={}", jar.display());
}

fn latest_d8(sdk: &std::path::Path) -> Option<PathBuf> {
    let mut candidates = fs::read_dir(sdk.join("build-tools"))
        .ok()?
        .filter_map(Result::ok)
        .map(|entry| entry.path().join("lib/d8.jar"))
        .filter(|path| path.is_file())
        .collect::<Vec<_>>();
    candidates.sort();
    candidates.pop()
}

fn run_build_command(command: &mut Command) {
    let output = command
        .output()
        .unwrap_or_else(|error| panic!("cannot run {command:?}: {error}"));
    assert!(
        output.status.success(),
        "{command:?} failed:\n{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}
