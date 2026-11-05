use std::{env, path::PathBuf, process::Command};

fn main() {
    println!("cargo:rerun-if-changed=../runtime/engineer");
    println!("cargo:rerun-if-changed=../scripts/build_engineer_bridge.py");
    for name in
        ["JAVA_HOME", "ANDROID_HOME", "ANDROID_SDK_ROOT", "ANDROID_NDK_ROOT", "LOCALAPPDATA"]
    {
        println!("cargo:rerun-if-env-changed={name}");
    }
    if env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("android") {
        return;
    }
    let sdk = env::var_os("ANDROID_HOME")
        .or_else(|| env::var_os("ANDROID_SDK_ROOT"))
        .map(PathBuf::from)
        .or_else(|| env::var_os("LOCALAPPDATA").map(|path| PathBuf::from(path).join("Android/Sdk")))
        .expect("Engineer bridge requires Android SDK");
    let ndk = env::var_os("ANDROID_NDK_ROOT")
        .map(PathBuf::from)
        .unwrap_or_else(|| sdk.join("ndk/30.0.16248370"));
    let target = env::var("TARGET").unwrap();
    let root =
        PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap()).parent().unwrap().to_owned();
    let status = Command::new("python")
        .arg(root.join("scripts/build_engineer_bridge.py"))
        .args(["--target", &target, "--sdk"])
        .arg(&sdk)
        .arg("--ndk")
        .arg(ndk)
        .status()
        .expect("Cannot run engineer bridge builder");
    assert!(status.success(), "Engineer bridge build failed");
    println!(
        "cargo:rustc-env=OMK_ENGINEER_DEX={}",
        root.join("target/engineer-bridge").join(target).join("classes.dex").display()
    );
}
