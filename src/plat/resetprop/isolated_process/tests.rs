use super::*;

fn identity(uid: u32, start_time: u64) -> ProcessIdentity {
    ProcessIdentity { uids: [uid; 4], start_time }
}

#[test]
fn lookup_requires_live_original_uid_and_stable_process() {
    let packages = resolve_packages_with_identity(
        99001,
        42,
        |_| Ok(identity(99001, 17)),
        |uid, pid| {
            assert_eq!((uid, pid), (99001, 42));
            Ok(vec!["com.example.owner".into()])
        },
    )
    .unwrap();
    assert_eq!(packages, ["com.example.owner"]);
    assert!(resolve_packages_with_identity(
        99001,
        42,
        |_| Ok(identity(10371, 17)),
        |_, _| panic!("mismatched UID must not reach AMS")
    )
    .is_err());
    for after in [identity(99002, 17), identity(99001, 18)] {
        let mut calls = 0;
        assert!(resolve_packages_with_identity(
            99001,
            42,
            |_| {
                calls += 1;
                Ok(if calls == 1 { identity(99001, 17) } else { after.clone() })
            },
            |_, _| Ok(vec!["com.example.owner".into()])
        )
        .is_err());
    }
}

#[test]
fn failed_identity_reads_never_query_or_accept_packages_and_name_the_stage() {
    let error = resolve_packages_with_identity(
        99015,
        16624,
        |_| Err(std::io::Error::from_raw_os_error(libc::ENOENT).into()),
        |_, _| panic!("unverified identity must not reach ActivityManager"),
    )
    .unwrap_err();
    assert!(format!("{error:#}").contains("before package lookup"));
    assert_eq!(
        error.root_cause().downcast_ref::<std::io::Error>().unwrap().raw_os_error(),
        Some(libc::ENOENT)
    );

    let mut reads = 0;
    let error = resolve_packages_with_identity(
        99015,
        16624,
        |_| {
            reads += 1;
            if reads == 1 {
                Ok(identity(99015, 17))
            } else {
                Err(std::io::Error::from_raw_os_error(libc::ENOENT).into())
            }
        },
        |_, _| Ok(vec!["com.example.owner".into()]),
    )
    .unwrap_err();
    assert!(format!("{error:#}").contains("after package lookup"));

    let error = resolve_packages_with_identity(
        99015,
        16624,
        |_| Ok(identity(99015, 17)),
        |_, _| Err(std::io::Error::from_raw_os_error(libc::ENOENT).into()),
    )
    .unwrap_err();
    assert!(format!("{error:#}").contains("ActivityManager package lookup"));
}

#[cfg(target_os = "android")]
#[test]
fn proc_identity_guard_rejects_non_helper_without_changing_uid() {
    let uid = unsafe { libc::getuid() };
    let euid = unsafe { libc::geteuid() };
    if uid != kmr_common::consts::AID_ROOT {
        assert!(ProcReadEuid::enter().is_err());
        assert_eq!(unsafe { libc::geteuid() }, euid);
    }
}

#[cfg(target_os = "android")]
#[test]
#[ignore = "requires authorized Android root; changes EUID only in a test subprocess"]
fn proc_identity_root_scope_restores_system_without_affecting_other_threads() {
    use std::sync::mpsc;

    const CHILD: &str = "OMK_PROC_IDENTITY_TEST_CHILD";
    if std::env::var_os(CHILD).is_none() {
        let output = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "plat::resetprop::isolated_process::tests::proc_identity_root_scope_restores_system_without_affecting_other_threads",
                "--ignored",
                "--nocapture",
            ])
            .env(CHILD, "1")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "isolated proc-identity check failed: {}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        return;
    }
    assert_eq!(unsafe { libc::getuid() }, kmr_common::consts::AID_ROOT);
    let original_euid = unsafe { libc::geteuid() };
    set_thread_euid(kmr_common::consts::AID_SYSTEM).unwrap();
    let (request, receiver) = mpsc::channel::<()>();
    let (reply, responses) = mpsc::channel();
    let observer = std::thread::spawn(move || {
        while receiver.recv().is_ok() {
            reply.send(unsafe { libc::geteuid() }).unwrap();
        }
    });
    let check_observer = || {
        request.send(()).unwrap();
        assert_eq!(
            responses.recv_timeout(std::time::Duration::from_secs(5)).unwrap(),
            kmr_common::consts::AID_SYSTEM
        );
    };
    check_observer();
    {
        let _guard = ProcReadEuid::enter().unwrap();
        assert_eq!(unsafe { libc::geteuid() }, kmr_common::consts::AID_ROOT);
        check_observer();
    }
    assert_eq!(unsafe { libc::geteuid() }, kmr_common::consts::AID_SYSTEM);
    let current = read_process_identity(std::process::id()).unwrap();
    assert_eq!(current.uids[0], kmr_common::consts::AID_ROOT);
    assert_eq!(unsafe { libc::geteuid() }, kmr_common::consts::AID_SYSTEM);
    let error = read_process_identity(u32::MAX).unwrap_err();
    assert!(format!("{error:#}").contains("initial proc identity read"));
    assert_eq!(unsafe { libc::geteuid() }, kmr_common::consts::AID_SYSTEM);
    let panic_result = std::panic::catch_unwind(|| {
        let _guard = ProcReadEuid::enter().unwrap();
        panic!("exercise credential restoration during unwind");
    });
    assert!(panic_result.is_err());
    assert_eq!(unsafe { libc::geteuid() }, kmr_common::consts::AID_SYSTEM);
    check_observer();
    drop(request);
    observer.join().unwrap();
    set_thread_euid(original_euid).unwrap();
}

#[test]
fn ordinary_or_invalid_callers_never_query_processes() {
    for (uid, pid) in [(10371, 42), (99001, 0), (99001, u32::MAX)] {
        assert!(resolve_packages_with_identity(
            uid,
            pid,
            |_| panic!("invalid identity must be rejected before proc access"),
            |_, _| panic!("invalid identity must be rejected before AMS access")
        )
        .unwrap()
        .is_empty());
    }
    assert!(is_isolated_uid(190001));
    assert!(is_isolated_uid(99999));
    assert!(!is_isolated_uid(89999));
    assert!(!is_isolated_uid(100000));
}

#[test]
fn proc_stat_handles_parentheses_and_rejects_mismatched_pid() {
    let stat = "42 (name with ) spaces) S 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 987 20";
    assert_eq!(parse_start_time(stat, 42).unwrap(), 987);
    assert!(parse_start_time(stat, 43).is_err());
    assert!(parse_start_time("42 (short) S 1", 42).is_err());
}

// Fields and order mirror ActivityManager.RunningAppProcessInfo.writeToParcel
// in the named Android releases; distinct suffix values catch field misalignment.
fn write_record(
    parcel: &mut Parcel,
    layout: ProcessParcelLayout,
    pid: i32,
    owner: i32,
    packages: &[Option<&str>],
) {
    parcel.write(&1i32).unwrap(); // non-null typed-list item
    let start = parcel.data_position();
    if layout == ProcessParcelLayout::Structured {
        parcel.write(&0i32).unwrap();
    }
    parcel.write(&"untrusted:process-name".to_owned()).unwrap();
    parcel.write(&pid).unwrap();
    parcel.write(&owner).unwrap();
    parcel.write(&(packages.len() as i32)).unwrap();
    for package in packages {
        parcel.write(&package.map(str::to_owned)).unwrap();
    }
    if layout != ProcessParcelLayout::Legacy {
        parcel.write(&vec!["com.dependencies.must.not.be.used".to_owned()]).unwrap();
    }
    for field in 101..107 {
        parcel.write(&field).unwrap();
    }
    if layout == ProcessParcelLayout::Structured {
        parcel.write(&Some("pkg/Class".to_owned())).unwrap();
    } else {
        parcel.write(&Some("pkg".to_owned())).unwrap();
        parcel.write(&"Class".to_owned()).unwrap();
    }
    for field in 107..110 {
        parcel.write(&field).unwrap();
    }
    parcel.write(&9876543210i64).unwrap();
    if layout == ProcessParcelLayout::Structured {
        let end = parcel.data_position();
        parcel.set_data_position(start);
        parcel.write(&((end - start) as i32)).unwrap();
        parcel.set_data_position(end);
    }
}

fn list(layout: ProcessParcelLayout, owner: i32) -> Parcel {
    let mut parcel = Parcel::new();
    parcel.write(&3i32).unwrap();
    parcel.write(&0i32).unwrap(); // legitimate null list item
    write_record(&mut parcel, layout, 41, 10001, &[Some("com.unrelated")]);
    write_record(&mut parcel, layout, 42, owner, &[Some("com.example.owner")]);
    parcel.set_data_position(0);
    parcel
}

#[test]
fn all_android_layouts_use_pid_and_packages_not_owner_uid_or_dependencies() {
    for layout in [
        ProcessParcelLayout::Legacy,
        ProcessParcelLayout::WithDependencies,
        ProcessParcelLayout::Structured,
    ] {
        let packages = read_matching_packages(&mut list(layout, 10371), layout, 99001, 42).unwrap();
        assert_eq!(packages, ["com.example.owner"]);
        assert!(read_matching_packages(&mut list(layout, 10371), layout, 99001, 43)
            .unwrap()
            .is_empty());
        for owner in [110371, 99002, -1] {
            assert!(read_matching_packages(&mut list(layout, owner), layout, 99001, 42).is_err());
        }
    }
}

#[test]
fn null_package_names_preserve_later_process_matches_and_valid_packages() {
    for layout in [
        ProcessParcelLayout::Legacy,
        ProcessParcelLayout::WithDependencies,
        ProcessParcelLayout::Structured,
    ] {
        let mut parcel = Parcel::new();
        parcel.write(&2i32).unwrap();
        write_record(&mut parcel, layout, 41, 10001, &[None]);
        write_record(
            &mut parcel,
            layout,
            42,
            10371,
            &[None, Some("com.example.shared"), None, Some("com.example.owner"), None],
        );
        parcel.set_data_position(0);
        assert_eq!(
            read_matching_packages(&mut parcel, layout, 99001, 42).unwrap(),
            ["com.example.owner", "com.example.shared"]
        );

        parcel.set_data_position(0);
        assert!(read_matching_packages(&mut parcel, layout, 99001, 41).unwrap().is_empty());
        parcel.set_data_position(0);
        assert!(read_matching_packages(&mut parcel, layout, 199001, 42).is_err());
    }
}

#[test]
fn null_package_names_do_not_hide_invalid_present_packages() {
    let layout = ProcessParcelLayout::WithDependencies;
    for package in ["", "com..example"] {
        let mut parcel = Parcel::new();
        parcel.write(&1i32).unwrap();
        write_record(&mut parcel, layout, 42, 10371, &[None, Some(package)]);
        parcel.set_data_position(0);
        assert!(read_matching_packages(&mut parcel, layout, 99001, 42).is_err());
    }
}

#[test]
fn ambiguous_or_malformed_process_lists_are_not_accepted() {
    let layout = ProcessParcelLayout::WithDependencies;
    let mut duplicate = Parcel::new();
    duplicate.write(&2i32).unwrap();
    write_record(&mut duplicate, layout, 42, 10371, &[Some("com.example.first")]);
    write_record(&mut duplicate, layout, 42, 10372, &[Some("com.example.second")]);
    duplicate.set_data_position(0);
    assert!(read_matching_packages(&mut duplicate, layout, 99001, 42).is_err());
    let mut trailing = list(layout, 10371);
    trailing.set_data_position(trailing.data_size());
    trailing.write(&123i32).unwrap();
    trailing.set_data_position(0);
    assert!(read_matching_packages(&mut trailing, layout, 99001, 42).is_err());
    let mut invalid_size = Parcel::new();
    for value in [1i32, 1, 4] {
        invalid_size.write(&value).unwrap();
    }
    invalid_size.set_data_position(0);
    assert!(read_matching_packages(&mut invalid_size, ProcessParcelLayout::Structured, 99001, 42)
        .is_err());
}

#[test]
fn helper_protocol_rejects_error_empty_and_invalid_package_responses() {
    assert!(parse_helper_response("NONE").unwrap().is_empty());
    assert_eq!(
        parse_helper_response("OK\tcom.example.owner\tcom.example.shared").unwrap(),
        ["com.example.owner", "com.example.shared"]
    );
    for response in ["ERR\tdenied", "OK\t", "OK\tcom.example\nmalicious", "OK\tcom..example"] {
        assert!(parse_helper_response(response).is_err());
    }
}

#[test]
fn unknown_android_versions_do_not_guess_transaction_numbers() {
    assert!(activity_contract(30).is_none());
    assert!(activity_contract(38).is_none());
    assert_eq!(activity_contract(32).unwrap().transaction, 76);
    assert_eq!(activity_contract(37).unwrap().layout, ProcessParcelLayout::Structured);
}
