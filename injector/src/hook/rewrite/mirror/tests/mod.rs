use super::*;
use crate::hook::rewrite::tests::{raw_parts, route_state_test_guard};

#[test]
fn mirror_recovery_retries_sensitive_events_in_global_sequence() {
    let _guard = route_state_test_guard();
    let caller = CallerInfo {
        uid: 1000,
        sid: "u:r:keystore:s0".into(),
        pid: 2000,
    };

    reserve_mirror_update(
        MirrorStateKind::Maintenance,
        MirrorFailurePolicy::FailClosed,
    )
    .expect("onUserAdded should reserve")
    .enqueue(MirrorReplayEvent::Maintenance {
        request: ParsedMaintenanceRequest::OnUserAdded { user_id: 10 },
        caller: caller.clone(),
    })
    .expect("onUserAdded should queue");
    reserve_mirror_update(
        MirrorStateKind::Maintenance,
        MirrorFailurePolicy::FailClosed,
    )
    .expect("initUserSuperKeys should reserve")
    .enqueue(MirrorReplayEvent::Maintenance {
        request: ParsedMaintenanceRequest::InitUserSuperKeys {
            user_id: 10,
            password: vec![1, 2, 3],
            allow_existing: false,
        },
        caller: caller.clone(),
    })
    .expect("initUserSuperKeys should queue");
    reserve_mirror_update(
        MirrorStateKind::Authorization,
        MirrorFailurePolicy::FailClosed,
    )
    .expect("onUserStorageLocked should reserve")
    .enqueue(MirrorReplayEvent::Authorization {
        request: ParsedAuthorizationRequest::OnUserStorageLocked { user_id: 10 },
        caller: caller.clone(),
    })
    .expect("onUserStorageLocked should queue");

    let mut executed = Vec::new();
    let mut fail_sensitive = true;
    assert!(recover_mirror_state_with(&mut |event| {
        let method = event.method();
        executed.push(method.clone());
        if fail_sensitive && method == "InitUserSuperKeys" {
            fail_sensitive = false;
            return Err(anyhow::Error::new(StatusCode::DeadObject));
        }
        Ok(())
    })
    .is_err());
    assert_eq!(executed, ["OnUserAdded", "InitUserSuperKeys"]);

    {
        let mut state = MIRROR_RECOVERY_STATE
            .lock()
            .expect("mirror recovery state poisoned");
        assert_eq!(state.maintenance.pending.len(), 1);
        assert_eq!(state.authorization.pending.len(), 1);
        let pending = state
            .maintenance
            .pending
            .front_mut()
            .expect("sensitive replay should remain queued");
        assert!(pending.retry_not_before.is_some());
        let Some(MirrorReplayEvent::Maintenance {
            request: ParsedMaintenanceRequest::InitUserSuperKeys { password, .. },
            caller: queued_caller,
        }) = &pending.event
        else {
            panic!("sensitive replay should retain its exact in-memory event");
        };
        assert_eq!(password, &[1, 2, 3]);
        assert_eq!(queued_caller.uid, caller.uid);
        assert_eq!(queued_caller.pid, caller.pid);
        assert_eq!(queued_caller.sid, caller.sid);
    }
    assert!(mirror_state_dirty(MirrorStateKind::Authorization));
    assert!(mirror_state_dirty(MirrorStateKind::Maintenance));

    let mut early_attempts = 0;
    assert!(recover_mirror_state_with(&mut |_| {
        early_attempts += 1;
        Ok(())
    })
    .is_err());
    assert_eq!(early_attempts, 0, "retry deadline must preserve FIFO");

    MIRROR_RECOVERY_STATE
        .lock()
        .expect("mirror recovery state poisoned")
        .maintenance
        .pending
        .front_mut()
        .expect("sensitive replay should remain queued")
        .retry_not_before = None;
    recover_mirror_state_with(&mut |event| {
        executed.push(event.method());
        Ok(())
    })
    .expect("in-memory mirror events should drain in global sequence order");

    assert_eq!(
        executed,
        [
            "OnUserAdded",
            "InitUserSuperKeys",
            "InitUserSuperKeys",
            "OnUserStorageLocked",
        ]
    );
    assert!(!mirror_state_dirty(MirrorStateKind::Authorization));
    assert!(!mirror_state_dirty(MirrorStateKind::Maintenance));
    assert!(ensure_mirror_state_recovered().is_ok());
}

#[test]
fn mirror_reservation_holds_global_order_and_lost_reply_fails_closed() {
    let _guard = route_state_test_guard();
    let caller = CallerInfo {
        uid: 1000,
        sid: String::new(),
        pid: 2000,
    };
    let earlier = reserve_mirror_update(
        MirrorStateKind::Authorization,
        MirrorFailurePolicy::FailClosed,
    )
    .expect("authorization update should reserve");
    reserve_mirror_update(
        MirrorStateKind::Maintenance,
        MirrorFailurePolicy::FailClosed,
    )
    .expect("maintenance update should reserve")
    .enqueue(MirrorReplayEvent::Maintenance {
        request: ParsedMaintenanceRequest::OnUserRemoved { user_id: 11 },
        caller,
    })
    .expect("later System reply should publish its event");

    let mut replayed = 0;
    assert!(recover_mirror_state_with(&mut |_| {
        replayed += 1;
        Ok(())
    })
    .is_err());
    assert_eq!(replayed, 0);
    assert!(
        MIRROR_RECOVERY_STATE
            .lock()
            .expect("mirror recovery state poisoned")
            .next_worker_wait(Instant::now())
            .is_none(),
        "the worker must sleep while an earlier System reply is outstanding"
    );

    earlier.cancel();
    recover_mirror_state_with(&mut |_| {
        replayed += 1;
        Ok(())
    })
    .expect("canceling a failed System call should unblock the later event");
    assert_eq!(replayed, 1);

    drop(
        reserve_mirror_update(
            MirrorStateKind::Authorization,
            MirrorFailurePolicy::FailClosed,
        )
        .expect("lost authorization update should reserve"),
    );
    let state = MIRROR_RECOVERY_STATE
        .lock()
        .expect("mirror recovery state poisoned");
    assert!(state.authorization.poisoned);
    assert!(state.authorization.pending.is_empty());
    drop(state);
    assert!(ensure_mirror_state_recovered().is_err());
}

#[test]
fn full_mirror_queue_rejects_only_the_new_fail_closed_mutation() {
    let _guard = route_state_test_guard();
    let caller = CallerInfo {
        uid: 1000,
        sid: String::new(),
        pid: 2000,
    };
    for _ in 0..MAX_PENDING_MIRROR_REPLAYS {
        reserve_mirror_update(
            MirrorStateKind::Authorization,
            MirrorFailurePolicy::FailClosed,
        )
        .expect("queue slot should reserve")
        .enqueue(MirrorReplayEvent::Authorization {
            request: ParsedAuthorizationRequest::OnUserStorageLocked { user_id: 10 },
            caller: caller.clone(),
        })
        .expect("reserved event should queue");
    }

    assert!(reserve_mirror_update(
        MirrorStateKind::Authorization,
        MirrorFailurePolicy::FailClosed,
    )
    .is_err());
    assert!(
        !MIRROR_RECOVERY_STATE
            .lock()
            .expect("mirror recovery state poisoned")
            .authorization
            .poisoned,
        "a request rejected before System execution must not poison existing recovery"
    );

    let mut replayed = 0;
    recover_mirror_state_with(&mut |_| {
        replayed += 1;
        Ok(())
    })
    .expect("the existing queue should remain recoverable");
    assert_eq!(replayed, MAX_PENDING_MIRROR_REPLAYS);
    assert!(ensure_mirror_state_recovered().is_ok());
}

#[test]
fn non_ok_system_reply_cancels_mirror_reservation() {
    let _guard = route_state_test_guard();
    let mut reply = parcel::build_status_reply(&Status::new_service_specific_error(
        ResponseCode::SYSTEM_ERROR.0,
        None,
    ))
    .expect("error reply should build");
    let (data, data_size, offsets, offsets_size) = raw_parts(&mut reply);
    let mut tr: binder_transaction_data = unsafe { std::mem::zeroed() };
    tr.data.ptr.buffer = data as libc::c_ulong;
    tr.data.ptr.offsets = offsets as libc::c_ulong;
    tr.data_size = data_size;
    tr.offsets_size = offsets_size;
    let mut call = PendingAuthorizationCall {
        request: ParsedAuthorizationRequest::AddAuthToken {
            auth_token: Default::default(),
        },
        method: AuthorizationMethod::AddAuthToken,
        caller: CallerInfo {
            uid: 1000,
            sid: String::new(),
            pid: 2000,
        },
        mirror_update: Some(
            reserve_mirror_update(
                MirrorStateKind::Authorization,
                MirrorFailurePolicy::BestEffort,
            )
            .expect("authorization update should reserve"),
        ),
    };

    assert!(unsafe { build_authorization_reply_mirror(&tr, &mut call) }
        .expect("System error reply should parse")
        .is_none());
    assert!(call.mirror_update.is_none());
    assert!(ensure_mirror_state_recovered().is_ok());
}

#[test]
fn best_effort_add_auth_token_failures_do_not_block_later_events() {
    let _guard = route_state_test_guard();
    let caller = CallerInfo {
        uid: 1000,
        sid: String::new(),
        pid: 2000,
    };

    for _ in 0..2 {
        reserve_mirror_update(
            MirrorStateKind::Authorization,
            MirrorFailurePolicy::BestEffort,
        )
        .expect("addAuthToken should reserve")
        .enqueue(MirrorReplayEvent::Authorization {
            request: ParsedAuthorizationRequest::AddAuthToken {
                auth_token: Default::default(),
            },
            caller: caller.clone(),
        })
        .expect("addAuthToken should queue");
    }
    reserve_mirror_update(
        MirrorStateKind::Authorization,
        MirrorFailurePolicy::FailClosed,
    )
    .expect("onUserStorageLocked should reserve")
    .enqueue(MirrorReplayEvent::Authorization {
        request: ParsedAuthorizationRequest::OnUserStorageLocked { user_id: 10 },
        caller,
    })
    .expect("onUserStorageLocked should queue");

    let mut attempts = 0;
    let mut executed = Vec::new();
    recover_mirror_state_with(&mut |event| {
        let method = event.method();
        executed.push(method.clone());
        if method == "AddAuthToken" {
            attempts += 1;
            if attempts == 1 {
                return Err(anyhow::Error::new(Status::new_service_specific_error(
                    7, None,
                )));
            }
            return Err(anyhow::Error::new(StatusCode::DeadObject));
        }
        Ok(())
    })
    .expect("best-effort failures should be dropped and later state should replay");

    assert_eq!(
        executed,
        ["AddAuthToken", "AddAuthToken", "OnUserStorageLocked"]
    );
    assert!(!mirror_state_dirty(MirrorStateKind::Authorization));
    assert!(ensure_mirror_state_recovered().is_ok());
}

#[test]
fn lost_best_effort_reply_does_not_poison_mirror_state() {
    let _guard = route_state_test_guard();
    let caller = CallerInfo {
        uid: 1000,
        sid: String::new(),
        pid: 2000,
    };
    let lost = reserve_mirror_update(
        MirrorStateKind::Authorization,
        MirrorFailurePolicy::BestEffort,
    )
    .expect("addAuthToken should reserve");
    reserve_mirror_update(
        MirrorStateKind::Authorization,
        MirrorFailurePolicy::FailClosed,
    )
    .expect("onUserStorageLocked should reserve")
    .enqueue(MirrorReplayEvent::Authorization {
        request: ParsedAuthorizationRequest::OnUserStorageLocked { user_id: 10 },
        caller,
    })
    .expect("onUserStorageLocked should queue");

    drop(lost);

    let mut replayed = 0;
    recover_mirror_state_with(&mut |_| {
        replayed += 1;
        Ok(())
    })
    .expect("later fail-closed state should replay after a lost best-effort reply");
    assert_eq!(replayed, 1);
    assert!(!mirror_state_dirty(MirrorStateKind::Authorization));
    assert!(ensure_mirror_state_recovered().is_ok());
}

#[test]
fn missing_best_effort_reservation_preserves_system_success() {
    let _guard = route_state_test_guard();
    let mut reply = parcel::build_status_reply(&Status::from(StatusCode::Ok))
        .expect("success reply should build");
    let (data, data_size, offsets, offsets_size) = raw_parts(&mut reply);
    let mut tr: binder_transaction_data = unsafe { std::mem::zeroed() };
    tr.data.ptr.buffer = data as libc::c_ulong;
    tr.data.ptr.offsets = offsets as libc::c_ulong;
    tr.data_size = data_size;
    tr.offsets_size = offsets_size;
    let mut call = PendingAuthorizationCall {
        request: ParsedAuthorizationRequest::AddAuthToken {
            auth_token: Default::default(),
        },
        method: AuthorizationMethod::AddAuthToken,
        caller: CallerInfo {
            uid: 1000,
            sid: String::new(),
            pid: 2000,
        },
        mirror_update: None,
    };

    assert!(unsafe { build_authorization_reply_mirror(&tr, &mut call) }
        .expect("best-effort mirror should preserve System success")
        .is_none());
    assert!(ensure_mirror_state_recovered().is_ok());
}

#[test]
fn mirror_business_error_preserves_event_and_blocks_routes() {
    let _guard = route_state_test_guard();
    reserve_mirror_update(
        MirrorStateKind::Maintenance,
        MirrorFailurePolicy::FailClosed,
    )
    .expect("onUserRemoved should reserve")
    .enqueue(MirrorReplayEvent::Maintenance {
        request: ParsedMaintenanceRequest::OnUserRemoved { user_id: 11 },
        caller: CallerInfo {
            uid: 1000,
            sid: String::new(),
            pid: 2000,
        },
    })
    .expect("onUserRemoved should queue");

    let error = recover_mirror_state_with(&mut |_| {
        Err(anyhow::Error::new(Status::new_service_specific_error(
            7, None,
        )))
    })
    .expect_err("business error must stop automatic retry");
    assert!(!omk_unavailable_error(&error));

    let state = MIRROR_RECOVERY_STATE
        .lock()
        .expect("mirror recovery state poisoned");
    assert!(state.maintenance.poisoned);
    assert_eq!(state.maintenance.pending.len(), 1);
    assert_eq!(
        state.maintenance.pending[0]
            .event
            .as_ref()
            .expect("business failure should retain the event")
            .method(),
        "OnUserRemoved"
    );
    assert!(state.next_worker_wait(Instant::now()).is_none());
    drop(state);
    assert!(!mirror_state_dirty(MirrorStateKind::Authorization));
    assert!(mirror_state_dirty(MirrorStateKind::Maintenance));
    assert!(ensure_mirror_state_recovered().is_err());
}
