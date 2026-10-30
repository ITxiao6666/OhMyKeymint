use super::*;
use std::sync::mpsc;

#[test]
fn overlapping_native_carrier_calls_are_busy_without_finalizing() {
    ensure_binder_process_state();
    let (entered_tx, entered_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let updates = Arc::new(AtomicUsize::new(0));
    let state = Arc::new(NativeOperationState {
        backend: BnKeystoreOperation::new_binder(BlockingOperationBackend {
            entered: entered_tx,
            release: Mutex::new(release_rx),
            updates: Arc::clone(&updates),
        }),
        aad_allowed: true,
        caller: CallerInfo { uid: 1000, pid: 2000, sid: String::new() },
        finalized: AtomicBool::new(false),
        call_gate: Mutex::new(()),
    });
    let first_state = Arc::clone(&state);
    let first = std::thread::spawn(move || {
        let mut reply = build_native_operation_reply(
            &ParsedOperationRequest::Update { input: vec![1] },
            &first_state,
        )
        .expect("first native call must produce a reply");
        let (data, size, offsets, offsets_size) = raw_parts(&mut reply);
        unsafe { parcel::parse_reply_status(data, size, offsets, offsets_size) }.unwrap()
    });
    entered_rx.recv_timeout(Duration::from_secs(10)).expect("first call must reach backend");
    for request in [
        ParsedOperationRequest::UpdateAad { aad_input: vec![2] },
        ParsedOperationRequest::Update { input: vec![3] },
        ParsedOperationRequest::Finish { input: None, signature: None },
        ParsedOperationRequest::Abort,
    ] {
        let mut reply = build_native_operation_reply(&request, &state).unwrap();
        let (data, size, offsets, offsets_size) = raw_parts(&mut reply);
        let status =
            unsafe { parcel::parse_reply_status(data, size, offsets, offsets_size) }.unwrap();
        assert_eq!(status.exception_code(), ExceptionCode::ServiceSpecific);
        assert_eq!(status.service_specific_error(), ResponseCode::OPERATION_BUSY.0);
        assert!(!state.is_finalized(), "busy must not retire the carrier");
    }
    assert_eq!(updates.load(Ordering::SeqCst), 1);
    release_tx.send(()).unwrap();
    assert!(first.join().unwrap().is_ok());
    let mut reply = build_native_operation_reply(
        &ParsedOperationRequest::Finish { input: None, signature: None },
        &state,
    )
    .unwrap();
    let (data, size, offsets, offsets_size) = raw_parts(&mut reply);
    assert!(unsafe { parcel::parse_reply_status(data, size, offsets, offsets_size) }
        .unwrap()
        .is_ok());
    assert!(state.is_finalized());
    let mut reply =
        build_native_operation_reply(&ParsedOperationRequest::Update { input: vec![6] }, &state)
            .unwrap();
    let (data, size, offsets, offsets_size) = raw_parts(&mut reply);
    let status = unsafe { parcel::parse_reply_status(data, size, offsets, offsets_size) }.unwrap();
    assert_eq!(status.exception_code(), ExceptionCode::ServiceSpecific);
    assert_eq!(
        status.service_specific_error(),
        crate::android::hardware::security::keymint::ErrorCode::ErrorCode::INVALID_OPERATION_HANDLE
            .0
    );
}

struct BlockingOperationBackend {
    entered: mpsc::Sender<()>,
    release: Mutex<mpsc::Receiver<()>>,
    updates: Arc<AtomicUsize>,
}

impl rsbinder::Interface for BlockingOperationBackend {}

impl AospKeystoreOperation for BlockingOperationBackend {
    fn r#updateAad(&self, _input: &[u8]) -> rsbinder::BinderResult<()> {
        Ok(())
    }

    fn r#update(&self, input: &[u8]) -> rsbinder::BinderResult<Option<Vec<u8>>> {
        if self.updates.fetch_add(1, Ordering::SeqCst) == 0 {
            self.entered.send(()).unwrap();
            self.release
                .lock()
                .unwrap()
                .recv_timeout(Duration::from_secs(10))
                .expect("test must release the first backend call");
        }
        Ok(Some(input.to_vec()))
    }

    fn r#finish(
        &self,
        _input: Option<&[u8]>,
        _signature: Option<&[u8]>,
    ) -> rsbinder::BinderResult<Option<Vec<u8>>> {
        Ok(None)
    }

    fn r#abort(&self) -> rsbinder::BinderResult<()> {
        Ok(())
    }
}

fn operation_status(target: LocalBinderTarget, request: ParsedOperationRequest) -> Status {
    let mut reply = build_operation_reply_rewrite(&PendingOperationCall {
        request,
        caller: CallerInfo { uid: 1000, pid: 2000, sid: String::new() },
        target,
        route: RouteTarget::Omk,
    })
    .expect("operation rewrite must succeed")
    .expect("OMK must own the reply");
    let (data, data_size, offsets, offsets_size) = raw_parts(&mut reply);
    unsafe { parcel::parse_reply_status(data, data_size, offsets, offsets_size) }
        .expect("operation reply must contain a status")
}

#[test]
fn overlapping_carrier_calls_are_busy_without_finalizing_or_blocking_other_operations() {
    ensure_binder_process_state();
    let _guard = route_state_test_guard();
    let target = LocalBinderTarget { ptr: 0x1234, cookie: 0x5678 };
    let other_target = LocalBinderTarget { ptr: 0x2345, cookie: 0x6789 };
    let (entered_tx, entered_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let updates = Arc::new(AtomicUsize::new(0));
    remember_operation_target(
        target,
        OperationTargetInfo {
            route: RouteTarget::Omk,
            aad_allowed: true,
            backend: Some(Arc::new(BnKeystoreOperation::new_binder(BlockingOperationBackend {
                entered: entered_tx,
                release: Mutex::new(release_rx),
                updates: updates.clone(),
            }))),
            finalized: false,
            call_gate: Arc::new(Mutex::new(())),
        },
    );
    remember_operation_target(
        other_target,
        OperationTargetInfo {
            route: RouteTarget::Omk,
            aad_allowed: true,
            backend: Some(Arc::new(BnKeystoreOperation::new_binder(TestOperationBackend {
                update_output: vec![7],
                aborts: Arc::new(AtomicUsize::new(0)),
                update_aad_status: None,
            }))),
            finalized: false,
            call_gate: Arc::new(Mutex::new(())),
        },
    );

    let first = std::thread::spawn(move || {
        operation_status(target, ParsedOperationRequest::Update { input: vec![1] })
    });
    entered_rx.recv_timeout(Duration::from_secs(10)).expect("first call must reach backend");
    for request in [
        ParsedOperationRequest::UpdateAad { aad_input: vec![2] },
        ParsedOperationRequest::Update { input: vec![3] },
        ParsedOperationRequest::Finish { input: None, signature: None },
        ParsedOperationRequest::Abort,
    ] {
        let status = operation_status(target, request);
        assert_eq!(status.exception_code(), ExceptionCode::ServiceSpecific);
        assert_eq!(status.service_specific_error(), ResponseCode::OPERATION_BUSY.0);
        let current = lookup_operation_target(target).expect("busy must keep the operation");
        assert!(!current.finalized);
        assert!(current.backend.is_some());
    }
    assert_eq!(updates.load(Ordering::SeqCst), 1);
    assert!(
        operation_status(other_target, ParsedOperationRequest::Update { input: vec![4] },).is_ok()
    );

    release_tx.send(()).unwrap();
    assert!(first.join().unwrap().is_ok());
    assert!(operation_status(target, ParsedOperationRequest::Update { input: vec![5] }).is_ok());
    assert_eq!(updates.load(Ordering::SeqCst), 2);
    assert!(operation_status(
        target,
        ParsedOperationRequest::Finish { input: None, signature: None }
    )
    .is_ok());
    let late = operation_status(target, ParsedOperationRequest::Update { input: vec![6] });
    assert_eq!(late.exception_code(), ExceptionCode::ServiceSpecific);
    assert_eq!(
        late.service_specific_error(),
        crate::android::hardware::security::keymint::ErrorCode::ErrorCode::INVALID_OPERATION_HANDLE
            .0,
    );
}
