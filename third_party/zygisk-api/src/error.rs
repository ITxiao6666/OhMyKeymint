#[derive(Clone, Debug, thiserror::Error)]
pub enum ZygiskError {
    #[error("Unable to connect to the companion process")]
    ConnectCompanionError,
    #[error("Unrecognized state flag ({0:#x}) returned by Zygisk")]
    UnrecognizedStateFlag(u32),
    #[error("Encountered an error while committing PLT hooks")]
    PltHookCommitError,
}
