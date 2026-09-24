//! Shared test utilities for opca-core.
//!
//! Provides a [`MockRunner`] that returns pre-configured responses,
//! plus helpers for building common [`CommandOutput`] values.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use crate::error::OpcaError;
use crate::op::{CommandOutput, CommandRunner, Op};

/// A mock command runner that returns pre-configured responses in order.
/// Clones share one queue and call log.
#[derive(Clone, Default)]
pub struct MockRunner {
    responses: Arc<Mutex<Vec<CommandOutput>>>,
    calls: Arc<Mutex<Vec<Vec<String>>>>,
}

impl MockRunner {
    pub fn new(responses: Vec<CommandOutput>) -> Self {
        Self {
            responses: Arc::new(Mutex::new(responses)),
            calls: Arc::default(),
        }
    }

    /// Return all recorded call argument lists.
    pub fn calls(&self) -> Vec<Vec<String>> {
        self.calls.lock().unwrap().clone()
    }
}

impl CommandRunner for MockRunner {
    fn run(
        &self,
        _bin: &str,
        args: &[&str],
        _input: Option<&str>,
        _env_vars: Option<&HashMap<String, String>>,
    ) -> Result<CommandOutput, OpcaError> {
        self.calls
            .lock()
            .unwrap()
            .push(args.iter().map(|s| s.to_string()).collect());

        let mut responses = self.responses.lock().unwrap();
        if responses.is_empty() {
            Ok(CommandOutput {
                stdout: String::new(),
                stderr: String::new(),
                success: true,
            })
        } else {
            Ok(responses.remove(0))
        }
    }
}

/// Build a successful [`CommandOutput`] with the given stdout.
pub fn ok_output(stdout: &str) -> CommandOutput {
    CommandOutput {
        stdout: stdout.to_string(),
        stderr: String::new(),
        success: true,
    }
}

/// Build a failed [`CommandOutput`] with the given stderr.
pub fn err_output(stderr: &str) -> CommandOutput {
    CommandOutput {
        stdout: String::new(),
        stderr: stderr.to_string(),
        success: false,
    }
}

/// Create an `Op<MockRunner>` with no account configured.
pub fn mock_op(responses: Vec<CommandOutput>) -> Op<MockRunner> {
    let runner = MockRunner::new(responses);
    Op::with_runner("TestVault", None, "op", runner)
}

/// Create an `Op<MockRunner>` with a test account configured.
pub fn mock_op_with_account(responses: Vec<CommandOutput>) -> Op<MockRunner> {
    let runner = MockRunner::new(responses);
    Op::with_runner("TestVault", Some("test.1password.com".into()), "op", runner)
}
