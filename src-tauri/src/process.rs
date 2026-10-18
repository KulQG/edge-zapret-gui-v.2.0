//! Frontend-facing state for an official BAT session.
//!
//! The elevated helper owns launch and stop authorization. No process handle or
//! job is tied to the GUI lifetime: closing the GUI leaves a verified session
//! running, and a later GUI instance can query it again.

use crate::error::AppError;
use crate::strategy::LaunchPlan;
use serde::Serialize;

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ProcessState {
    Running,
    Stopped,
    Error,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProcessStatus {
    pub state: ProcessState,
    pub running: bool,
    pub pid: Option<u32>,
    pub strategy_id: Option<String>,
    pub strategy_name: Option<String>,
    pub executable_path: Option<String>,
    /// Unix epoch milliseconds, converted from the process creation FILETIME.
    pub created_at_ms: Option<u64>,
    pub exit_code: Option<i32>,
    pub error: Option<AppError>,
}

impl Default for ProcessStatus {
    fn default() -> Self {
        Self {
            state: ProcessState::Stopped,
            running: false,
            pid: None,
            strategy_id: None,
            strategy_name: None,
            executable_path: None,
            created_at_ms: None,
            exit_code: None,
            error: None,
        }
    }
}

/// Thin facade retained for existing Tauri commands and recovery flows. The
/// helper revalidates the persisted process identity for every operation.
#[derive(Default)]
pub struct ProcessManager;

impl ProcessManager {
    pub fn start(&mut self, plan: LaunchPlan) -> Result<ProcessStatus, AppError> {
        crate::manual_helper::start(&plan.strategy_id)
    }

    pub fn stop(&mut self) -> Result<ProcessStatus, AppError> {
        crate::manual_helper::stop()
    }

    pub fn status(&mut self) -> ProcessStatus {
        crate::manual_helper::status()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_status_has_no_process_identity() {
        let status = ProcessStatus::default();
        assert_eq!(status.state, ProcessState::Stopped);
        assert!(!status.running);
        assert!(status.pid.is_none());
        assert!(status.executable_path.is_none());
    }
}
