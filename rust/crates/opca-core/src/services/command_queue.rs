//! In-memory command queue for batching 1Password write operations.
//!
//! Write operations are queued in memory and flushed after each logical
//! operation completes. Multiple `store_document` commands for the same
//! target are collapsed so only the final state is written.
//!
//! The queue is intentionally **not** persisted to the database because
//! payloads may contain secret material (private keys, cert PEM data).

use serde::{Deserialize, Serialize};

use crate::error::OpcaError;
use crate::op::{CommandRunner, Op, StoreAction};

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// The kind of 1Password write operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QueueOp {
    StoreItem,
    StoreDocument,
    RenameItem,
    DeleteItem,
}

/// Payload data for a queued command.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueuePayload {
    /// "create", "edit", or "auto"
    #[serde(default)]
    pub action: String,
    /// 1Password assignment-syntax attributes (for store_item)
    #[serde(default)]
    pub attributes: Vec<String>,
    /// Document filename (for store_document)
    #[serde(default)]
    pub filename: String,
    /// Document/item content
    #[serde(default)]
    pub content: String,
    /// Rename destination title
    #[serde(default)]
    pub dst_title: String,
    /// Whether to archive on delete
    #[serde(default = "default_true")]
    pub archive: bool,
    /// 1Password category (for store_item create)
    #[serde(default)]
    pub category: String,
}

fn default_true() -> bool {
    true
}

impl Default for QueuePayload {
    fn default() -> Self {
        Self {
            action: "auto".to_string(),
            attributes: Vec::new(),
            filename: String::new(),
            content: String::new(),
            dst_title: String::new(),
            archive: true,
            category: String::new(),
        }
    }
}

/// A single queued write operation for 1Password.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueuedCommand {
    pub operation: QueueOp,
    pub target_type: String,
    pub target_id: String,
    pub payload: QueuePayload,
}

/// Result of executing a single queued command.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlushResult {
    pub operation: QueueOp,
    pub target_id: String,
    pub success: bool,
    pub error: Option<String>,
}

// ---------------------------------------------------------------------------
// CommandQueue
// ---------------------------------------------------------------------------

/// In-memory command queue for batching 1Password write operations.
pub struct CommandQueue {
    queue: Vec<QueuedCommand>,
}

impl CommandQueue {
    pub fn new() -> Self {
        Self { queue: Vec::new() }
    }

    /// Number of commands waiting to be flushed.
    pub fn pending_count(&self) -> usize {
        self.queue.len()
    }

    /// Add a command to the queue.
    pub fn enqueue(&mut self, command: QueuedCommand) {
        self.queue.push(command);
    }

    /// Convenience: queue a store_item operation.
    pub fn enqueue_store_item(
        &mut self,
        target_id: &str,
        attributes: Vec<String>,
        target_type: &str,
        action: &str,
        category: &str,
    ) {
        self.enqueue(QueuedCommand {
            operation: QueueOp::StoreItem,
            target_type: target_type.to_string(),
            target_id: target_id.to_string(),
            payload: QueuePayload {
                action: action.to_string(),
                attributes,
                category: category.to_string(),
                ..Default::default()
            },
        });
    }

    /// Convenience: queue a store_document operation.
    pub fn enqueue_store_document(
        &mut self,
        target_id: &str,
        filename: &str,
        content: &str,
        target_type: &str,
        action: &str,
    ) {
        self.enqueue(QueuedCommand {
            operation: QueueOp::StoreDocument,
            target_type: target_type.to_string(),
            target_id: target_id.to_string(),
            payload: QueuePayload {
                action: action.to_string(),
                filename: filename.to_string(),
                content: content.to_string(),
                ..Default::default()
            },
        });
    }

    /// Convenience: queue a rename_item operation.
    pub fn enqueue_rename_item(&mut self, src_title: &str, dst_title: &str) {
        self.enqueue(QueuedCommand {
            operation: QueueOp::RenameItem,
            target_type: "certbundle".to_string(),
            target_id: src_title.to_string(),
            payload: QueuePayload {
                dst_title: dst_title.to_string(),
                ..Default::default()
            },
        });
    }

    /// Convenience: queue a delete_item operation.
    pub fn enqueue_delete_item(&mut self, target_id: &str, archive: bool) {
        self.enqueue(QueuedCommand {
            operation: QueueOp::DeleteItem,
            target_type: "certbundle".to_string(),
            target_id: target_id.to_string(),
            payload: QueuePayload {
                archive,
                ..Default::default()
            },
        });
    }

    /// Collapse redundant commands before flushing.
    ///
    /// Multiple `store_document` commands for the same `target_id` are
    /// collapsed into the last one, since only the final state matters.
    fn collapse_queue(&self) -> Vec<QueuedCommand> {
        // Find the last index for each store_document target_id
        let mut last_store_doc = std::collections::HashMap::new();
        for (i, cmd) in self.queue.iter().enumerate() {
            if cmd.operation == QueueOp::StoreDocument {
                last_store_doc.insert(&cmd.target_id, i);
            }
        }

        self.queue
            .iter()
            .enumerate()
            .filter(|(i, cmd)| {
                if cmd.operation == QueueOp::StoreDocument {
                    last_store_doc.get(&cmd.target_id) == Some(i)
                } else {
                    true
                }
            })
            .map(|(_, cmd)| cmd.clone())
            .collect()
    }

    /// Execute all queued commands against the 1Password CLI.
    pub fn flush<R: CommandRunner>(&mut self, op: &Op<R>) -> Vec<FlushResult> {
        if self.queue.is_empty() {
            return Vec::new();
        }

        let commands = self.collapse_queue();
        self.queue.clear();

        let mut results = Vec::new();

        for cmd in commands {
            let mut result = FlushResult {
                operation: cmd.operation.clone(),
                target_id: cmd.target_id.clone(),
                success: false,
                error: None,
            };

            let exec_result: Result<(), OpcaError> = match cmd.operation {
                QueueOp::StoreItem => {
                    let action = parse_store_action(&cmd.payload.action);
                    let attr_refs: Vec<&str> =
                        cmd.payload.attributes.iter().map(|s| s.as_str()).collect();
                    op.store_item(
                        &cmd.target_id,
                        Some(&attr_refs),
                        action,
                        &cmd.payload.category,
                        None,
                        None,
                    )
                    .map(|_| ())
                }
                QueueOp::StoreDocument => {
                    let action = parse_store_action(&cmd.payload.action);
                    op.store_document(
                        &cmd.target_id,
                        &cmd.payload.filename,
                        &cmd.payload.content,
                        action,
                        None,
                    )
                    .map(|_| ())
                }
                QueueOp::RenameItem => op
                    .rename_item(&cmd.target_id, &cmd.payload.dst_title)
                    .map(|_| ()),
                QueueOp::DeleteItem => op
                    .delete_item(&cmd.target_id, cmd.payload.archive)
                    .map(|_| ()),
            };

            match exec_result {
                Ok(()) => result.success = true,
                Err(e) => result.error = Some(e.to_string()),
            }

            results.push(result);
        }

        results
    }

    /// Discard all pending commands without executing them.
    pub fn clear(&mut self) {
        self.queue.clear();
    }
}

impl Default for CommandQueue {
    fn default() -> Self {
        Self::new()
    }
}

fn parse_store_action(s: &str) -> StoreAction {
    match s {
        "create" => StoreAction::Create,
        "edit" => StoreAction::Edit,
        _ => StoreAction::Auto,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_queue_is_empty() {
        let q = CommandQueue::new();
        assert_eq!(q.pending_count(), 0);
    }

    #[test]
    fn test_enqueue_increments_count() {
        let mut q = CommandQueue::new();
        q.enqueue_store_item("item1", vec!["cn=test".into()], "certbundle", "create", "Secure Note");
        assert_eq!(q.pending_count(), 1);
        q.enqueue_store_item("item2", vec!["cn=test2".into()], "certbundle", "create", "Secure Note");
        assert_eq!(q.pending_count(), 2);
    }

    #[test]
    fn test_clear_empties_queue() {
        let mut q = CommandQueue::new();
        q.enqueue_store_item("item1", vec![], "certbundle", "create", "Secure Note");
        q.enqueue_store_item("item2", vec![], "certbundle", "create", "Secure Note");
        assert_eq!(q.pending_count(), 2);
        q.clear();
        assert_eq!(q.pending_count(), 0);
    }

    #[test]
    fn test_collapse_keeps_last_store_document() {
        let mut q = CommandQueue::new();
        q.enqueue_store_document("CA_Database", "db.sql", "v1", "database", "auto");
        q.enqueue_store_document("CA_Database", "db.sql", "v2", "database", "auto");
        q.enqueue_store_document("CA_Database", "db.sql", "v3", "database", "auto");

        let collapsed = q.collapse_queue();
        assert_eq!(collapsed.len(), 1);
        assert_eq!(collapsed[0].payload.content, "v3");
    }

    #[test]
    fn test_collapse_preserves_different_targets() {
        let mut q = CommandQueue::new();
        q.enqueue_store_document("CA_Database", "db.sql", "v1", "database", "auto");
        q.enqueue_store_document("CRL", "crl.pem", "crl-data", "crl", "auto");
        q.enqueue_store_document("CA_Database", "db.sql", "v2", "database", "auto");

        let collapsed = q.collapse_queue();
        assert_eq!(collapsed.len(), 2);
        assert_eq!(collapsed[0].target_id, "CRL");
        assert_eq!(collapsed[1].target_id, "CA_Database");
        assert_eq!(collapsed[1].payload.content, "v2");
    }

    #[test]
    fn test_collapse_preserves_non_document_ops() {
        let mut q = CommandQueue::new();
        q.enqueue_store_item("cert1", vec!["cn=a".into()], "certbundle", "create", "Secure Note");
        q.enqueue_store_document("CA_Database", "db.sql", "v1", "database", "auto");
        q.enqueue_rename_item("cert1", "cert1_revoked");
        q.enqueue_store_document("CA_Database", "db.sql", "v2", "database", "auto");

        let collapsed = q.collapse_queue();
        assert_eq!(collapsed.len(), 3);
        assert_eq!(collapsed[0].operation, QueueOp::StoreItem);
        assert_eq!(collapsed[1].operation, QueueOp::RenameItem);
        assert_eq!(collapsed[2].operation, QueueOp::StoreDocument);
    }

    #[test]
    fn test_enqueue_rename() {
        let mut q = CommandQueue::new();
        q.enqueue_rename_item("old_name", "new_name");
        assert_eq!(q.pending_count(), 1);

        let cmd = &q.queue[0];
        assert_eq!(cmd.operation, QueueOp::RenameItem);
        assert_eq!(cmd.target_id, "old_name");
        assert_eq!(cmd.payload.dst_title, "new_name");
    }

    #[test]
    fn test_enqueue_delete() {
        let mut q = CommandQueue::new();
        q.enqueue_delete_item("old_cert", true);
        assert_eq!(q.pending_count(), 1);

        let cmd = &q.queue[0];
        assert_eq!(cmd.operation, QueueOp::DeleteItem);
        assert!(cmd.payload.archive);
    }

    #[test]
    fn test_flush_with_mock_runner() {
        use crate::testutil::{mock_op, ok_output};

        let op = mock_op(vec![ok_output(r#"{"id":"abc123"}"#)]);

        let mut q = CommandQueue::new();
        q.enqueue_store_item("test_cert", vec!["cn[text]=test".into()], "certbundle", "create", "Secure Note");

        let results = q.flush(&op);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].operation, QueueOp::StoreItem);
        assert_eq!(results[0].target_id, "test_cert");
        assert_eq!(q.pending_count(), 0);
    }

    #[test]
    fn test_flush_empty_queue() {
        use crate::testutil::mock_op;

        let op = mock_op(vec![]);

        let mut q = CommandQueue::new();
        let results = q.flush(&op);
        assert!(results.is_empty());
    }

    #[test]
    fn test_parse_store_action() {
        assert_eq!(parse_store_action("create"), StoreAction::Create);
        assert_eq!(parse_store_action("edit"), StoreAction::Edit);
        assert_eq!(parse_store_action("auto"), StoreAction::Auto);
        assert_eq!(parse_store_action("anything"), StoreAction::Auto);
    }
}
