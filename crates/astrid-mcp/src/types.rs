//! MCP types for tools, resources, and results.

use rmcp::model::{self as rmcp_model, ContentBlock};
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Definition of an MCP tool.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolDefinition {
    /// Tool name.
    pub name: String,
    /// Server this tool belongs to.
    pub server: String,
    /// Human-readable description.
    pub description: Option<String>,
    /// JSON Schema for input parameters.
    pub input_schema: Value,
}

impl ToolDefinition {
    /// Create a new tool definition.
    #[must_use]
    pub fn new(name: impl Into<String>, server: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            server: server.into(),
            description: None,
            input_schema: serde_json::json!({"type": "object"}),
        }
    }

    /// Create from an rmcp `Tool` and server name.
    #[must_use]
    pub fn from_rmcp(tool: &rmcp_model::Tool, server: &str) -> Self {
        Self {
            name: tool.name.to_string(),
            server: server.to_string(),
            description: tool.description.as_deref().map(String::from),
            input_schema: serde_json::to_value(&*tool.input_schema)
                .unwrap_or_else(|_| serde_json::json!({"type": "object"})),
        }
    }

    /// Get the full tool identifier (server:tool).
    #[must_use]
    pub fn full_name(&self) -> String {
        format!("{}:{}", self.server, self.name)
    }

    /// Get the MCP resource URI for this tool.
    #[must_use]
    pub fn resource_uri(&self) -> String {
        format!("mcp://{}:{}", self.server, self.name)
    }
}

/// Result from calling an MCP tool.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolResult {
    /// Whether the call succeeded.
    pub success: bool,
    /// Content returned by the tool.
    pub content: Vec<ToolContent>,
    /// Error message if failed.
    pub error: Option<String>,
    /// Whether this result is an error.
    pub is_error: bool,
}

impl ToolResult {
    /// Create a successful result with text content.
    #[must_use]
    pub fn text(content: impl Into<String>) -> Self {
        Self {
            success: true,
            content: vec![ToolContent::Text {
                text: content.into(),
            }],
            error: None,
            is_error: false,
        }
    }

    /// Create an error result.
    #[must_use]
    pub fn error(message: impl Into<String>) -> Self {
        let msg = message.into();
        Self {
            success: false,
            content: vec![ToolContent::Text { text: msg.clone() }],
            error: Some(msg),
            is_error: true,
        }
    }

    /// Get text content as a single string.
    #[must_use]
    pub fn text_content(&self) -> String {
        self.content
            .iter()
            .filter_map(|c| match c {
                ToolContent::Text { text } => Some(text.as_str()),
                _ => None,
            })
            .collect::<Vec<_>>()
            .join("\n")
    }
}

impl From<rmcp_model::CallToolResult> for ToolResult {
    fn from(result: rmcp_model::CallToolResult) -> Self {
        let is_error = result.is_error.unwrap_or(false);
        let content: Vec<ToolContent> = result.content.iter().map(ToolContent::from_rmcp).collect();

        let error = if is_error {
            // Extract text content as the error message
            let text = content
                .iter()
                .filter_map(|c| match c {
                    ToolContent::Text { text } => Some(text.as_str()),
                    _ => None,
                })
                .collect::<Vec<_>>()
                .join("\n");
            if text.is_empty() {
                Some("Unknown error".to_string())
            } else {
                Some(text)
            }
        } else {
            None
        };

        Self {
            success: !is_error,
            content,
            error,
            is_error,
        }
    }
}

/// Content types returned by tools.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ToolContent {
    /// Text content.
    Text {
        /// The text.
        text: String,
    },
    /// Image content.
    Image {
        /// Base64-encoded image data.
        data: String,
        /// MIME type.
        mime_type: String,
    },
    /// Resource reference.
    Resource {
        /// Resource URI.
        uri: String,
        /// Resource data.
        data: Option<String>,
        /// MIME type.
        mime_type: Option<String>,
    },
}

impl ToolContent {
    /// Convert from an rmcp content block.
    fn from_rmcp(content: &ContentBlock) -> Self {
        match content {
            ContentBlock::Text(text) => Self::Text {
                text: text.text.clone(),
            },
            ContentBlock::Image(image) => Self::Image {
                data: image.data.clone(),
                mime_type: image.mime_type.clone(),
            },
            ContentBlock::Resource(embedded) => match &embedded.resource {
                rmcp_model::ResourceContents::TextResourceContents {
                    uri,
                    mime_type,
                    text,
                    ..
                } => Self::Resource {
                    uri: uri.clone(),
                    data: Some(text.clone()),
                    mime_type: mime_type.clone(),
                },
                rmcp_model::ResourceContents::BlobResourceContents {
                    uri,
                    mime_type,
                    blob,
                    ..
                } => Self::Resource {
                    uri: uri.clone(),
                    data: Some(blob.clone()),
                    mime_type: mime_type.clone(),
                },
                _ => Self::Text {
                    text: "[unsupported resource content]".to_string(),
                },
            },
            // Audio and ResourceLink variants map to text fallbacks
            ContentBlock::Audio(_) => Self::Text {
                text: "[audio content]".to_string(),
            },
            ContentBlock::ResourceLink(resource) => Self::Resource {
                uri: resource.uri.clone(),
                data: None,
                mime_type: resource.mime_type.clone(),
            },
            _ => Self::Text {
                text: "[unsupported content type]".to_string(),
            },
        }
    }
}

/// Server capabilities.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[expect(clippy::struct_excessive_bools)]
pub(crate) struct ServerCapabilities {
    /// Whether the server supports tools.
    #[serde(default)]
    pub tools: bool,
    /// Whether the server supports resources.
    #[serde(default)]
    pub resources: bool,
    /// Whether the server supports prompts.
    #[serde(default)]
    pub prompts: bool,
    /// Whether the server supports sampling.
    #[serde(default)]
    pub sampling: bool,
    /// Whether the server supports elicitation.
    #[serde(default)]
    pub elicitation: bool,
}

impl ServerCapabilities {
    /// Convert from rmcp `ServerCapabilities`.
    #[must_use]
    pub(crate) fn from_rmcp(caps: &rmcp_model::ServerCapabilities) -> Self {
        Self {
            tools: caps.tools.is_some(),
            resources: caps.resources.is_some(),
            prompts: caps.prompts.is_some(),
            // Server capabilities don't have sampling/elicitation fields;
            // those are client capabilities. Default to false.
            sampling: false,
            elicitation: false,
        }
    }
}

/// Information about a running server.
///
/// Stored per `RunningServer` after the MCP handshake. Fields are not yet
/// consumed but will be needed when exposing server metadata to frontends.
#[derive(Debug, Clone)]
#[expect(
    dead_code,
    reason = "fields populated from MCP handshake, not yet exposed to consumers"
)]
pub(crate) struct ServerInfo {
    /// Server name.
    pub name: String,
    /// Protocol version.
    pub protocol_version: String,
    /// Server capabilities.
    pub capabilities: ServerCapabilities,
    /// Server instructions (for LLM).
    pub instructions: Option<String>,
}

impl ServerInfo {
    /// Convert from rmcp `InitializeResult` and a server name.
    #[must_use]
    pub(crate) fn from_rmcp(info: &rmcp_model::InitializeResult, name: &str) -> Self {
        Self {
            name: name.to_string(),
            protocol_version: info.protocol_version.to_string(),
            capabilities: ServerCapabilities::from_rmcp(&info.capabilities),
            instructions: info.instructions.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tool_definition() {
        let tool = ToolDefinition::new("read_file", "filesystem");
        assert_eq!(tool.full_name(), "filesystem:read_file");
        assert_eq!(tool.resource_uri(), "mcp://filesystem:read_file");
    }

    #[test]
    fn test_tool_result_text() {
        let result = ToolResult::text("Hello, world!");
        assert!(result.success);
        assert!(!result.is_error);
        assert_eq!(result.text_content(), "Hello, world!");
    }

    #[test]
    fn test_tool_result_error() {
        let result = ToolResult::error("Something went wrong");
        assert!(!result.success);
        assert!(result.is_error);
        assert_eq!(result.error, Some("Something went wrong".to_string()));
    }

    #[test]
    fn rmcp_text_content_is_preserved() {
        let content = ContentBlock::text("Hello from MCP");

        match ToolContent::from_rmcp(&content) {
            ToolContent::Text { text } => assert_eq!(text, "Hello from MCP"),
            _ => panic!("text content must remain text"),
        }
    }
}
