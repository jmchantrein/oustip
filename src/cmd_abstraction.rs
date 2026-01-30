//! Command execution abstraction for testability.
//!
//! This module provides a trait-based abstraction over command execution,
//! allowing unit tests to mock system command calls without actually running them.

use anyhow::Result;
use std::io::Write;
use std::process::{Command, Stdio};

#[cfg(test)]
use mockall::automock;

/// Output from command execution
#[derive(Debug, Clone, Default)]
pub struct CommandOutput {
    /// Standard output from the command
    pub stdout: String,
    /// Standard error from the command
    pub stderr: String,
    /// Whether the command succeeded (exit code 0)
    pub success: bool,
    /// The exit code, if available
    pub code: Option<i32>,
}

/// Trait for command execution, allowing dependency injection for testing.
///
/// This trait abstracts over `std::process::Command` to enable mocking in tests.
/// The real implementation uses actual system commands, while tests can use
/// mock implementations to control command behavior.
#[cfg_attr(test, automock)]
pub trait CommandExecutor: Send + Sync {
    /// Execute a command with the given arguments.
    ///
    /// # Arguments
    /// * `cmd` - The command to execute (e.g., "/usr/sbin/nft")
    /// * `args` - The arguments to pass to the command
    ///
    /// # Returns
    /// A `CommandOutput` struct with stdout, stderr, and success status
    fn execute(&self, cmd: &str, args: &[String]) -> Result<CommandOutput>;

    /// Execute a command with stdin input.
    ///
    /// # Arguments
    /// * `cmd` - The command to execute
    /// * `args` - The arguments to pass to the command
    /// * `stdin` - The data to write to the command's stdin
    ///
    /// # Returns
    /// A `CommandOutput` struct with stdout, stderr, and success status
    fn execute_with_stdin(&self, cmd: &str, args: &[String], stdin: &str) -> Result<CommandOutput>;
}

/// Real implementation of CommandExecutor that runs actual system commands.
#[derive(Debug, Clone, Default)]
pub struct RealCommandExecutor;

impl RealCommandExecutor {
    /// Create a new RealCommandExecutor
    pub fn new() -> Self {
        Self
    }
}

impl CommandExecutor for RealCommandExecutor {
    fn execute(&self, cmd: &str, args: &[String]) -> Result<CommandOutput> {
        let output = Command::new(cmd)
            .args(args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()?;

        Ok(CommandOutput {
            stdout: String::from_utf8_lossy(&output.stdout).to_string(),
            stderr: String::from_utf8_lossy(&output.stderr).to_string(),
            success: output.status.success(),
            code: output.status.code(),
        })
    }

    fn execute_with_stdin(
        &self,
        cmd: &str,
        args: &[String],
        stdin_data: &str,
    ) -> Result<CommandOutput> {
        let mut child = Command::new(cmd)
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;

        if let Some(mut stdin) = child.stdin.take() {
            stdin.write_all(stdin_data.as_bytes())?;
        }

        let output = child.wait_with_output()?;

        Ok(CommandOutput {
            stdout: String::from_utf8_lossy(&output.stdout).to_string(),
            stderr: String::from_utf8_lossy(&output.stderr).to_string(),
            success: output.status.success(),
            code: output.status.code(),
        })
    }
}

/// Helper function to convert a slice of &str to Vec<String>.
///
/// This is needed because mockall has issues with lifetimes in `&[&str]`,
/// so we use `&[String]` in the trait signature instead.
pub fn args_to_strings(args: &[&str]) -> Vec<String> {
    args.iter().map(|s| s.to_string()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_args_to_strings() {
        let args = args_to_strings(&["arg1", "arg2", "arg3"]);
        assert_eq!(args, vec!["arg1", "arg2", "arg3"]);
    }

    #[test]
    fn test_args_to_strings_empty() {
        let args = args_to_strings(&[]);
        assert!(args.is_empty());
    }

    #[test]
    fn test_command_output_default() {
        let output = CommandOutput::default();
        assert!(output.stdout.is_empty());
        assert!(output.stderr.is_empty());
        assert!(!output.success);
        assert!(output.code.is_none());
    }

    #[test]
    fn test_real_command_executor_new() {
        let executor = RealCommandExecutor::new();
        let _ = executor; // Just verify it can be created
    }

    #[test]
    fn test_real_command_executor_default() {
        let executor = RealCommandExecutor;
        let _ = executor;
    }

    #[test]
    fn test_real_command_executor_execute_echo() {
        let executor = RealCommandExecutor::new();
        let args = args_to_strings(&["-n", "hello"]);
        let result = executor.execute("echo", &args);
        assert!(result.is_ok());
        let output = result.unwrap();
        assert!(output.success);
        assert_eq!(output.stdout, "hello");
    }

    #[test]
    fn test_real_command_executor_execute_failure() {
        let executor = RealCommandExecutor::new();
        let args = args_to_strings(&["--invalid-flag"]);
        let result = executor.execute("ls", &args);
        // ls --invalid-flag should fail
        assert!(result.is_ok()); // Command runs, just fails
        let output = result.unwrap();
        assert!(!output.success);
    }

    #[test]
    fn test_real_command_executor_execute_with_stdin() {
        let executor = RealCommandExecutor::new();
        let args = args_to_strings(&[]);
        let result = executor.execute_with_stdin("cat", &args, "hello world");
        assert!(result.is_ok());
        let output = result.unwrap();
        assert!(output.success);
        assert_eq!(output.stdout, "hello world");
    }

    #[test]
    fn test_mock_command_executor() {
        let mut mock = MockCommandExecutor::new();

        mock.expect_execute()
            .withf(|cmd, args| cmd == "test" && args == ["arg1".to_string()])
            .times(1)
            .returning(|_, _| {
                Ok(CommandOutput {
                    stdout: "mocked output".to_string(),
                    stderr: String::new(),
                    success: true,
                    code: Some(0),
                })
            });

        let args = vec!["arg1".to_string()];
        let result = mock.execute("test", &args);
        assert!(result.is_ok());
        let output = result.unwrap();
        assert_eq!(output.stdout, "mocked output");
        assert!(output.success);
    }

    #[test]
    fn test_mock_command_executor_with_stdin() {
        let mut mock = MockCommandExecutor::new();

        mock.expect_execute_with_stdin()
            .withf(|cmd, args, stdin| {
                cmd == "nft" && args == ["-f".to_string(), "-".to_string()] && stdin == "script"
            })
            .times(1)
            .returning(|_, _, _| {
                Ok(CommandOutput {
                    stdout: String::new(),
                    stderr: String::new(),
                    success: true,
                    code: Some(0),
                })
            });

        let args = vec!["-f".to_string(), "-".to_string()];
        let result = mock.execute_with_stdin("nft", &args, "script");
        assert!(result.is_ok());
        assert!(result.unwrap().success);
    }
}
