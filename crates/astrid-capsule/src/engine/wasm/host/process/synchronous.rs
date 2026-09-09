//! Finite stdin delivery while stdout and stderr are drained concurrently.

use std::io::{self, Write};
use std::process::{Child, Output};

pub(super) fn wait_with_input(mut child: Child, input: Option<Vec<u8>>) -> io::Result<Output> {
    let pipe = child.stdin.take();
    let Some(input) = input else {
        drop(pipe);
        return child.wait_with_output();
    };
    let Some(mut pipe) = pipe else {
        let _ = child.kill();
        let _ = child.wait();
        return Err(io::Error::other("spawn stdin pipe unavailable"));
    };
    std::thread::scope(|scope| {
        // Writing before collecting output deadlocks when the child fills an
        // output pipe before reading input. Dropping the writer supplies EOF.
        let writer = match std::thread::Builder::new()
            .name("process-stdin".into())
            .spawn_scoped(scope, move || pipe.write_all(&input))
        {
            Ok(writer) => writer,
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(error);
            },
        };
        let output = child.wait_with_output();
        let written = writer
            .join()
            .map_err(|_| io::Error::other("spawn stdin writer panicked"))?;
        written?;
        output
    })
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::process::{Command, Stdio};

    fn shell(script: &str) -> Child {
        Command::new("/bin/sh")
            .args(["-c", script])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap()
    }

    #[test]
    fn delivers_json_and_eof() {
        let input = b"{\"operation\":\"slice\",\"query\":\"run_init\"}\n".to_vec();
        let output = wait_with_input(shell("cat"), Some(input.clone())).unwrap();
        assert!(output.status.success());
        assert_eq!(output.stdout, input);
    }

    #[test]
    fn empty_and_absent_input_close_stdin() {
        for input in [None, Some(Vec::new())] {
            let output = wait_with_input(shell("cat; printf eof"), input).unwrap();
            assert!(output.status.success());
            assert_eq!(output.stdout, b"eof");
        }
    }

    #[test]
    fn early_stdin_close_reports_write_failure_and_reaps_child() {
        let child = shell("exec 0<&-; exit 0");
        let error = wait_with_input(child, Some(vec![b'x'; super::super::MAX_SPAWN_STDIN_BYTES]))
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::BrokenPipe);
    }

    #[test]
    fn drains_output_while_delivering_large_input() {
        let input = vec![b'x'; super::super::MAX_SPAWN_STDIN_BYTES];
        let child = shell(
            "dd if=/dev/zero bs=65536 count=4 2>/dev/null; dd if=/dev/zero bs=65536 count=4 >&2 2>/dev/null; cat",
        );
        let output = wait_with_input(child, Some(input.clone())).unwrap();
        assert!(output.status.success());
        assert_eq!(&output.stdout[..262_144], vec![0; 262_144]);
        assert_eq!(&output.stdout[262_144..], input);
        assert_eq!(output.stderr, vec![0; 262_144]);
    }
}
