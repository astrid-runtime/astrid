#![cfg_attr(windows, allow(unsafe_code))]

#[cfg(not(windows))]
fn main() {}

#[cfg(windows)]
fn main() {
    windows::run();
}

#[cfg(windows)]
mod windows {

    use std::ffi::{OsStr, OsString};
    use std::io;
    use std::os::windows::ffi::OsStrExt;
    use std::path::Path;
    use std::process::Command;
    use std::ptr;
    use std::time::Duration;

    use astrid_core::local_transport;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::windows::named_pipe::ClientOptions;
    use windows_sys::Win32::Foundation::{CloseHandle, ERROR_ACCESS_DENIED, HANDLE, WAIT_OBJECT_0};
    use windows_sys::Win32::Security::{
        ImpersonateLoggedOnUser, LOGON32_LOGON_INTERACTIVE, LOGON32_PROVIDER_DEFAULT, LogonUserW,
        RevertToSelf,
    };
    use windows_sys::Win32::Storage::FileSystem::SECURITY_IDENTIFICATION;
    use windows_sys::Win32::System::Threading::{
        CreateProcessWithLogonW, GetExitCodeProcess, INFINITE, LOGON_WITH_PROFILE,
        PROCESS_INFORMATION, STARTUPINFOW, WaitForSingleObject,
    };

    const CHILD_MODE: &str = "cross-user-child";
    const SAME_USER_MODE: &str = "same-user-child";

    pub(super) fn run() {
        let args: Vec<OsString> = std::env::args_os().collect();
        if args.get(1).is_some_and(|arg| arg == CHILD_MODE) {
            let pipe_name = args.get(2).expect("child pipe name");
            cross_user_child(pipe_name);
            return;
        }
        if args.get(1).is_some_and(|arg| arg == SAME_USER_MODE) {
            let pipe_name = args.get(2).expect("child pipe name");
            same_user_child(pipe_name);
            return;
        }
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("Tokio runtime");
        runtime.block_on(parent_harness());
    }

    async fn parent_harness() {
        let endpoint = Path::new(r"C:\ignored\system.sock");
        let pipe_name =
            local_transport::endpoint_name_for_test(endpoint).expect("production pipe name");
        let listener = std::sync::Arc::new(local_transport::bind(endpoint).expect("bind pipe"));

        assert!(
            local_transport::listener_rejects_remote_clients_for_test(&listener)
                .await
                .expect("query native pipe flags"),
            "the kernel pipe object must carry PIPE_REJECT_REMOTE_CLIENTS"
        );

        let user = TestUser::create();
        let child_exit = spawn_as_user(&user, &pipe_name, CHILD_MODE)
            .expect("launch alternate-token probe")
            .wait()
            .expect("run alternate-token probe");
        assert_eq!(
            child_exit, 0,
            "alternate-token child failed to prove access-denied rejection"
        );

        assert!(
            tokio::time::timeout(
                Duration::from_millis(150),
                local_transport::accept(&listener)
            )
            .await
            .is_err(),
            "cross-user probe must be rejected before an accepted stream or handshake byte"
        );

        let executable = std::env::current_exe().expect("security harness executable");
        let mut same_user_child = Command::new(executable)
            .arg(SAME_USER_MODE)
            .arg(&pipe_name)
            .spawn()
            .expect("spawn separate same-user production client");
        let mut server = local_transport::accept(&listener)
            .await
            .expect("listener remains usable after rejected alternate token");
        let mut bytes = [0_u8; 9];
        server.read_exact(&mut bytes).await.expect("read");
        assert_eq!(&bytes, b"same-user");
        server.write_all(b"accepted").await.expect("write response");
        server.flush().await.expect("flush response");
        let status = same_user_child.wait().expect("wait for same-user client");
        assert!(
            status.success(),
            "separate same-user production client failed: {status}"
        );
        drop(server);
        drop(listener);
        assert!(
            !local_transport::endpoint_is_present(endpoint).expect("closed endpoint state"),
            "production listener must release the namespace"
        );

        // The deliberately permissive first instance lets a genuine alternate
        // effective token reach the server-side authorization boundary. The
        // client sends bytes first, proving the production accept path performs
        // its required real pre-read before it impersonates and rejects that
        // token. The listener must already have installed its normal protected
        // replacement and recover for a same-user client.
        let permissive = std::sync::Arc::new(
            local_transport::bind_permissive_first_instance_for_test(endpoint)
                .expect("bind permissive effective-token probe instance"),
        );
        let effective_client = spawn_effective_token_thread(&user, &pipe_name);
        let rejected = local_transport::accept(&permissive)
            .await
            .expect_err("alternate effective token must fail closed");
        assert_eq!(rejected.kind(), io::ErrorKind::PermissionDenied);
        assert!(
            rejected.to_string().contains("effective token"),
            "post-read effective-token gate must reject before descriptor or PID checks: \
             {rejected}"
        );
        effective_client
            .join()
            .expect("alternate effective-token client thread");

        let executable = std::env::current_exe().expect("security harness executable");
        let mut recovery_child = Command::new(executable)
            .arg(SAME_USER_MODE)
            .arg(&pipe_name)
            .spawn()
            .expect("spawn recovery client");
        let mut recovery_server = local_transport::accept(&permissive)
            .await
            .expect("protected replacement must accept same-user client");
        let mut recovery_bytes = [0_u8; 9];
        recovery_server
            .read_exact(&mut recovery_bytes)
            .await
            .expect("recovery read");
        assert_eq!(&recovery_bytes, b"same-user");
        recovery_server
            .write_all(b"accepted")
            .await
            .expect("recovery response");
        recovery_server.flush().await.expect("recovery flush");
        assert!(
            recovery_child.wait().expect("wait for recovery").success(),
            "listener did not recover after effective-token rejection"
        );

        user.delete()
            .expect("delete alternate-token test user after probes");
    }

    fn cross_user_child(target_pipe: &OsStr) {
        let own_pipe =
            local_transport::endpoint_name_for_test(Path::new(r"C:\ignored\system.sock"))
                .expect("alternate user pipe name");
        if own_pipe == target_pipe {
            eprintln!("alternate logon unexpectedly has the parent token SID");
            std::process::exit(40);
        }

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("child Tokio runtime");
        let _runtime = runtime.enter();
        match ClientOptions::new().open(target_pipe) {
            Err(error)
                if error.raw_os_error().map(i32::cast_unsigned) == Some(ERROR_ACCESS_DENIED) =>
            {
                std::process::exit(0);
            },
            Err(error) => {
                eprintln!("cross-user open failed for an unexpected reason: {error}");
                std::process::exit(41);
            },
            Ok(_) => {
                eprintln!("cross-user process opened the protected pipe");
                std::process::exit(42);
            },
        }
    }

    fn same_user_child(target_pipe: &OsStr) {
        let endpoint = Path::new(r"C:\ignored\system.sock");
        let own_pipe =
            local_transport::endpoint_name_for_test(endpoint).expect("same-user pipe name");
        assert_eq!(
            own_pipe, target_pipe,
            "same-user child must derive the identical SID-owned namespace"
        );

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("same-user child Tokio runtime");
        runtime.block_on(async {
            let mut stream = local_transport::connect(endpoint)
                .await
                .expect("same-user production connect");
            stream.write_all(b"same-user").await.expect("write");
            stream.flush().await.expect("flush");
            let mut response = [0_u8; 8];
            stream
                .read_exact(&mut response)
                .await
                .expect("read response");
            assert_eq!(&response, b"accepted");
        });
    }

    fn spawn_effective_token_thread(
        user: &TestUser,
        target_pipe: &OsStr,
    ) -> std::thread::JoinHandle<()> {
        let username = user.name.clone();
        let password = user.password.clone();
        let target_pipe = target_pipe.to_os_string();
        std::thread::spawn(move || {
            let username = wide_nul(OsStr::new(&username));
            let domain = wide_nul(OsStr::new("."));
            let password = wide_nul(OsStr::new(&password));
            let mut token = ptr::null_mut();
            let logged_on = unsafe {
                LogonUserW(
                    username.as_ptr(),
                    domain.as_ptr(),
                    password.as_ptr(),
                    LOGON32_LOGON_INTERACTIVE,
                    LOGON32_PROVIDER_DEFAULT,
                    &raw mut token,
                )
            };
            assert!(
                logged_on != 0 && !token.is_null(),
                "LogonUserW failed: {}",
                io::Error::last_os_error()
            );
            let token = TestHandle(token);
            assert!(
                unsafe { ImpersonateLoggedOnUser(token.0) } != 0,
                "ImpersonateLoggedOnUser failed: {}",
                io::Error::last_os_error()
            );
            let impersonation = TestImpersonation { active: true };

            // Endpoint derivation deliberately uses the process token, so this
            // current-user process still selects the parent's pipe while its
            // connecting thread presents the alternate effective token.
            let own_pipe =
                local_transport::endpoint_name_for_test(Path::new(r"C:\ignored\system.sock"))
                    .expect("process-token pipe name");
            assert_eq!(own_pipe, target_pipe);

            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("effective-token thread Tokio runtime");
            runtime.block_on(async {
                let mut options = ClientOptions::new();
                options.security_qos_flags(SECURITY_IDENTIFICATION);
                let mut stream = options
                    .open(&target_pipe)
                    .expect("permissive first instance must admit alternate effective token");
                stream
                    .write_all(b"alternate")
                    .await
                    .expect("effective-token probe write");
                stream.flush().await.expect("effective-token probe flush");
                let mut byte = [0_u8; 1];
                match stream.read(&mut byte).await {
                    Ok(0) | Err(_) => {},
                    Ok(_) => panic!("rejected effective-token client received server data"),
                }
            });
            impersonation.revert();
        })
    }

    struct TestHandle(HANDLE);

    impl Drop for TestHandle {
        fn drop(&mut self) {
            if !self.0.is_null() {
                unsafe {
                    CloseHandle(self.0);
                }
            }
        }
    }

    struct TestImpersonation {
        active: bool,
    }

    impl TestImpersonation {
        fn revert(mut self) {
            assert!(
                unsafe { RevertToSelf() } != 0,
                "test thread failed to revert impersonation: {}",
                io::Error::last_os_error()
            );
            self.active = false;
        }
    }

    impl Drop for TestImpersonation {
        fn drop(&mut self) {
            if self.active && unsafe { RevertToSelf() } == 0 {
                std::process::abort();
            }
        }
    }

    struct TestUser {
        name: String,
        password: String,
        active: bool,
    }

    impl TestUser {
        fn create() -> Self {
            let name = format!("AstridP{:08x}", std::process::id());
            let password = format!("Aa9!{name}x");

            let absent = Command::new("net")
                .args(["user", &name])
                .status()
                .expect("query test user");
            assert!(
                !absent.success(),
                "refusing to reuse or delete a pre-existing local account"
            );

            let created = Command::new("net")
                .args(["user", &name, &password, "/add", "/expires:never"])
                .status()
                .expect("create alternate-token test user");
            assert!(
                created.success(),
                "native runner must permit creation of an isolated local test user"
            );
            Self {
                name,
                password,
                active: true,
            }
        }

        fn delete(mut self) -> io::Result<()> {
            self.delete_inner()
        }

        fn delete_inner(&mut self) -> io::Result<()> {
            if !self.active {
                return Ok(());
            }
            let deleted = Command::new("net")
                .args(["user", &self.name, "/delete"])
                .status()?;
            if !deleted.success() {
                return Err(io::Error::other(format!(
                    "net user failed to delete {}",
                    self.name
                )));
            }
            self.active = false;
            Ok(())
        }
    }

    impl Drop for TestUser {
        fn drop(&mut self) {
            // Best effort during unwinding. The normal path calls `delete` and
            // asserts cleanup explicitly without risking a double panic.
            let _ = self.delete_inner();
        }
    }

    fn spawn_as_user(user: &TestUser, pipe_name: &OsStr, mode: &str) -> io::Result<LogonChild> {
        let executable = std::env::current_exe()?;
        let application = wide_nul(executable.as_os_str());
        let username = wide_nul(OsStr::new(&user.name));
        let domain = wide_nul(OsStr::new("."));
        let password = wide_nul(OsStr::new(&user.password));
        let command = format!(
            "\"{}\" {mode} \"{}\"",
            executable.display(),
            pipe_name.to_string_lossy()
        );
        let mut command = wide_nul(OsStr::new(&command));

        let mut startup = STARTUPINFOW {
            cb: u32::try_from(std::mem::size_of::<STARTUPINFOW>())
                .map_err(|_| io::Error::other("STARTUPINFOW size overflow"))?,
            ..Default::default()
        };
        let mut process = PROCESS_INFORMATION::default();
        let created = unsafe {
            CreateProcessWithLogonW(
                username.as_ptr(),
                domain.as_ptr(),
                password.as_ptr(),
                LOGON_WITH_PROFILE,
                application.as_ptr(),
                command.as_mut_ptr(),
                0,
                ptr::null(),
                ptr::null(),
                &raw mut startup,
                &raw mut process,
            )
        };
        if created == 0 {
            return Err(io::Error::last_os_error());
        }

        unsafe {
            CloseHandle(process.hThread);
        }
        Ok(LogonChild(process.hProcess))
    }

    struct LogonChild(HANDLE);

    impl LogonChild {
        fn wait(mut self) -> io::Result<u32> {
            let wait = unsafe { WaitForSingleObject(self.0, INFINITE) };
            if wait != WAIT_OBJECT_0 {
                return Err(io::Error::other(format!(
                    "alternate-token child wait failed: {wait}"
                )));
            }

            let mut exit_code = u32::MAX;
            let read = unsafe { GetExitCodeProcess(self.0, &raw mut exit_code) };
            unsafe {
                CloseHandle(self.0);
            }
            self.0 = ptr::null_mut();
            if read == 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(exit_code)
        }
    }

    impl Drop for LogonChild {
        fn drop(&mut self) {
            if !self.0.is_null() {
                unsafe {
                    CloseHandle(self.0);
                }
            }
        }
    }

    fn wide_nul(value: &OsStr) -> Vec<u16> {
        value.encode_wide().chain(std::iter::once(0)).collect()
    }
}
