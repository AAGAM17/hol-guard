#[cfg(target_os = "linux")]
use std::io::ErrorKind;
#[cfg(any(all(test, unix), target_os = "linux"))]
use std::io::Write;
#[cfg(target_os = "linux")]
use std::process::{Command, Stdio};

#[cfg(any(target_os = "linux", target_os = "macos"))]
use super::{MAX_SECRET_TEXT_BYTES, SERVICE_NAME};

#[cfg(target_os = "macos")]
pub(super) fn read_platform_secret(account: &str) -> Result<Option<String>, String> {
    read_platform_secret_with_limit(account, MAX_SECRET_TEXT_BYTES)
}

#[cfg(target_os = "macos")]
pub(super) fn read_platform_secret_with_limit(
    account: &str,
    max_bytes: usize,
) -> Result<Option<String>, String> {
    use security_framework::passwords::generic_password;

    let value = match generic_password(
        security_framework::passwords::PasswordOptions::new_generic_password(SERVICE_NAME, account),
    ) {
        Ok(value) => value,
        // Security.framework's stable errSecItemNotFound value. Do not turn
        // any other keychain failure into an apparent unenrolled state.
        Err(error) if error.code() == -25300 => return Ok(None),
        Err(error) => return Err(map_keychain_error(error)),
    };
    let value =
        String::from_utf8(value).map_err(|_| "native_approval_secure_state_invalid".to_owned())?;
    if value.len() > max_bytes {
        return Err("native_approval_secure_state_invalid".to_owned());
    }
    Ok(Some(value.trim().to_owned()))
}

#[cfg(target_os = "macos")]
pub(super) fn write_platform_secret(account: &str, value: &str) -> Result<(), String> {
    write_platform_secret_with_limit(account, value, MAX_SECRET_TEXT_BYTES)
}

#[cfg(target_os = "macos")]
pub(super) fn write_platform_secret_with_limit(
    account: &str,
    value: &str,
    max_bytes: usize,
) -> Result<(), String> {
    use security_framework::passwords::set_generic_password;

    if value.len() > max_bytes {
        return Err("native_approval_secure_state_invalid".to_owned());
    }
    set_generic_password(SERVICE_NAME, account, value.as_bytes()).map_err(map_keychain_error)
}

#[cfg(target_os = "macos")]
fn map_keychain_error(_error: security_framework::base::Error) -> String {
    "native_approval_secure_state_unavailable".to_owned()
}

#[cfg(target_os = "linux")]
pub(super) fn read_platform_secret(account: &str) -> Result<Option<String>, String> {
    read_platform_secret_with_limit(account, MAX_SECRET_TEXT_BYTES)
}

#[cfg(target_os = "linux")]
pub(super) fn read_platform_secret_with_limit(
    account: &str,
    max_bytes: usize,
) -> Result<Option<String>, String> {
    let output = match Command::new("/usr/bin/secret-tool")
        .args(["lookup", "service", SERVICE_NAME, "account", account])
        .output()
    {
        Ok(output) => output,
        // A developer or CI image may not have a desktop secret store.  With
        // no enrollment record this is equivalent to an empty store; writes
        // still fail closed below.
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err("native_approval_secure_state_unavailable".to_owned()),
    };
    if !output.status.success() {
        return Ok(None);
    }
    let value = String::from_utf8(output.stdout)
        .map_err(|_| "native_approval_secure_state_invalid".to_owned())?;
    if value.len() > max_bytes {
        return Err("native_approval_secure_state_invalid".to_owned());
    }
    Ok(Some(value.trim().to_owned()))
}

#[cfg(target_os = "linux")]
pub(super) fn write_platform_secret(account: &str, value: &str) -> Result<(), String> {
    write_platform_secret_with_limit(account, value, MAX_SECRET_TEXT_BYTES)
}

#[cfg(target_os = "linux")]
pub(super) fn write_platform_secret_with_limit(
    account: &str,
    value: &str,
    max_bytes: usize,
) -> Result<(), String> {
    if value.len() > max_bytes {
        return Err("native_approval_secure_state_invalid".to_owned());
    }
    let mut child = Command::new("/usr/bin/secret-tool")
        .args([
            "store",
            "--label",
            "HOL Guard native approval enrollment",
            "service",
            SERVICE_NAME,
            "account",
            account,
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| "native_approval_secure_state_unavailable".to_owned())?;
    let stdin = child
        .stdin
        .take()
        .ok_or_else(|| "native_approval_secure_state_unavailable".to_owned())?;
    write_secret_input(stdin, value)?;
    let status = child
        .wait()
        .map_err(|_| "native_approval_secure_state_unavailable".to_owned())?;
    if status.success() {
        Ok(())
    } else {
        Err("native_approval_secure_state_unavailable".to_owned())
    }
}

#[cfg(any(all(test, unix), target_os = "linux"))]
fn write_secret_input(mut stdin: impl Write, value: &str) -> Result<(), String> {
    stdin
        .write_all(value.as_bytes())
        .map_err(|_| "native_approval_secure_state_unavailable".to_owned())
}

#[cfg(all(test, unix))]
mod tests {
    use super::write_secret_input;
    use std::process::{Command, Stdio};

    #[test]
    fn secret_input_is_dropped_before_child_wait() {
        let mut child = Command::new("/bin/cat")
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .spawn()
            .unwrap();
        let stdin = child.stdin.take().unwrap();
        write_secret_input(stdin, "test").unwrap();
        assert!(child.wait().unwrap().success());
    }
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
pub(super) fn read_platform_secret(_account: &str) -> Result<Option<String>, String> {
    read_platform_secret_with_limit(_account, 0)
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
pub(super) fn read_platform_secret_with_limit(
    _account: &str,
    _max_bytes: usize,
) -> Result<Option<String>, String> {
    // No desktop secret store is wired on this platform yet. Treat that as an
    // empty store so reads can fail open to "no enrollment", matching Linux
    // when the helper binary is absent. Writes below still fail closed.
    Ok(None)
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
pub(super) fn write_platform_secret(_account: &str, value: &str) -> Result<(), String> {
    write_platform_secret_with_limit(_account, value, 0)
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
pub(super) fn write_platform_secret_with_limit(
    _account: &str,
    _value: &str,
    _max_bytes: usize,
) -> Result<(), String> {
    Err("native_approval_secure_state_unavailable".to_owned())
}
