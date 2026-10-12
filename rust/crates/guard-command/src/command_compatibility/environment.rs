//! Assignment prefixes (`NAME=value cmd`) the compatibility layer can attribute.
//!
//! A prefix only changes the program's environment, so the observed program
//! and arguments still describe the command when the name is inert. Any other
//! name can point the program, its compiler or its loader at other code
//! (`NODE_PATH`, `RUSTFLAGS`, `GOFLAGS`, `CC`, `LD_PRELOAD`, ...). No denylist
//! can name all of those, so only an allowlist of inert names is accepted.

#[cfg(test)]
use crate::CommandSegmentV1;

/// Names that only adjust output, locale or a build mode.
pub(crate) fn inert_environment_name(name: &str) -> bool {
    matches!(
        name,
        "CI" | "NODE_ENV"
            | "FORCE_COLOR"
            | "NO_COLOR"
            | "CLICOLOR"
            | "CLICOLOR_FORCE"
            | "TERM"
            | "TZ"
            | "LANG"
            | "LANGUAGE"
            | "COLUMNS"
            | "LINES"
            | "DEBUG"
            | "NODE_NO_WARNINGS"
            | "RUST_LOG"
            | "RUST_BACKTRACE"
            | "PYTHONUNBUFFERED"
            | "PYTHONDONTWRITEBYTECODE"
    ) || name.starts_with("LC_")
}

#[cfg(test)]
pub(super) fn supported(segment: &CommandSegmentV1) -> bool {
    segment
        .environment_names
        .iter()
        .all(|name| inert_environment_name(name))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn segment(executable: &str, names: &[&str]) -> CommandSegmentV1 {
        let prefix: String = names.iter().map(|name| format!("{name}=1 ")).collect();
        let model = crate::parse_command(
            &serde_json::from_value(
                serde_json::json!({"command": format!("{prefix}{executable} run")}),
            )
            .unwrap(),
        )
        .unwrap();
        model.segments.into_iter().next().unwrap()
    }

    #[test]
    fn inert_names_are_supported_on_every_program() {
        for program in ["git", "gh", "bun", "curl"] {
            assert!(supported(&segment(program, &["CI", "LC_ALL", "NO_COLOR"])));
        }
    }

    #[test]
    fn every_other_name_stays_unsupported() {
        for program in ["bun", "node", "cargo", "go", "make", "git", "curl"] {
            for name in [
                "APP_FLAG",
                "NODE_PATH",
                "NODE_OPTIONS",
                "BUN_OPTIONS",
                "LD_PRELOAD",
                "DYLD_INSERT_LIBRARIES",
                "GIT_SSH_COMMAND",
                "HOME",
                "npm_config_script_shell",
                "XDG_CONFIG_HOME",
                "PYTHONPATH",
                "PYTHONBREAKPOINT",
                "RUSTFLAGS",
                "RUSTDOCFLAGS",
                "GOFLAGS",
                "CC",
                "CXX",
                "MAKEFLAGS",
                "GCONV_PATH",
            ] {
                assert!(!supported(&segment(program, &[name])), "{program}: {name}");
                assert!(
                    !supported(&segment(program, &["CI", name])),
                    "{program}: CI {name}"
                );
            }
        }
    }
}
