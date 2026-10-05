"""Owner context for the isolated Grok client without package imports."""

GROK_HOOK_INVOCATION_TEMPLATE = """
_GROK_HOME = None
_GROK_WORKSPACE = None


def _configure_grok_invocation():
    global _GROK_HOME, _GROK_WORKSPACE
    if len(sys.argv) == 1:
        return True
    if len(sys.argv) != 2 or len(sys.argv[1]) > 64 * 1024:
        return False
    config = _json_object(sys.argv[1])
    if config is None or config.get("harness") != HARNESS or config.get("guard_home") != GUARD_HOME:
        return False
    args = config.get("cli_args")
    if not isinstance(args, list) or not all(isinstance(value, str) for value in args):
        return False
    if args[:2] != ["guard", "hook"] or args[-1:] != ["--json"]:
        return False
    options = args[2:-1]
    if len(options) % 2 or len(set(options[::2])) != len(options[::2]):
        return False
    options = dict(zip(options[::2], options[1::2]))
    if options.get("--harness") != HARNESS or not options.get("--guard-home"):
        return False
    if not set(options) <= {"--harness", "--guard-home", "--home", "--workspace"}:
        return False
    if any(not Path(value).is_absolute() for key, value in options.items() if key != "--harness"):
        return False
    try:
        guard_home = Path(options["--guard-home"]).resolve()
    except (OSError, RuntimeError, ValueError):
        return False
    if guard_home != Path(GUARD_HOME):
        return False
    _GROK_HOME = options.get("--home", str(Path.home()))
    _GROK_WORKSPACE = options.get("--workspace")
    return True


def _grok_invocation_payload(input_text):
    payload = _json_object(input_text)
    if payload is not None and payload.get("cwd") is None and _GROK_WORKSPACE is not None:
        payload["cwd"] = _GROK_WORKSPACE
        return json.dumps(payload, ensure_ascii=True, separators=(",", ":"))
    return input_text
"""
