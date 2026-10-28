"""Web GUI for triage-agent.

This module delegates implementation to triage_agent.ui.server,
maintaining full backward compatibility.
"""

from triage_agent.ui.server import (
    SERVER_CSRF_TOKEN,
    ThreadedHTTPServer,
    TriageDashboardHandler,
    get_bundled_html,
    load_static_asset,
    load_ui_template,
    main,
    resolve_safe_path,
    run_gui,
)

# Compatibility: provide HTML_PAGE string if accessed directly
def __getattr__(name: str):
    if name == "HTML_PAGE":
        return get_bundled_html()
    raise AttributeError(f"module '{__name__}' has no attribute '{name}'")


if __name__ == "__main__":
    main()
