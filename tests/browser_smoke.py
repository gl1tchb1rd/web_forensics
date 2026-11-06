"""Run separately against a running app, never part of the offline unittest suite."""
import os
import shutil
from playwright.sync_api import sync_playwright


def main():
    base = os.environ.get("WF_TEST_URL", "http://127.0.0.1:8000")
    executable = os.environ.get("WF_CHROMIUM") or shutil.which("chromium")
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(executable_path=executable, headless=True, args=["--no-sandbox"])
        credentials = None
        if os.environ.get("WF_TEST_AUTH_PASSWORD"):
            credentials = {"username": os.environ.get("WF_TEST_AUTH_USERNAME", "admin"), "password": os.environ["WF_TEST_AUTH_PASSWORD"]}
        page = browser.new_page(viewport={"width": 1440, "height": 1000}, http_credentials=credentials)
        errors = []
        external = []
        page.on("pageerror", lambda error: errors.append(str(error)))
        page.on("request", lambda request: external.append(request.url) if not request.url.startswith(base + "/") else None)
        page.goto(base)
        page.get_by_role("link", name="Header auswerten").click()
        page.locator("#headers-case").fill("TEST-2026/123")
        page.get_by_role("button", name="Fiktives Beispiel einsetzen").click()
        page.get_by_role("button", name="Header lokal auswerten").click()
        page.locator("#view-result").wait_for(state="visible")
        assert "TEST-2026/123" in page.locator("#result-meta").inner_text()
        with page.expect_download() as info:
            page.get_by_role("button", name="PDF herunterladen").click()
        assert info.value.suggested_filename.endswith(".pdf")
        page.locator("#view-home").wait_for(state="visible")
        assert page.locator("#headers-input").input_value() == ""
        assert page.locator("#result-sections").inner_text() == ""
        page.set_viewport_size({"width": 390, "height": 844})
        assert page.evaluate("document.documentElement.scrollWidth <= innerWidth")
        assert not errors, errors
        assert not external, external
        print("Browser checks passed: offline analysis, PDF download, clearing, mobile layout, no external browser requests.")
        browser.close()


if __name__ == "__main__":
    main()
