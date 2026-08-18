import asyncio
import gc
import json
import os
import shutil
import subprocess
import tempfile
import traceback
from fastapi import FastAPI
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from DrissionPage import ChromiumPage, ChromiumOptions

app = FastAPI()
_solve_lock = asyncio.Lock()

CF_WAIT_SECONDS = 45
TOKEN_WAIT_SECONDS = 25
POST_SETTLE_SECONDS = 3
FLOW_TIMEOUT = 100


class SolvePayload(BaseModel):
    url: str
    sitekey: str = ""
    submit: bool = True


def find_chrome_path():
    return (
        shutil.which("google-chrome-stable")
        or shutil.which("google-chrome")
        or shutil.which("chromium")
        or shutil.which("chromium-browser")
        or "/usr/bin/google-chrome-stable"
    )


def build_options(user_data_dir):
    co = ChromiumOptions()
    co.headless(False)
    co.set_browser_path(find_chrome_path())
    co.set_user_data_path(user_data_dir)
    co.set_argument("--no-sandbox")
    co.set_argument("--disable-setuid-sandbox")
    co.set_argument("--disable-dev-shm-usage")
    co.set_argument("--disable-gpu")
    co.set_argument("--no-first-run")
    co.set_argument("--no-default-browser-check")
    co.set_argument("--disable-extensions")
    co.set_argument("--mute-audio")
    co.set_argument("--no-zygote")
    co.set_argument("--renderer-process-limit=1")
    co.set_argument("--disable-site-isolation-trials")
    co.set_argument("--js-flags=--max-old-space-size=128")
    co.set_argument("--window-size=1280,720")
    co.set_argument("--lang=en-US,en")
    co.set_user_agent("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
    return co


def page_state(page):
    try:
        return json.loads(page.run_js("""JSON.stringify((() => {
            const inputs = document.querySelectorAll('input[name="g-recaptcha-response"], input[name="cf-turnstile-response"]');
            let val = '';
            for (const el of inputs) { if (el.value && el.value.length > 10) { val = el.value; break; } }
            const hasWidget = !!document.querySelector('.g-recaptcha, .cf-turnstile, #recaptcha-element, iframe[src*="challenges.cloudflare.com"]');
            const hasSubmit = !!document.querySelector('button[type="submit"]');
            return { hasWidget, val, hasSubmit };
        })())"""))
    except Exception:
        return {"hasWidget": False, "val": "", "hasSubmit": False}


def chrome_probe(exe_path):
    """Run chrome headful 20s, capture stderr, return evidence string."""
    evidence = ""
    try:
        p = subprocess.Popen(
            [exe_path, "--no-sandbox", "--disable-gpu", "--disable-dev-shm-usage",
             "--enable-logging=stderr", "--v=1", "about:blank"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            env={**os.environ, "DISPLAY": os.environ.get("DISPLAY", ":99")},
        )
        try:
            rc = p.wait(timeout=20)
            evidence = f"probe_exit={rc}"
        except subprocess.TimeoutExpired:
            p.kill()
            evidence = "probe_ALIVE_20s"
        out, err = p.communicate(timeout=10)
        lines = [l for l in (err or "").splitlines()
                 if any(k in l for k in ("FATAL", "ERROR", "GL", "GPU", "X11", "Xlib", "sandbox", "fontconfig", "dbus", "zygote", "shm", "memfd"))]
        evidence += f" lines={len(lines)}"
        evidence += " || " + " ;; ".join(lines[-12:])
    except Exception as e:
        evidence = f"probe_exc={str(e)[:200]}"
    try:
        r = subprocess.run(["ps", "aux"], capture_output=True, text=True, timeout=5)
        chrome_lines = [l for l in r.stdout.splitlines() if "chrome" in l]
        evidence += f" || chrome_procs={len(chrome_lines)}"
        for l in chrome_lines[-3:]:
            parts = l.split()
            evidence += f" [{parts[1]} {parts[10] if len(parts) > 10 else '?'}]"
    except Exception:
        pass
    try:
        r = subprocess.run(["ls", "-la", "/tmp/.X11-unix"], capture_output=True, text=True, timeout=5)
        evidence += f" || X11={(r.stdout or '')[-120:]}"
    except Exception:
        pass
    return evidence


def click_turnstile_checkbox(page):
    try:
        frame = page.get_frame("tag:iframe@src^https://challenges.cloudflare.com")
        if frame:
            btn = frame.ele("tag:input@type=checkbox", timeout=2) or frame.ele("tag:body", timeout=2)
            if btn:
                btn.click()
                return True
    except Exception:
        pass
    return False


def wait_cf_pass(page):
    title = ""
    clicked = False
    for i in range(CF_WAIT_SECONDS):
        time_sleep(1)
        try:
            title = page.title
        except Exception:
            continue
        if title and "Just a moment" not in str(title):
            break
        if not clicked and i % 3 == 0:
            clicked = click_turnstile_checkbox(page)
    return str(title) if title else ""


def inject_turnstile(page, sitekey):
    script = f"""
        (() => {{
            if (window.__tsToken !== undefined) return;
            window.__tsToken = '';
            const el = document.createElement('div');
            document.body.appendChild(el);
            const s = document.createElement('script');
            s.src = 'https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit';
            s.onload = () => {{
                turnstile.render(el, {{
                    sitekey: {json.dumps(sitekey)},
                    callback: (t) => {{ window.__tsToken = t; }}
                }});
                setTimeout(() => {{
                    if (!window.__tsToken) {{
                        try {{
                            turnstile.render(el, {{
                                sitekey: {json.dumps(sitekey)},
                                appearance: 'execute',
                                callback: (t) => {{ window.__tsToken = t; }}
                            }});
                        }} catch (e) {{ window.__tsToken = 'ERR:' + String(e); }}
                    }}
                }}, 4000);
            }};
            document.body.appendChild(s);
        }})()
    """
    try:
        page.run_js(script)
        return True
    except Exception:
        return False


def wait_turnstile_token(page):
    clicked = False
    for _ in range(TOKEN_WAIT_SECONDS):
        time_sleep(1)
        state = page_state(page)
        if state["val"]:
            return state["val"]
        if not clicked:
            clicked = click_turnstile_checkbox(page)
        try:
            token = page.run_js("window.__tsToken || ''")
            if token and not str(token).startswith("ERR:"):
                return str(token)
            if token:
                return ""
        except Exception:
            pass
    return ""


def click_submit(page):
    try:
        btn = page.ele("tag:button@type=submit", timeout=3)
        if not btn:
            return False
        btn.click()
        return True
    except Exception:
        return False


def collect_cookies(page):
    raw = page.cookies(as_dict=False)
    cookies = []
    header_parts = []
    netscape = ["# Netscape HTTP Cookie File"]
    for c in raw:
        name = str(c.get("name", "") or "")
        value = str(c.get("value", "") or "")
        if not name or value is None:
            continue
        domain = str(c.get("domain", "") or "")
        path = str(c.get("path", "/") or "/")
        expires = c.get("expires", 0) or 0
        try:
            expires = int(expires)
        except Exception:
            expires = 0
        http_only = bool(c.get("httpOnly", False))
        secure = bool(c.get("secure", False))
        cookies.append({
            "name": name, "value": value, "domain": domain, "path": path,
            "expires": expires, "httpOnly": http_only, "secure": secure,
        })
        header_parts.append(f"{name}={value}")
        prefix = "#HttpOnly_" if http_only else ""
        sec_flag = "TRUE" if secure else "FALSE"
        netscape.append(f"{prefix}{domain}\tTRUE\t{path}\t{sec_flag}\t{expires}\t{name}\t{value}")
    return cookies, "; ".join(header_parts), "\n".join(netscape)


def time_sleep(sec):
    import time
    time.sleep(sec)


def execute_solve(payload: SolvePayload):
    page = None
    user_data_dir = tempfile.mkdtemp(prefix="dp-")
    try:
        co = build_options(user_data_dir)
        try:
            page = ChromiumPage(co)
        except Exception as e:
            raise RuntimeError(f"chromium_start={str(e)[:150]} || {chrome_probe(find_chrome_path())}")

        page.get(payload.url)
        title = wait_cf_pass(page)
        if "Just a moment" in title or not title:
            raise RuntimeError("Gagal melewati halaman verifikasi awal Cloudflare (Just a moment...)")

        state = page_state(page)
        token = ""
        widget_found = state["hasWidget"]

        if widget_found:
            token = wait_turnstile_token(page)
        elif payload.sitekey:
            widget_found = inject_turnstile(page, payload.sitekey)
            if widget_found:
                token = wait_turnstile_token(page)

        submitted = False
        if payload.submit and widget_found:
            if page_state(page)["hasSubmit"]:
                submitted = click_submit(page)
                time_sleep(POST_SETTLE_SECONDS)

        user_agent = page.user_agent
        cookies, cookie_header, netscape = collect_cookies(page)
        final_url = page.url or ""

        return {
            "success": True,
            "title": str(title),
            "token": str(token),
            "sitekey_used": str(payload.sitekey),
            "widget_found": bool(widget_found),
            "submitted": bool(submitted),
            "user_agent": str(user_agent),
            "cookie_header": cookie_header,
            "cookies_count": len(cookies),
            "cookies": cookies,
            "netscape": netscape,
            "final_url": str(final_url),
        }
    finally:
        if page:
            try:
                page.quit()
            except Exception:
                pass
        try:
            shutil.rmtree(user_data_dir, ignore_errors=True)
        except Exception:
            pass
        gc.collect()


@app.get("/")
async def health():
    return {"status": "ok", "v": 2}


@app.post("/api/solve")
async def solve_url(payload: SolvePayload):
    async with _solve_lock:
        try:
            result = await asyncio.wait_for(
                asyncio.to_thread(execute_solve, payload), timeout=FLOW_TIMEOUT
            )
            return JSONResponse(status_code=200, content=result)
        except asyncio.TimeoutError:
            gc.collect()
            return JSONResponse(status_code=200, content={"success": False, "error": "Operation timed out"})
        except Exception as e:
            traceback.print_exc()
            gc.collect()
            return JSONResponse(status_code=200, content={"success": False, "error": str(e)})
