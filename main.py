import asyncio
import json
import os
from fastapi import FastAPI
from pydantic import BaseModel
import nodriver as uc

app = FastAPI()

_browser = None
_browser_lock = asyncio.Lock()
_solve_lock = asyncio.Lock()
_browser_mode = "headful" if os.environ.get("HEADLESS", "1") != "1" else "headless"

BROWSER_ARGS = [
    "--no-sandbox",
    "--disable-setuid-sandbox",
    "--disable-dev-shm-usage",
    "--disable-gpu",
    "--no-first-run",
    "--window-size=1280,720",
]

CF_WAIT_SECONDS = 30
TOKEN_WAIT_SECONDS = 30
POST_SETTLE_SECONDS = 4
FLOW_TIMEOUT = 120


class URLPayload(BaseModel):
    url: str


class SolvePayload(BaseModel):
    url: str
    sitekey: str = ""
    submit: bool = True


async def get_browser():
    global _browser, _browser_mode
    async with _browser_lock:
        if _browser is None:
            try:
                _browser = await uc.start(
                    headless=_browser_mode == "headless",
                    sandbox=False,
                    browser_args=BROWSER_ARGS,
                )
            except Exception:
                if _browser_mode == "headless":
                    raise
                _browser_mode = "headless"
                _browser = await uc.start(
                    headless=True,
                    sandbox=False,
                    browser_args=BROWSER_ARGS,
                )
    return _browser


async def reset_browser():
    global _browser
    async with _browser_lock:
        if _browser:
            try:
                _browser.stop()
            except Exception:
                pass
            _browser = None


async def wait_cf_pass(tab):
    title = ""
    for _ in range(CF_WAIT_SECONDS):
        await asyncio.sleep(1)
        try:
            title = await tab.evaluate("document.title")
        except Exception:
            continue
        if title and "Just a moment" not in str(title):
            break
    return str(title) if title else ""


async def page_state(tab):
    try:
        raw = await tab.evaluate("""JSON.stringify((() => {
            const inputs = document.querySelectorAll('input[name="g-recaptcha-response"], input[name="cf-turnstile-response"]');
            let val = '';
            for (const el of inputs) { if (el.value && el.value.length > 10) { val = el.value; break; } }
            const hasWidget = !!document.querySelector('.g-recaptcha, .cf-turnstile, #recaptcha-element, iframe[src*="challenges.cloudflare.com"]');
            const hasSubmit = !!document.querySelector('button[type="submit"]');
            return { hasWidget, val, hasSubmit };
        })())""")
        return json.loads(raw) if raw else {"hasWidget": False, "val": "", "hasSubmit": False}
    except Exception:
        return {"hasWidget": False, "val": "", "hasSubmit": False}


async def click_turnstile_checkbox(tab):
    try:
        raw = await tab.evaluate("""JSON.stringify((() => {
            const f = [...document.querySelectorAll('iframe')].find(e => (e.src || '').includes('challenges.cloudflare.com'));
            if (!f) return null;
            const r = f.getBoundingClientRect();
            return { x: r.x + 30, y: r.y + r.height / 2 };
        })())""")
        pos = json.loads(raw) if raw else None
        if pos:
            await tab.mouse.click(pos["x"], pos["y"])
            return True
    except Exception:
        pass
    return False


async def inject_turnstile(tab, sitekey):
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
            }};
            document.body.appendChild(s);
        }})()
    """
    try:
        await tab.evaluate(script)
        return True
    except Exception:
        return False


async def wait_turnstile_token(tab):
    token = ""
    clicked = False
    for _ in range(TOKEN_WAIT_SECONDS):
        await asyncio.sleep(1)
        state = await page_state(tab)
        token = state["val"]
        if token:
            break
        if not clicked:
            clicked = await click_turnstile_checkbox(tab)
        try:
            token = await tab.evaluate("window.__tsToken || ''")
        except Exception:
            token = ""
        if token:
            break
    return token


async def click_submit(tab):
    try:
        return await tab.evaluate("""(() => {
            const b = document.querySelector('button[type="submit"]');
            if (!b) return false;
            b.click();
            return true;
        })()""")
    except Exception:
        return False


def to_netscape(cookie):
    c = cookie if isinstance(cookie, dict) else {}
    domain = c.get("domain", "")
    path = c.get("path", "/")
    secure = "TRUE" if c.get("secure") else "FALSE"
    try:
        expires = int(c.get("expires", 0) or 0)
    except (TypeError, ValueError):
        expires = 0
    name = c.get("name", "")
    value = c.get("value", "")
    prefix = "#HttpOnly_" if c.get("httpOnly") else ""
    return f"{prefix}{domain}\tTRUE\t{path}\t{secure}\t{expires}\t{name}\t{value}"


def cookie_matches(cookie, host):
    domain = (cookie.get("domain") or "").lstrip(".")
    host = (host or "").lower()
    if not domain:
        return True
    return host == domain or host.endswith("." + domain)


async def collect_cookies(browser):
    raw = await browser.cookies.get_all()
    cookies = []
    for c in raw:
        if hasattr(c, "to_json"):
            data = c.to_json()
        elif hasattr(c, "__dict__"):
            data = c.__dict__
        else:
            data = {"raw": str(c)}
        cookies.append(data)
    return cookies


async def solve_flow(payload):
    browser = await get_browser()
    tab = await browser.get(payload.url)
    try:
        title = await wait_cf_pass(tab)
        if "Just a moment" in title or not title:
            raise RuntimeError("Cloudflare challenge tidak selesai dalam 30 detik")

        state = await page_state(tab)
        token = ""
        widget_found = state["hasWidget"]

        if widget_found:
            token = await wait_turnstile_token(tab)
        elif payload.sitekey:
            widget_found = await inject_turnstile(tab, payload.sitekey)
            if widget_found:
                token = await wait_turnstile_token(tab)

        submitted = False
        if payload.submit and widget_found:
            has_submit = (await page_state(tab))["hasSubmit"]
            if has_submit:
                submitted = await click_submit(tab)
                await asyncio.sleep(POST_SETTLE_SECONDS)

        user_agent = ""
        try:
            user_agent = await tab.evaluate("navigator.userAgent")
        except Exception:
            pass

        all_cookies = await collect_cookies(browser)
        try:
            host = tab.url or payload.url
            from urllib.parse import urlparse
            host = urlparse(host).netloc.split(":")[0]
        except Exception:
            host = ""
        cookies = [c for c in all_cookies if cookie_matches(c, host)] or all_cookies
        netscape = ["# Netscape HTTP Cookie File"]
        netscape.extend(to_netscape(c) for c in cookies if c.get("domain") and c.get("name"))
        netscape = "\n".join(netscape)

        final_url = ""
        try:
            final_url = tab.url or ""
        except Exception:
            pass

        return {
            "success": True,
            "title": title,
            "token": token,
            "sitekey_used": payload.sitekey,
            "widget_found": widget_found,
            "submitted": submitted,
            "browser_mode": _browser_mode,
            "user_agent": user_agent,
            "cookies_count": len(cookies),
            "cookies": cookies,
            "netscape": netscape,
            "final_url": final_url,
        }
    finally:
        try:
            await tab.close()
        except Exception:
            pass


@app.get("/")
async def health():
    return {"status": "ok"}


@app.get("/api/diag")
async def diag():
    import shutil
    import socket
    import subprocess
    import tempfile

    exe = (
        shutil.which("google-chrome-stable")
        or shutil.which("google-chrome")
        or shutil.which("chromium")
        or shutil.which("chromium-browser")
        or ""
    )
    result = {"exe": exe or None}
    if not exe:
        return result

    try:
        r = subprocess.run([exe, "--version"], capture_output=True, text=True, timeout=20)
        result["version"] = r.stdout.strip() or r.stderr.strip()[:500]
    except Exception as e:
        result["version_error"] = str(e)[:500]

    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]

    with tempfile.TemporaryDirectory() as profile:
        args = [
            exe,
            "--remote-allow-origins=*",
            "--no-first-run",
            "--no-service-autorun",
            "--no-default-browser-check",
            "--homepage=about:blank",
            "--no-pings",
            "--password-store=basic",
            "--disable-infobars",
            "--disable-breakpad",
            "--disable-dev-shm-usage",
            "--disable-session-crashed-bubble",
            "--disable-search-engine-choice-screen",
            "--user-data-dir=%s" % profile,
            "--headless=new",
            "--no-sandbox",
            "--remote-debugging-port=%s" % port,
            *BROWSER_ARGS,
            "about:blank",
        ]
        try:
            r = subprocess.run(args, capture_output=True, text=True, timeout=20)
            result["nodriver_like_rc"] = r.returncode
            result["nodriver_like_stdout"] = (r.stdout or "")[:200]
            result["nodriver_like_stderr"] = (r.stderr or "")[:1500]
        except subprocess.TimeoutExpired as e:
            result["nodriver_like_timeout"] = True
            result["nodriver_like_stderr"] = ((e.stderr or b"").decode("utf-8", "replace") if isinstance(e.stderr, bytes) else (e.stderr or ""))[:1500]
        except Exception as e:
            result["nodriver_like_error"] = str(e)[:500]

    try:
        browser = await asyncio.wait_for(
            uc.start(headless=True, sandbox=False, browser_args=BROWSER_ARGS), timeout=45
        )
        result["uc_start"] = "ok"
        try:
            await browser.stop()
        except Exception:
            pass
    except Exception as e:
        result["uc_start"] = "failed"
        result["uc_start_error"] = str(e)[:1000]

    import subprocess as sp

    async def try_mode(label, headless):
        try:
            b = await asyncio.wait_for(
                uc.start(headless=headless, sandbox=False, browser_args=BROWSER_ARGS), timeout=45
            )
            result[label] = "ok"
            try:
                await b.stop()
            except Exception:
                pass
        except Exception as e:
            result[label] = "failed"
            result[label + "_error"] = str(e)[:400]

    await try_mode("chain_headful", False)
    await try_mode("chain_headless", True)
    await try_mode("chain_headless2", True)

    try:
        sp.run(["pkill", "-9", "-f", "chrome"], capture_output=True, timeout=10)
    except Exception:
        pass
    return result


@app.post("/api/resolve")
async def resolve_url(payload: URLPayload):
    async with _solve_lock:
        try:
            return await asyncio.wait_for(solve_flow(SolvePayload(url=payload.url, submit=False)), timeout=FLOW_TIMEOUT)
        except asyncio.TimeoutError:
            await reset_browser()
            return {"success": False, "error": "Timeout"}
        except Exception as e:
            await reset_browser()
            return {"success": False, "error": str(e)}


@app.post("/api/solve")
async def solve_url(payload: SolvePayload):
    async with _solve_lock:
        try:
            return await asyncio.wait_for(solve_flow(payload), timeout=FLOW_TIMEOUT)
        except asyncio.TimeoutError:
            await reset_browser()
            return {"success": False, "error": "Timeout"}
        except Exception as e:
            await reset_browser()
            return {"success": False, "error": str(e)}
