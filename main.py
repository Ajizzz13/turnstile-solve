import asyncio
import base64
import gc
import json
import os
import shutil
import subprocess
import traceback
from fastapi import FastAPI
from fastapi.responses import JSONResponse
from pydantic import BaseModel
import nodriver as uc
from nodriver import cdp

app = FastAPI()
_solve_lock = asyncio.Lock()

HEADLESS = os.environ.get("HEADLESS", "0") == "1"

BROWSER_ARGS = [
    "--no-sandbox",
    "--disable-setuid-sandbox",
    "--disable-dev-shm-usage",
    "--disable-gpu",
    "--no-first-run",
    "--no-default-browser-check",
    "--disable-extensions",
    "--mute-audio",
    "--no-zygote",
    "--renderer-process-limit=1",
    "--disable-site-isolation-trials",
    "--js-flags=--max-old-space-size=128",
    "--window-size=1280,720",
    "--lang=en-US,en",
    "--user-agent=Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/151.0.0.0 Safari/537.36",
]

CF_WAIT_SECONDS = 45
TOKEN_WAIT_SECONDS = 35
POST_SETTLE_SECONDS = 3
FLOW_TIMEOUT = 110


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


async def get_page_state(tab):
    try:
        raw = await tab.evaluate("""JSON.stringify((() => {
            const inputs = document.querySelectorAll('input[name="g-recaptcha-response"], input[name="cf-turnstile-response"]');
            let val = '';
            for (const el of inputs) { if (el.value && el.value.length > 10) { val = el.value; break; } }
            const hasWidget = !!document.querySelector('.g-recaptcha, .cf-turnstile, #recaptcha-element, iframe[src*="challenges.cloudflare.com"]');
            const hasIframe = !!document.querySelector('iframe[src*="challenges.cloudflare.com"]');
            const hasSubmit = !!document.querySelector('button[type="submit"]');
            return { hasWidget, hasIframe, hasSubmit, val };
        })())""")
        return json.loads(raw) if raw else {"hasWidget": False, "hasIframe": False, "hasSubmit": False, "val": ""}
    except Exception:
        return {"hasWidget": False, "hasIframe": False, "hasSubmit": False, "val": ""}


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


async def wait_cf_pass(tab):
    title = ""
    clicked = False
    for i in range(CF_WAIT_SECONDS):
        await asyncio.sleep(1)
        try:
            title = await tab.evaluate("document.title")
        except Exception:
            continue
        if title and "Just a moment" not in str(title):
            break
        if not clicked and i % 3 == 0:
            clicked = await click_turnstile_checkbox(tab)
    return str(title) if title else ""


async def inject_turnstile(tab, sitekey):
    script = f"""
        (() => {{
            if (window.__tsToken !== undefined) return;
            window.__tsToken = '';
            window.__tsError = '';
            const setToken = (t) => {{
                window.__tsToken = t;
                let inp = document.querySelector('input[name="g-recaptcha-response"]');
                if (!inp) {{
                    inp = document.createElement('input');
                    inp.type = 'hidden';
                    inp.name = 'g-recaptcha-response';
                    document.querySelector('form')?.appendChild(inp) || document.body.appendChild(inp);
                }}
                inp.value = t;
            }};
            const el = document.querySelector('#recaptcha-element, .g-recaptcha') || (() => {{
                const d = document.createElement('div');
                d.id = 'recaptcha-element';
                document.body.appendChild(d);
                return d;
            }})();
            const s = document.createElement('script');
            s.src = 'https://challenges.cloudflare.com/turnstile/v0/api.js?compat=recaptcha2&render=explicit';
            s.onload = () => {{
                try {{
                    turnstile.render(el, {{
                        sitekey: {json.dumps(sitekey)},
                        callback: setToken,
                        'error-callback': () => {{ window.__tsError = 'error-callback'; }}
                    }});
                    setTimeout(() => {{
                        if (!window.__tsToken) {{
                            try {{
                                turnstile.render(el, {{
                                    sitekey: {json.dumps(sitekey)},
                                    appearance: 'execute',
                                    callback: setToken,
                                    'error-callback': () => {{ window.__tsError = 'execute-error'; }}
                                }});
                            }} catch (e) {{ window.__tsError = 'execute-exc: ' + String(e); }}
                        }}
                    }}, 4000);
                }} catch (e) {{
                    window.__tsError = String(e);
                }}
            }};
            document.body.appendChild(s);
        }})()
    """
    try:
        await tab.evaluate(script)
        return True
    except Exception:
        return False


async def wait_turnstile_token(tab, max_seconds=TOKEN_WAIT_SECONDS):
    clicked = False
    last_iframe = False
    for i in range(max_seconds):
        await asyncio.sleep(1)
        state = await get_page_state(tab)
        if state["val"]:
            return state["val"]
        if state["hasIframe"]:
            last_iframe = True
            if not clicked or i % 2 == 0:
                clicked = await click_turnstile_checkbox(tab) or clicked
        elif not clicked and i % 3 == 0:
            clicked = await click_turnstile_checkbox(tab)
        try:
            token = await tab.evaluate("window.__tsToken || ''")
            if token:
                return token
        except Exception:
            pass
    return ""


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


def sanitize_cookie(c):
    name = str(getattr(c, "name", "") or (c.get("name", "") if isinstance(c, dict) else ""))
    value = str(getattr(c, "value", "") or (c.get("value", "") if isinstance(c, dict) else ""))
    domain = str(getattr(c, "domain", "") or (c.get("domain", "") if isinstance(c, dict) else ""))
    path = str(getattr(c, "path", "/") or (c.get("path", "/") if isinstance(c, dict) else "/"))
    expires = getattr(c, "expires", 0) or (c.get("expires", 0) if isinstance(c, dict) else 0)
    try:
        expires = int(expires)
    except Exception:
        expires = 0
    http_only = bool(getattr(c, "http_only", False) or (c.get("httpOnly", False) if isinstance(c, dict) else False))
    secure = bool(getattr(c, "secure", False) or (c.get("secure", False) if isinstance(c, dict) else False))
    return {
        "name": name,
        "value": value,
        "domain": domain,
        "path": path,
        "expires": expires,
        "httpOnly": http_only,
        "secure": secure,
    }


async def collect_cookies(browser):
    raw = await browser.cookies.get_all()
    cookies = []
    header_parts = []
    netscape = ["# Netscape HTTP Cookie File"]
    for item in raw:
        c = sanitize_cookie(item)
        if c["name"] and c["value"] is not None:
            cookies.append(c)
            header_parts.append(f"{c['name']}={c['value']}")
            prefix = "#HttpOnly_" if c["httpOnly"] else ""
            sec_flag = "TRUE" if c["secure"] else "FALSE"
            netscape.append(f"{prefix}{c['domain']}\tTRUE\t{c['path']}\t{sec_flag}\t{c['expires']}\t{c['name']}\t{c['value']}")
    return cookies, "; ".join(header_parts), "\n".join(netscape)


def chrome_probe(exe_path):
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
    except Exception:
        pass
    try:
        r = subprocess.run(["ls", "-la", "/tmp/.X11-unix"], capture_output=True, text=True, timeout=5)
        evidence += f" || X11={(r.stdout or '')[-120:]}"
    except Exception:
        pass
    return evidence


async def execute_solve(payload: SolvePayload):
    browser = None
    try:
        exe_path = find_chrome_path()
        try:
            for attempt in range(3):
                try:
                    browser = await uc.start(
                        headless=HEADLESS,
                        no_sandbox=True,
                        browser_executable_path=exe_path,
                        browser_args=BROWSER_ARGS,
                    )
                    break
                except Exception:
                    if attempt < 2:
                        await asyncio.sleep(2)
                    else:
                        raise
        except Exception as e:
            raise RuntimeError(f"{str(e)[:80]} || {chrome_probe(exe_path)}")

        tab = await browser.get(payload.url)

        title = await wait_cf_pass(tab)
        if "Just a moment" in title or not title:
            raise RuntimeError("Gagal melewati halaman verifikasi awal Cloudflare (Just a moment...)")

        state = await get_page_state(tab)
        token = ""
        widget_found = state["hasWidget"]
        injected = False

        if widget_found:
            token = await wait_turnstile_token(tab, max_seconds=5)
        if not token and payload.sitekey:
            injected = await inject_turnstile(tab, payload.sitekey)
            if injected:
                token = await wait_turnstile_token(tab)

        submitted = False
        if payload.submit and (widget_found or injected):
            if (await get_page_state(tab))["hasSubmit"]:
                submitted = await click_submit(tab)
                await asyncio.sleep(POST_SETTLE_SECONDS)

        user_agent = await tab.evaluate("navigator.userAgent")
        cookies, cookie_header, netscape = await collect_cookies(browser)
        ts_error = ""
        try:
            ts_error = str(await tab.evaluate("window.__tsError || ''"))
        except Exception:
            pass
        ts_info = ""
        try:
            ts_info = str(await tab.evaluate("""JSON.stringify({
                hasTsApi: typeof turnstile !== 'undefined',
                iframeCount: [...document.querySelectorAll('iframe')].filter(f => (f.src||'').includes('challenges.cloudflare.com')).length,
                widgetHtml: (document.querySelector('.g-recaptcha,#recaptcha-element')?.innerHTML || '').slice(0, 300),
                widgetRect: (() => { const el = document.querySelector('.g-recaptcha,#recaptcha-element'); if (!el) return null; const r = el.getBoundingClientRect(); return {w: r.width, h: r.height, x: r.x, y: r.y, display: getComputedStyle(el).display}; })()
            })"""))
        except Exception:
            pass
        screenshot = ""
        try:
            shot = await tab.save_screenshot()
            if shot:
                screenshot = base64.b64encode(shot).decode()[:300000]
        except Exception:
            pass
        final_url = ""
        try:
            final_url = str(tab.url or "")
        except Exception:
            pass

        return {
            "success": True,
            "title": str(title),
            "token": str(token),
            "sitekey_used": str(payload.sitekey),
            "widget_found": bool(widget_found),
            "injected": bool(injected),
            "iframe_final": (await get_page_state(tab))["hasIframe"],
            "submitted": bool(submitted),
            "user_agent": str(user_agent),
            "cookie_header": cookie_header,
            "cookies_count": len(cookies),
            "cookies": cookies,
            "netscape": netscape,
            "final_url": final_url,
            "ts_error": ts_error,
            "ts_info": ts_info,
            "screenshot_b64": screenshot,
        }
    finally:
        if browser:
            try:
                browser.stop()
            except Exception:
                pass
        gc.collect()


@app.get("/")
async def health():
    return {"status": "ok", "v": 3}


@app.post("/api/solve")
async def solve_url(payload: SolvePayload):
    async with _solve_lock:
        try:
            result = await asyncio.wait_for(execute_solve(payload), timeout=FLOW_TIMEOUT)
            return JSONResponse(status_code=200, content=result)
        except asyncio.TimeoutError:
            gc.collect()
            return JSONResponse(status_code=200, content={"success": False, "error": "Operation timed out"})
        except Exception as e:
            traceback.print_exc()
            gc.collect()
            return JSONResponse(status_code=200, content={"success": False, "error": str(e)})
