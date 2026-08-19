import asyncio
import base64
import gc
import json
import traceback
from fastapi import FastAPI
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from patchright.sync_api import sync_playwright

app = FastAPI()
_solve_lock = asyncio.Lock()

CF_WAIT_SECONDS = 45
TOKEN_WAIT_SECONDS = 35
POST_SETTLE_SECONDS = 3
FLOW_TIMEOUT = 120

USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"

BROWSER_ARGS = [
    "--no-sandbox",
    "--disable-setuid-sandbox",
    "--disable-dev-shm-usage",
    "--disable-gpu",
    "--no-first-run",
    "--no-default-browser-check",
    "--disable-extensions",
    "--mute-audio",
    "--disable-blink-features=AutomationControlled",
    "--disable-background-networking",
    "--disable-background-timer-throttling",
    "--disable-backgrounding-occluded-windows",
    "--disable-renderer-backgrounding",
    "--window-position=2000,2000",
]


class SolvePayload(BaseModel):
    url: str
    sitekey: str = ""
    submit: bool = True


def page_state(page):
    try:
        return json.loads(page.evaluate("""JSON.stringify((() => {
            const inputs = document.querySelectorAll('input[name="g-recaptcha-response"], input[name="cf-turnstile-response"]');
            let val = '';
            for (const el of inputs) { if (el.value && el.value.length > 10) { val = el.value; break; } }
            const hasWidget = !!document.querySelector('.g-recaptcha, .cf-turnstile, #recaptcha-element, iframe[src*="challenges.cloudflare.com"]');
            const hasIframe = !!document.querySelector('iframe[src*="challenges.cloudflare.com"]');
            const hasSubmit = !!document.querySelector('button[type="submit"]');
            return { hasWidget, hasIframe, hasSubmit, val };
        })())"""))
    except Exception:
        return {"hasWidget": False, "hasIframe": False, "hasSubmit": False, "val": ""}


def click_turnstile_checkbox(page):
    try:
        pos = json.loads(page.evaluate("""JSON.stringify((() => {
            const w = document.querySelector('.g-recaptcha,#recaptcha-element');
            const f = [...document.querySelectorAll('iframe')].find(e => (e.src || '').includes('challenges.cloudflare.com'));
            if (f) {
                const r = f.getBoundingClientRect();
                return { x: r.x + 30, y: r.y + r.height / 2 };
            }
            if (w) {
                const r = w.getBoundingClientRect();
                return { x: r.x + 30, y: r.y + r.height / 2 };
            }
            return null;
        })())"""))
        if pos:
            page.mouse.click(pos["x"], pos["y"])
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
            title = page.title()
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
                }} catch (e) {{
                    window.__tsError = String(e);
                }}
            }};
            document.body.appendChild(s);
        }})()
    """
    try:
        page.evaluate(script)
        return True
    except Exception:
        return False


def wait_turnstile_token(page):
    clicked = False
    exec_called = False
    for i in range(TOKEN_WAIT_SECONDS):
        time_sleep(1)
        state = page_state(page)
        if state["val"]:
            return state["val"]
        if state["hasIframe"]:
            if not clicked or i % 2 == 0:
                clicked = click_turnstile_checkbox(page) or clicked
        elif not clicked and i % 3 == 0:
            clicked = click_turnstile_checkbox(page)
        if not exec_called and i >= 5:
            try:
                page.evaluate("""(() => {
                    const inp = document.querySelector('input[name="cf-turnstile-response"], input[name="g-recaptcha-response"]');
                    const id = inp?.id ? inp.id.replace('_response', '') : null;
                    if (id && typeof turnstile !== 'undefined') {
                        try { turnstile.execute(id); } catch (e) { window.__tsError = 'exec: ' + String(e); }
                    }
                    return id;
                })()""")
                exec_called = True
            except Exception:
                pass
        try:
            token = page.evaluate("window.__tsToken || ''")
            if token:
                return token
        except Exception:
            pass
    return ""


def click_submit(page):
    try:
        return page.evaluate("""(() => {
            const b = document.querySelector('button[type="submit"]');
            if (!b) return false;
            b.click();
            return true;
        })()""")
    except Exception:
        return False


def collect_cookies(context):
    raw = context.cookies()
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
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True, args=BROWSER_ARGS)
            context = browser.new_context(user_agent=USER_AGENT, locale="en-US")
            page = context.new_page()
            page.goto(payload.url, wait_until="domcontentloaded", timeout=60000)

            title = wait_cf_pass(page)
            if "Just a moment" in title or not title:
                raise RuntimeError("Gagal melewati halaman verifikasi awal Cloudflare (Just a moment...)")

            state = page_state(page)
            token = ""
            widget_found = state["hasWidget"]
            injected = False

            sitekey = payload.sitekey
            if not sitekey:
                try:
                    sitekey = str(page.evaluate("document.querySelector('.g-recaptcha,#recaptcha-element')?.getAttribute('data-sitekey') || ''"))
                except Exception:
                    sitekey = ""

            if widget_found:
                token = wait_turnstile_token_short(page)
            if not token and sitekey:
                injected = inject_turnstile(page, sitekey)
                if injected:
                    token = wait_turnstile_token(page)

            submitted = False
            if payload.submit and (widget_found or injected):
                if page_state(page)["hasSubmit"]:
                    submitted = click_submit(page)
                    time_sleep(POST_SETTLE_SECONDS)

            user_agent = page.evaluate("navigator.userAgent")
            cookies, cookie_header, netscape = collect_cookies(context)
            ts_error = ""
            try:
                ts_error = str(page.evaluate("window.__tsError || ''"))
            except Exception:
                pass
            ts_info = ""
            try:
                ts_info = str(page.evaluate("""JSON.stringify({
                    hasTsApi: typeof turnstile !== 'undefined',
                    iframeCount: [...document.querySelectorAll('iframe')].filter(f => (f.src||'').includes('challenges.cloudflare.com')).length,
                    widgetHtml: (document.querySelector('.g-recaptcha,#recaptcha-element')?.innerHTML || '').slice(0, 300)
                })"""))
            except Exception:
                pass
            screenshot = ""
            try:
                shot = page.screenshot()
                if shot:
                    screenshot = base64.b64encode(shot).decode()[:300000]
            except Exception:
                pass

            return {
                "success": True,
                "title": str(title),
                "token": str(token),
                "sitekey_used": str(sitekey),
                "widget_found": bool(widget_found),
                "injected": bool(injected),
                "submitted": bool(submitted),
                "user_agent": str(user_agent),
                "cookie_header": cookie_header,
                "cookies_count": len(cookies),
                "cookies": cookies,
                "netscape": netscape,
                "ts_error": ts_error,
                "ts_info": ts_info,
                "screenshot_b64": screenshot,
            }
    finally:
        gc.collect()


def wait_turnstile_token_short(page):
    for _ in range(5):
        time_sleep(1)
        state = page_state(page)
        if state["val"]:
            return state["val"]
        try:
            token = page.evaluate("window.__tsToken || ''")
            if token:
                return token
        except Exception:
            pass
    return ""


@app.get("/")
async def health():
    return {"status": "ok", "v": 5}


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