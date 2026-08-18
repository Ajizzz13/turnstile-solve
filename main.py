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

HEADLESS = os.environ.get("HEADLESS", "1") == "1"

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
    global _browser
    async with _browser_lock:
        if _browser is None:
            _browser = await uc.start(
                headless=HEADLESS,
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
            return { x: r.x + r.width / 2, y: r.y + r.height / 2 };
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
    for i in range(TOKEN_WAIT_SECONDS):
        await asyncio.sleep(1)
        state = await page_state(tab)
        token = state["val"]
        if token:
            break
        if i % 2 == 0:
            await click_turnstile_checkbox(tab)
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


async def collect_cookies(browser):
    raw = await browser.cookies.get_all()
    cookies = []
    for c in raw:
        if hasattr(c, "to_json"):
            cookies.append(c.to_json())
        elif hasattr(c, "__dict__"):
            cookies.append(c.__dict__)
        else:
            cookies.append({"raw": str(c)})
    netscape = ["# Netscape HTTP Cookie File"]
    netscape.extend(to_netscape(c) for c in cookies if c.get("domain") and c.get("name"))
    return cookies, "\n".join(netscape)


async def solve_flow(payload):
    browser = await get_browser()
    tab = await browser.get(payload.url)

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

    cookies, netscape = await collect_cookies(browser)

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
        "cookies_count": len(cookies),
        "cookies": cookies,
        "netscape": netscape,
        "final_url": final_url,
    }


@app.get("/")
async def health():
    return {"status": "ok"}


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