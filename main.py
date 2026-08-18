import asyncio
import json
import shutil
import subprocess
import traceback
from fastapi import FastAPI
from fastapi.responses import JSONResponse
from pydantic import BaseModel
import nodriver as uc

app = FastAPI()

_browser = None
_browser_lock = asyncio.Lock()
_solve_lock = asyncio.Lock()

BROWSER_ARGS = [
    "--no-sandbox",
    "--disable-setuid-sandbox",
    "--disable-dev-shm-usage",
    "--disable-gpu",
    "--no-first-run",
    "--no-default-browser-check",
    "--disable-extensions",
    "--window-size=1280,720",
    "--lang=en-US,en",
    "--user-agent=Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/151.0.0.0 Safari/537.36",
]

CF_WAIT_SECONDS = 60
TOKEN_WAIT_SECONDS = 25
POST_SETTLE_SECONDS = 3
FLOW_TIMEOUT = 75


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


async def get_browser():
    global _browser
    async with _browser_lock:
        if _browser is None:
            exe_path = find_chrome_path()
            _browser = await uc.start(
                headless=True,
                no_sandbox=True,
                browser_executable_path=exe_path,
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


async def get_page_state(tab):
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
            // Geser klik ke area kotak centang (sekitar 30px dari kiri)
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
            
        # Secara aktif mencari dan klik checkbox jika masih tertahan di WAF Cloudflare
        if not clicked and i % 3 == 0:
            clicked = await click_turnstile_checkbox(tab)
            
    return str(title) if title else ""


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
    clicked = False
    for _ in range(TOKEN_WAIT_SECONDS):
        await asyncio.sleep(1)
        state = await get_page_state(tab)
        if state["val"]:
            return state["val"]
        if not clicked:
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


async def solve_flow(payload: SolvePayload):
    browser = await get_browser()
    tab = await browser.get(payload.url)
    try:
        title = await wait_cf_pass(tab)
        if "Just a moment" in title or not title:
            raise RuntimeError("Gagal melewati halaman verifikasi awal Cloudflare (Just a moment...)")

        state = await get_page_state(tab)
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
            if (await get_page_state(tab))["hasSubmit"]:
                submitted = await click_submit(tab)
                await asyncio.sleep(POST_SETTLE_SECONDS)

        user_agent = await tab.evaluate("navigator.userAgent")
        cookies, cookie_header, netscape = await collect_cookies(browser)

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
            "submitted": bool(submitted),
            "user_agent": str(user_agent),
            "cookie_header": cookie_header,
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
    exe = find_chrome_path()
    result = {"exe": exe}
    if exe:
        try:
            r = subprocess.run([exe, "--version"], capture_output=True, text=True, timeout=10)
            result["version"] = r.stdout.strip() or r.stderr.strip()
        except Exception as e:
            result["version_error"] = str(e)
    return result


@app.post("/api/solve")
async def solve_url(payload: SolvePayload):
    async with _solve_lock:
        try:
            result = await asyncio.wait_for(solve_flow(payload), timeout=FLOW_TIMEOUT)
            return JSONResponse(status_code=200, content=result)
        except asyncio.TimeoutError:
            print("ERROR: solve_url timed out", flush=True)
            await reset_browser()
            # Status diubah ke 200 agar body JSON tidak dibajak Render/Cloudflare
            return JSONResponse(status_code=200, content={"success": False, "error": "Operation timed out"})
        except Exception as e:
            traceback.print_exc()
            await reset_browser()
            # Status diubah ke 200 agar body JSON tidak dibajak Render/Cloudflare
            return JSONResponse(status_code=200, content={"success": False, "error": str(e)})
