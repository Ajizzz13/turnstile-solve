import asyncio
from fastapi import FastAPI
from pydantic import BaseModel
import nodriver as uc

app = FastAPI()

class URLPayload(BaseModel):
    url: str

@app.get("/")
async def health():
    return {"status": "ok"}

@app.post("/api/resolve")
async def resolve_url(payload: URLPayload):
    browser = None
    try:
        browser = await uc.start(
            headless=True,
            sandbox=False,
            browser_args=[
                "--no-sandbox",
                "--disable-setuid-sandbox",
                "--disable-dev-shm-usage",
                "--disable-gpu",
                "--no-first-run",
                "--window-size=1280,720"
            ]
        )
        
        page = await browser.get(payload.url)
        
        title = ""
        for _ in range(20):
            await asyncio.sleep(1)
            title = await page.evaluate("document.title")
            if title and "Just a moment" not in str(title):
                break

        raw_cookies = await browser.cookies.get_all()
        cookie_list = []
        for c in raw_cookies:
            if hasattr(c, "to_json"):
                cookie_list.append(c.to_json())
            elif hasattr(c, "__dict__"):
                cookie_list.append(c.__dict__)
            else:
                cookie_list.append(str(c))

        return {
            "success": "Just a moment" not in str(title),
            "title": str(title) if title else "",
            "cookies_count": len(cookie_list),
            "cookies": cookie_list
        }
    except Exception as e:
        return {"success": False, "error": str(e)}
    finally:
        if browser:
            try:
                browser.stop()
            except Exception:
                pass
