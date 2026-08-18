import asyncio
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import nodriver as uc

app = FastAPI()

class URLPayload(BaseModel):
    url: str

@app.get("/")
async def health():
    return {"status": "running"}

@app.post("/api/resolve")
async def resolve_url(payload: URLPayload):
    browser = None
    try:
        browser = await uc.start(
            headless=True,
            no_sandbox=True,
            browser_args=[
                "--disable-dev-shm-usage",
                "--disable-gpu",
                "--window-size=1920,1080"
            ]
        )
        page = await browser.get(payload.url)
        await asyncio.sleep(5)

        cookies = await page.send(uc.cdp.network.get_cookies())
        title = await page.evaluate("document.title")

        return {
            "success": True,
            "title": title,
            "cookies": [c.to_json() for c in cookies]
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        if browser:
            browser.stop()
