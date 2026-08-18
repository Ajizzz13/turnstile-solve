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
            browser_args=[
                "--no-sandbox",
                "--disable-dev-shm-usage",
                "--disable-gpu",
                "--headless=new"
            ]
        )
        page = await browser.get(payload.url)
        await asyncio.sleep(4)
        
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
