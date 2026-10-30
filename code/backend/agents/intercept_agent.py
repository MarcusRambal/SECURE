import sys
import asyncio
import os
from contextlib import asynccontextmanager
from urllib.parse import urlparse
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from playwright.async_api import async_playwright

# En Windows, forzar ProactorEventLoopPolicy desde el inicio
if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())

@asynccontextmanager
async def lifespan(app: FastAPI):
    yield

app = FastAPI(title="SECURE - Intercept Agent", lifespan=lifespan)

class InterceptPayload(BaseModel):
    target_url: str
    output_filename: str = "request.txt"

def format_raw_request(method, url, headers, post_data=""):
    parsed_url = urlparse(url)
    path = parsed_url.path or "/"
    if parsed_url.query:
        path += f"?{parsed_url.query}"
        
    host = parsed_url.netloc or "localhost:3000"

    if post_data is None:
        post_data = ""
    elif not isinstance(post_data, str):
        import json
        post_data = json.dumps(post_data)

    headers_str = f"Host: {host}\r\n"
    for k, v in headers.items():
        if k.lower() not in ["host", "content-length"]:
            headers_str += f"{k}: {v}\r\n"

    if post_data:
        headers_str += f"Content-Length: {len(post_data.encode('utf-8'))}\r\n"

    return f"{method} {path} HTTP/1.1\r\n{headers_str}\r\n{post_data}"

@app.post("/intercept")
async def intercept_request(payload: InterceptPayload):
    captured_data = {}

    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        context = await browser.new_context(viewport={"width": 1280, "height": 720})
        page = await context.new_page()

        def handle_request(request):
            if request.method in ["POST", "PUT"] and not captured_data:
                if "login" in request.url or "api" in request.url or "rest" in request.url:
                    captured_data["method"] = request.method
                    captured_data["url"] = request.url
                    captured_data["headers"] = dict(request.headers)
                    captured_data["post_data"] = request.post_data or ""

        page.on("request", handle_request)

        try:
            await page.goto(payload.target_url, wait_until="domcontentloaded")
            await page.wait_for_timeout(1000)

            dismiss_btn = page.locator("button.close-dialog, button[aria-label='Close Welcome Banner']")
            if await dismiss_btn.count() > 0 and await dismiss_btn.is_visible():
                await dismiss_btn.click()

            cookie_btn = page.locator("a.cc-dismiss, button[aria-label='dismiss cookie message']")
            if await cookie_btn.count() > 0 and await cookie_btn.is_visible():
                await cookie_btn.click()

            email_input = page.locator("input#email")
            password_input = page.locator("input#password")
            submit_btn = page.locator("button#loginButton")

            if await email_input.is_visible():
                await email_input.fill("admin@juice-sh.op")
                await password_input.fill("password123")
                await submit_btn.click()
                await page.wait_for_timeout(2000)

        except Exception as e:
            await browser.close()
            raise HTTPException(status_code=500, detail=f"Error en automatización: {str(e)}")

        await browser.close()

    if not captured_data:
        raise HTTPException(
            status_code=400, 
            detail="No se interceptó la petición POST de login."
        )

    raw_http = format_raw_request(
        method=captured_data["method"],
        url=captured_data["url"],
        headers=captured_data["headers"],
        post_data=captured_data["post_data"]
    )

    file_path = os.path.join(os.path.dirname(__file__), payload.output_filename)
    with open(file_path, "w", encoding="utf-8") as f:
        f.write(raw_http)

    return {"status": "success", "file_saved": payload.output_filename}

if __name__ == "__main__":
    import uvicorn
    if sys.platform == "win32":
        asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())
    # Pasar la instancia app directamente y reload=False evita que el reloader reemplace el loop
    uvicorn.run(app, host="127.0.0.1", port=8001, reload=False)