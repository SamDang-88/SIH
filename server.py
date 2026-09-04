import asyncio
import os
from pathlib import Path
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from pipeline import run_pipeline

app = FastAPI(title="NTRO Threat Detection Stream")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

BASE_DIR = Path(__file__).resolve().parent
DASHBOARD_PATH = BASE_DIR / "dashboard.html"


@app.get("/api/pcaps")
def list_available_pcaps():
    from pathlib import Path
    directory = Path(__file__).resolve().parent
    pcaps = [p.name for p in directory.glob("*.pcap")]
    return sorted(pcaps)

@app.get("/")
def serve_dashboard():
    if not DASHBOARD_PATH.exists():
        raise HTTPException(status_code=404, detail="dashboard.html not found")
    return FileResponse(str(DASHBOARD_PATH))

@app.get("/api/sources")
def get_sources():
    """Scans disk and automatically provides all local PCAPs and live eth0."""
    pcaps = [p.name for p in BASE_DIR.glob("*.pcap")]
    return JSONResponse({
        "interfaces": ["eth0"],
        "pcaps": sorted(pcaps)
    })

@app.get("/health")
def health():
    return {"status": "ACTIVE", "engine_state": "PASSIVE_MONITORING"}

@app.websocket("/ws/live")
async def live_stream(websocket: WebSocket, source: str = "eth0"):
    await websocket.accept()
    loop = asyncio.get_event_loop()
    
    try:
        pipeline_gen = run_pipeline(source)
    except Exception as err:
        await websocket.send_json({"event_type": "ERROR", "data": {"error": f"Failed source: {str(err)}"}})
        await websocket.close()
        return

    try:
        while True:
            item = await loop.run_in_executor(None, lambda: next(pipeline_gen, None))
            if item is None:
                await websocket.send_json({
                    "event_type": "STATUS",
                    "data": {"status": "FINISHED", "source": source}
                })
                break
                
            event_type, payload = item
            await websocket.send_json({
                "event_type": event_type,
                "data": payload
            })
            await asyncio.sleep(0.0001)

    except WebSocketDisconnect:
        pass
    except Exception as e:
        try:
            await websocket.send_json({"event_type": "ERROR", "data": {"error": str(e)}})
        except Exception:
            pass
