from fastapi import APIRouter
from fastapi.responses import StreamingResponse
import time
import json

router = APIRouter()

def event_stream():
    while True:
        payload = {
            "timestamp": time.time(),
            "status": "ok",
            "metrics": {
                "load": 0.42,
                "risk": 0.13,
                "registry_count": 7
            }
        }
        yield f"data: {json.dumps(payload)}\n\n"
        time.sleep(1)

@router.get("/stream")
async def stream():
    return StreamingResponse(event_stream(), media_type="text/event-stream")
