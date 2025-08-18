# run.py
import uvicorn

if __name__ == "__main__":
    uvicorn.run(
        "info_shield.api.app:app",  # points to your FastAPI app
        host="127.0.0.1",
        port=8000,
        reload=True
    )