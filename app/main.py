from fastapi import FastAPI

app = FastAPI(title="Home Inventory AI", version="1.0.0")


@app.get("/health")
async def health_check():
    return {"status": "ok"}
