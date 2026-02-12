from fastapi import FastAPI

app = FastAPI(title="InfraProbe")


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}
