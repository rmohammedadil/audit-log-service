from fastapi import FastAPI

app = FastAPI(
    title="Audit Log Service",
    description="A tamper-evident audit logging service",
    version="0.1.0",
)


@app.get("/")
def root():
    return {
        "message": "Audit Log Service is running"
    }


@app.get("/health")
def health_check():
    return {
        "status": "healthy"
    }