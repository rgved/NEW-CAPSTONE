from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from backend.memory.sqlite.database import init_db

# Import routers
from backend.api.routes.dashboard import router as dashboard_router
from backend.api.routes.missions import router as missions_router
from backend.api.routes.findings import router as findings_router
from backend.api.routes.reports import router as reports_router
from backend.api.routes.metrics import router as metrics_router
from backend.api.routes.memory import router as memory_router
from backend.api.routes.ownership import router as ownership_router
from backend.api.routes.auth import router as auth_router

app = FastAPI(
    title="Agentic Web Security Recon Platform API",
    description="REST API interface for Phase 8 Dashboard.",
    version="1.0.0"
)

# Enable CORS for frontend accessibility
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize database tables on server startup
@app.on_event("startup")
def startup_event():
    init_db()

# Register Routers
app.include_router(auth_router, prefix="/api")
app.include_router(dashboard_router, prefix="/api")
app.include_router(missions_router, prefix="/api")
app.include_router(findings_router, prefix="/api")
app.include_router(reports_router, prefix="/api")
app.include_router(metrics_router, prefix="/api")
app.include_router(memory_router, prefix="/api")
app.include_router(ownership_router, prefix="/api")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("backend.api.server:app", host="127.0.0.1", port=8000, reload=True)
