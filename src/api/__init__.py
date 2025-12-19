from fastapi import APIRouter

# Import all routers here
from . import auth, incidents, iocs, users, analysis

# Create main router
api_router = APIRouter()

# Include all API routers
api_router.include_router(auth.router, prefix="/auth", tags=["Authentication"])
api_router.include_router(users.router, prefix="/users", tags=["Users"])
api_router.include_router(incidents.router, prefix="/incidents", tags=["Incidents"])
api_router.include_router(iocs.router, prefix="/iocs", tags=["IOCs"])
api_router.include_router(analysis.router, prefix="/analysis", tags=["Analysis"])
