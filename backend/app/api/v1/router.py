"""API v1 router aggregation."""
from fastapi import APIRouter

from app.api.v1 import auth, findings, health, projects, repositories, scans, stats, webhooks

api_router = APIRouter()
api_router.include_router(auth.router)
api_router.include_router(projects.router)
api_router.include_router(scans.router)
api_router.include_router(findings.router)
api_router.include_router(repositories.router)
api_router.include_router(stats.router)
api_router.include_router(webhooks.router)
api_router.include_router(health.router)
