"""Workers package.

The Celery app is imported lazily via `app.workers.celery_app` to avoid pulling
heavy broker dependencies into modules that only need the scanner adapters
(e.g. unit tests, the normalizer).
"""
