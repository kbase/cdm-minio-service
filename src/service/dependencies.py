"""
Dependencies for FastAPI dependency injection.
"""

from src.service.http_bearer import KBaseHTTPBearer

# Initialize the KBase auth dependency for use in routes
auth = KBaseHTTPBearer()
