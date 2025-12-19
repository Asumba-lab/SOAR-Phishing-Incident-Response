"""
Custom exceptions and error handlers for the application.
"""
from typing import Any, Dict, Optional
from fastapi import HTTPException, status
from pydantic import BaseModel

class ErrorResponse(BaseModel):
    """Standard error response model."""
    success: bool = False
    error: str
    code: int
    details: Optional[Dict[str, Any]] = None

class AppException(Exception):
    """Base exception class for application-specific exceptions."""
    def __init__(
        self,
        status_code: int,
        error: str,
        details: Optional[Dict[str, Any]] = None,
    ):
        self.status_code = status_code
        self.error = error
        self.details = details or {}
        super().__init__(error)

    def to_dict(self) -> Dict[str, Any]:
        """Convert exception to a dictionary."""
        return {
            "success": False,
            "error": self.error,
            "code": self.status_code,
            "details": self.details,
        }

class NotFoundException(AppException):
    """Raised when a resource is not found."""
    def __init__(self, resource: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(
            status_code=status.HTTP_404_NOT_FOUND,
            error=f"{resource} not found",
            details=details,
        )

class UnauthorizedException(AppException):
    """Raised when authentication is required but not provided or invalid."""
    def __init__(self, details: Optional[Dict[str, Any]] = None):
        super().__init__(
            status_code=status.HTTP_401_UNAUTHORIZED,
            error="Not authenticated",
            details=details or {"message": "Authentication required"},
        )

class ForbiddenException(AppException):
    """Raised when the user doesn't have permission to access a resource."""
    def __init__(self, details: Optional[Dict[str, Any]] = None):
        super().__init__(
            status_code=status.HTTP_403_FORBIDDEN,
            error="Permission denied",
            details=details or {"message": "You don't have permission to access this resource"},
        )

class BadRequestException(AppException):
    """Raised when the request is invalid."""
    def __init__(self, details: Optional[Dict[str, Any]] = None):
        super().__init__(
            status_code=status.HTTP_400_BAD_REQUEST,
            error="Bad request",
            details=details or {"message": "The request could not be processed"},
        )

class ConflictException(AppException):
    """Raised when there's a conflict with the current state of the resource."""
    def __init__(self, details: Optional[Dict[str, Any]] = None):
        super().__init__(
            status_code=status.HTTP_409_CONFLICT,
            error="Conflict",
            details=details or {"message": "The request conflicts with the current state of the resource"},
        )

class RateLimitException(AppException):
    """Raised when the rate limit is exceeded."""
    def __init__(self, details: Optional[Dict[str, Any]] = None):
        super().__init__(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            error="Rate limit exceeded",
            details=details or {"message": "Too many requests, please try again later"},
        )

def handle_app_exception(request, exc: AppException):
    """Handle application-specific exceptions."""
    return JSONResponse(
        status_code=exc.status_code,
        content=exc.to_dict(),
    )

def setup_exception_handlers(app):
    """Set up exception handlers for the FastAPI app."""
    from fastapi.responses import JSONResponse
    
    @app.exception_handler(AppException)
    async def app_exception_handler(request, exc: AppException):
        return JSONResponse(
            status_code=exc.status_code,
            content=exc.to_dict(),
        )
    
    @app.exception_handler(HTTPException)
    async def http_exception_handler(request, exc: HTTPException):
        return JSONResponse(
            status_code=exc.status_code,
            content={
                "success": False,
                "error": exc.detail,
                "code": exc.status_code,
            },
        )
    
    @app.exception_handler(Exception)
    async def global_exception_handler(request, exc: Exception):
        # Log the full exception
        import traceback
        traceback.print_exc()
        
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={
                "success": False,
                "error": "Internal server error",
                "code": status.HTTP_500_INTERNAL_SERVER_ERROR,
                "details": {"message": str(exc)},
            },
        )
