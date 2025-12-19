"""Integration tests for authentication endpoints."""
import pytest
from fastapi import status
from sqlalchemy.ext.asyncio import AsyncSession

from src.models.user import User
from src.schemas.token import Token

# Test data
TEST_USER_EMAIL = "test@example.com"
TEST_USER_PASSWORD = "testpassword123"
TEST_USER_FULL_NAME = "Test User"
INVALID_EMAIL = "not-an-email"
SHORT_PASSWORD = "123"
MISSING_FIELD = ""

class TestAuthEndpoints:
    """Test authentication endpoints."""
    
    async def test_register_user_success(self, test_client):
        """Test successful user registration."""
        user_data = {
            "email": TEST_USER_EMAIL,
            "password": TEST_USER_PASSWORD,
            "full_name": TEST_USER_FULL_NAME,
        }
        
        response = test_client.post(
            "/api/v1/auth/register",
            json=user_data,
        )
        
        assert response.status_code == status.HTTP_201_CREATED
        data = response.json()
        assert data["email"] == TEST_USER_EMAIL
        assert data["full_name"] == TEST_USER_FULL_NAME
        assert "id" in data
        assert "hashed_password" not in data
    
    async def test_register_duplicate_email(self, test_client, create_test_user):
        """Test registration with duplicate email."""
        # First registration (should be successful)
        await create_test_user
        
        # Second registration with same email
        user_data = {
            "email": TEST_USER_EMAIL,
            "password": "anotherpassword",
            "full_name": "Another User"
        }
        
        response = test_client.post("/api/v1/auth/register", json=user_data)
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert "Email already registered" in response.text
    
    @pytest.mark.parametrize("field,value,error_message", [
        ("email", INVALID_EMAIL, "value is not a valid email address"),
        ("password", SHORT_PASSWORD, "ensure this value has at least 8 characters"),
        ("email", MISSING_FIELD, "field required"),
        ("password", MISSING_FIELD, "field required"),
    ])
    async def test_register_validation_errors(self, test_client, field, value, error_message):
        """Test registration with invalid data."""
        user_data = {
            "email": TEST_USER_EMAIL if field != "email" else value,
            "password": TEST_USER_PASSWORD if field != "password" else value,
            "full_name": TEST_USER_FULL_NAME,
        }
        
        response = test_client.post("/api/v1/auth/register", json=user_data)
        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY
        assert error_message in str(response.json())
    
    async def test_login_user_success(self, test_client, create_test_user):
        """Test successful user login with valid credentials."""
        # Create test user first
        await create_test_user
        
        login_data = {
            "username": TEST_USER_EMAIL,
            "password": TEST_USER_PASSWORD,
        }
        
        response = test_client.post(
            "/api/v1/auth/login",
            data=login_data,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert "access_token" in data
        assert data["token_type"] == "bearer"
        
        # Validate token schema
        token = Token(**data)
        assert len(token.access_token) > 0
    
    @pytest.mark.parametrize("username,password,expected_status,error_message", [
        (TEST_USER_EMAIL, "wrongpassword", status.HTTP_401_UNAUTHORIZED, "Incorrect email or password"),
        ("nonexistent@example.com", TEST_USER_PASSWORD, status.HTTP_401_UNAUTHORIZED, "Incorrect email or password"),
        ("", TEST_USER_PASSWORD, status.HTTP_422_UNPROCESSABLE_ENTITY, "field required"),
        (TEST_USER_EMAIL, "", status.HTTP_422_UNPROCESSABLE_ENTITY, "field required"),
    ])
    async def test_login_failure_cases(self, test_client, create_test_user, username, password, expected_status, error_message):
        """Test various login failure scenarios."""
        # Create test user first
        await create_test_user
        
        login_data = {
            "username": username,
            "password": password,
        }
        
        response = test_client.post(
            "/api/v1/auth/login",
            data=login_data,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        
        assert response.status_code == expected_status
        if expected_status == status.HTTP_401_UNAUTHORIZED:
            assert error_message in response.text
        else:
            assert error_message in str(response.json())
    
    async def test_get_current_user_authenticated(self, authenticated_client):
        """Test getting the current authenticated user with valid token."""
        response = authenticated_client.get("/api/v1/users/me")
        
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["email"] == TEST_USER_EMAIL
        assert data["full_name"] == TEST_USER_FULL_NAME
        assert "hashed_password" not in data
        assert "is_active" in data
        assert data["is_active"] is True
    
    async def test_get_current_user_unauthorized(self, test_client):
        """Test getting current user without authentication."""
        response = test_client.get("/api/v1/users/me")
        assert response.status_code == status.HTTP_401_UNAUTHORIZED
    
    async def test_get_current_user_invalid_token(self, test_client):
        """Test getting current user with invalid token."""
        response = test_client.get(
            "/api/v1/users/me",
            headers={"Authorization": "Bearer invalid_token"}
        )
        assert response.status_code == status.HTTP_401_UNAUTHORIZED
    
    async def test_refresh_token_success(self, authenticated_client):
        """Test successful token refresh."""
        response = authenticated_client.post("/api/v1/auth/refresh-token")
        
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert "access_token" in data
        assert data["token_type"] == "bearer"
        
        # The new token should be valid
        token = Token(**data)
        assert len(token.access_token) > 0
    
    async def test_refresh_token_unauthorized(self, test_client):
        """Test token refresh without authentication."""
        response = test_client.post("/api/v1/auth/refresh-token")
        assert response.status_code == status.HTTP_401_UNAUTHORIZED
    
    async def test_logout(self, authenticated_client, test_client):
        """Test user logout."""
        response = authenticated_client.post("/api/v1/auth/logout")
        assert response.status_code == status.HTTP_200_OK
        
        # After logout, the token should be invalidated
        response = test_client.get(
            "/api/v1/users/me",
            headers={"Authorization": "Bearer invalid_token"}
        )
        assert response.status_code == status.HTTP_401_UNAUTHORIZED
