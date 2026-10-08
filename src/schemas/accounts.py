from pydantic import BaseModel, EmailStr, Field, field_validator

from database import accounts_validators


class UserEmailSchema(BaseModel):
    email: EmailStr

    @field_validator("email")
    @classmethod
    def validate_email(cls, value: str) -> str:
        return accounts_validators.validate_email(value.lower())


class UserPasswordSchema(BaseModel):
    password: str

    @field_validator("password")
    @classmethod
    def validate_password(cls, value: str) -> str:
        accounts_validators.validate_password_strength(value)
        return value


class UserRegistrationRequestSchema(UserEmailSchema, UserPasswordSchema):
    model_config = {
        "json_schema_extra": {
            "examples": [
                {"email": "user@example.com", "password": "StrongPass1!"}
            ]
        }
    }


class UserRegistrationResponseSchema(BaseModel):
    id: int
    email: EmailStr

    model_config = {
        "from_attributes": True,
        "json_schema_extra": {
            "examples": [{"id": 1, "email": "user@example.com"}]
        },
    }


class UserActivationRequestSchema(UserEmailSchema):
    token: str = Field(..., max_length=64)


class MessageResponseSchema(BaseModel):
    message: str


class PasswordResetRequestSchema(UserEmailSchema):
    pass


class PasswordResetCompleteRequestSchema(UserEmailSchema, UserPasswordSchema):
    token: str = Field(..., max_length=64)


class UserLoginRequestSchema(UserEmailSchema):
    password: str


class UserLoginResponseSchema(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class TokenRefreshRequestSchema(BaseModel):
    refresh_token: str


class TokenRefreshResponseSchema(BaseModel):
    access_token: str
