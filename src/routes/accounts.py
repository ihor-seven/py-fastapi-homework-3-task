from datetime import datetime, timezone
from typing import cast

from fastapi import APIRouter, Depends, status, HTTPException
from sqlalchemy import select, delete
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import joinedload

from config import get_jwt_auth_manager, get_settings, BaseAppSettings
from database import (
    get_db,
    UserModel,
    UserGroupModel,
    UserGroupEnum,
    ActivationTokenModel,
    PasswordResetTokenModel,
    RefreshTokenModel,
)
from exceptions import BaseSecurityError
from schemas.accounts import (
    UserRegistrationRequestSchema,
    UserRegistrationResponseSchema,
    UserActivationRequestSchema,
    PasswordResetRequestSchema,
    PasswordResetCompleteRequestSchema,
    UserLoginRequestSchema,
    UserLoginResponseSchema,
    TokenRefreshRequestSchema,
    TokenRefreshResponseSchema,
    MessageResponseSchema,
)
from security.interfaces import JWTAuthManagerInterface

router = APIRouter()


def _is_expired(expires_at) -> bool:
    expires_at = cast(datetime, expires_at).replace(tzinfo=timezone.utc)
    return expires_at < datetime.now(timezone.utc)


@router.post(
    "/register/",
    response_model=UserRegistrationResponseSchema,
    status_code=status.HTTP_201_CREATED,
)
async def register_user(
    user_data: UserRegistrationRequestSchema,
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(UserModel).where(UserModel.email == user_data.email)
    )
    if result.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"A user with this email {user_data.email} already exists.",
        )

    result = await db.execute(
        select(UserGroupModel).where(UserGroupModel.name == UserGroupEnum.USER)
    )
    group = result.scalar_one_or_none()
    if not group:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred during user creation.",
        )

    try:
        new_user = UserModel.create(
            email=user_data.email,
            raw_password=user_data.password,
            group_id=cast(int, group.id),
        )
        db.add(new_user)
        await db.flush()

        activation_token = ActivationTokenModel(user_id=cast(int, new_user.id))
        db.add(activation_token)

        await db.commit()
        await db.refresh(new_user)
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred during user creation.",
        )

    return new_user


@router.post("/activate/", response_model=MessageResponseSchema)
async def activate_account(
    activation_data: UserActivationRequestSchema,
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(UserModel)
        .options(joinedload(UserModel.activation_token))
        .where(UserModel.email == activation_data.email)
    )
    user = result.scalar_one_or_none()
    token_record = user.activation_token if user else None

    if (
        not user
        or not token_record
        or token_record.token != activation_data.token
        or _is_expired(token_record.expires_at)
    ):
        if token_record and token_record.token == activation_data.token:
            await db.delete(token_record)
            await db.commit()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired activation token.",
        )

    if user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User account is already active.",
        )

    user.is_active = True
    await db.delete(token_record)
    await db.commit()

    return MessageResponseSchema(
        message="User account activated successfully."
    )


@router.post("/password-reset/request/", response_model=MessageResponseSchema)
async def request_password_reset_token(
    data: PasswordResetRequestSchema,
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(UserModel).where(UserModel.email == data.email)
    )
    user = result.scalar_one_or_none()

    if user and user.is_active:
        await db.execute(
            delete(PasswordResetTokenModel).where(
                PasswordResetTokenModel.user_id == user.id
            )
        )
        db.add(PasswordResetTokenModel(user_id=cast(int, user.id)))
        await db.commit()

    return MessageResponseSchema(
        message=(
            "If you are registered, "
            "you will receive an email with instructions."
        )
    )


@router.post("/reset-password/complete/", response_model=MessageResponseSchema)
async def reset_password(
    data: PasswordResetCompleteRequestSchema,
    db: AsyncSession = Depends(get_db),
):
    invalid_error = HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail="Invalid email or token.",
    )

    result = await db.execute(
        select(UserModel).where(UserModel.email == data.email)
    )
    user = result.scalar_one_or_none()
    if not user or not user.is_active:
        raise invalid_error

    result = await db.execute(
        select(PasswordResetTokenModel).where(
            PasswordResetTokenModel.user_id == user.id
        )
    )
    token_record = result.scalar_one_or_none()

    if (
        not token_record
        or token_record.token != data.token
        or _is_expired(token_record.expires_at)
    ):
        if token_record:
            await db.delete(token_record)
            await db.commit()
        raise invalid_error

    try:
        user.password = data.password
        await db.delete(token_record)
        await db.commit()
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while resetting the password.",
        )

    return MessageResponseSchema(message="Password reset successfully.")


@router.post(
    "/login/",
    response_model=UserLoginResponseSchema,
    status_code=status.HTTP_200_OK,
)
async def login_user(
    login_data: UserLoginRequestSchema,
    db: AsyncSession = Depends(get_db),
    settings: BaseAppSettings = Depends(get_settings),
    jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
):
    result = await db.execute(
        select(UserModel).where(UserModel.email == login_data.email)
    )
    user = result.scalar_one_or_none()

    if not user or not user.verify_password(login_data.password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password.",
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is not activated.",
        )

    user_id = cast(int, user.id)
    jwt_refresh_token = jwt_manager.create_refresh_token({"user_id": user_id})

    try:
        refresh_token = RefreshTokenModel.create(
            user_id=user_id,
            days_valid=settings.LOGIN_TIME_DAYS,
            token=jwt_refresh_token,
        )
        db.add(refresh_token)
        await db.commit()
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while processing the request.",
        )

    jwt_access_token = jwt_manager.create_access_token({"user_id": user_id})

    return UserLoginResponseSchema(
        access_token=jwt_access_token,
        refresh_token=jwt_refresh_token,
    )


@router.post("/api/v1/accounts/refresh/", response_model=TokenRefreshResponseSchema)
async def refresh_access_token(
    token_data: TokenRefreshRequestSchema,
    db: AsyncSession = Depends(get_db),
    jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
):
    try:
        decoded = jwt_manager.decode_refresh_token(token_data.refresh_token)
        user_id = decoded.get("user_id")
    except BaseSecurityError as error:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(error),
        )

    result = await db.execute(
        select(RefreshTokenModel).where(
            RefreshTokenModel.token == token_data.refresh_token
        )
    )
    if not result.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token not found.",
        )

    result = await db.execute(select(UserModel).where(UserModel.id == user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found.",
        )

    new_access_token = jwt_manager.create_access_token({"user_id": user_id})
    return TokenRefreshResponseSchema(access_token=new_access_token)
