from dataclasses import dataclass

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException


class ExpressJsonResponse(JSONResponse):
    media_type = "application/json; charset=utf-8"


@dataclass(frozen=True, slots=True)
class PublicHttpError(Exception):
    status_code: int
    code: str
    message: str


def error_response(status_code: int, code: str, message: str) -> JSONResponse:
    return ExpressJsonResponse(
        status_code=status_code,
        content={"error": {"code": code, "message": message}},
    )


def install_error_handlers(application: FastAPI) -> None:
    @application.exception_handler(PublicHttpError)
    async def public_error(_request: Request, error: PublicHttpError) -> JSONResponse:
        return error_response(error.status_code, error.code, error.message)

    @application.exception_handler(RequestValidationError)
    async def invalid_request(_request: Request, _error: RequestValidationError) -> JSONResponse:
        return error_response(400, "INVALID_REQUEST", "Invalid request")

    @application.exception_handler(StarletteHTTPException)
    async def framework_error(_request: Request, error: StarletteHTTPException) -> JSONResponse:
        if error.status_code in {404, 405}:
            return error_response(404, "NOT_FOUND", "Route not found")
        return error_response(error.status_code, "HTTP_ERROR", "Request failed")
