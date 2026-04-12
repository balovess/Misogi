@echo off
REM generate_stubs.bat — Generate Python gRPC stubs from Misogi V1 proto definition (Windows).
REM
REM Usage:
REM   generate_stubs.bat
REM
REM Prerequisites:
REM   - Python 3.11+ with grpcio-tools installed
REM   - Proto file at ..\..\proto-dist\v1\misogi.proto

setlocal enabledelayedexpansion

set "SCRIPT_DIR=%~dp0"
set "PROTO_ROOT=%SCRIPT_DIR%..\..\proto-dist\v1"
set "PROTO_FILE=misogi.proto"
set "OUTPUT_DIR=%SCRIPT_DIR%src\misogi_client\pb2"

echo ==> Misogi Python gRPC Stub Generator (Windows)
echo     Proto source : %PROTO_ROOT%\%PROTO_FILE%
echo     Output target: %OUTPUT_DIR%
echo.

if not exist "%PROTO_ROOT%\%PROTO_FILE%" (
    echo [ERROR] Proto file not found: %PROTO_ROOT%\%PROTO_FILE% >&2
    exit /b 1
)

if not exist "%OUTPUT_DIR%" mkdir "%OUTPUT_DIR%"

python -m grpc_tools.protoc ^
    -I"%PROTO_ROOT%" ^
    --python_out="%OUTPUT_DIR%" ^
    --grpc_python_out="%OUTPUT_DIR%" ^
    "%PROTO_ROOT%\%PROTO_FILE%"

if %ERRORLEVEL% neq 0 (
    echo [ERROR] protoc generation failed with error code %ERRORLEVEL% >&2
    exit /b %ERRORLEVEL%
)

echo.
echo [OK] Stubs generated successfully in %OUTPUT_DIR%\
echo      - misogi_pb2.py          (message types^)
echo      - misogi_pb2_grpc.py     (service stubs^)
