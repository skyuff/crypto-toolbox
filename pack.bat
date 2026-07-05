@echo off
chcp 65001 >nul
setlocal enabledelayedexpansion

echo ============================================
echo    商用密码检测工具箱 - 一键打包脚本
echo ============================================
echo.

set "PROJECT_ROOT=%~dp0"
set "RELEASE_DIR=%PROJECT_ROOT%release"
set "MODE=%1"

if "%MODE%"=="" set "MODE=separate"

echo [1/5] 清理旧的发布目录...
if exist "%RELEASE_DIR%" rd /s /q "%RELEASE_DIR%"
mkdir "%RELEASE_DIR%"
mkdir "%RELEASE_DIR%\backend"
mkdir "%RELEASE_DIR%\frontend"
echo       完成
echo.

echo [2/5] 打包后端 (Maven)...
cd /d "%PROJECT_ROOT%backend"
call mvn clean package -DskipTests
if %errorlevel% neq 0 (
    echo [错误] 后端打包失败，请检查 Maven 环境
    pause
    exit /b 1
)
copy /y "target\crypto-toolbox-backend.jar" "%RELEASE_DIR%\backend\" >nul
echo       完成: backend\crypto-toolbox-backend.jar
echo.

echo [3/5] 打包前端 (npm)...
cd /d "%PROJECT_ROOT%frontend"
if not exist "node_modules" (
    echo       首次安装依赖...
    call npm install
    if %errorlevel% neq 0 (
        echo [错误] npm install 失败
        pause
        exit /b 1
    )
)
call npm run build
if %errorlevel% neq 0 (
    echo [错误] 前端打包失败
    pause
    exit /b 1
)
xcopy /e /i /q "dist\*" "%RELEASE_DIR%\frontend\" >nul
echo       完成: frontend\ (静态文件)
echo.

if "%MODE%"=="single" (
    echo [4/5] 合并为单 jar 包模式...
    mkdir "%PROJECT_ROOT%backend\src\main\resources\static" 2>nul
    xcopy /e /i /q "%RELEASE_DIR%\frontend\*" "%PROJECT_ROOT%backend\src\main\resources\static\" >nul
    cd /d "%PROJECT_ROOT%backend"
    call mvn clean package -DskipTests >nul 2>&1
    copy /y "target\crypto-toolbox-backend.jar" "%RELEASE_DIR%\crypto-toolbox-all-in-one.jar" >nul
    rd /s /q "%PROJECT_ROOT%backend\src\main\resources\static" 2>nul
    echo       完成: crypto-toolbox-all-in-one.jar
    echo.
) else (
    echo [4/5] 跳过单 jar 合并 (使用 separate 模式)
    echo       提示: 运行 pack.bat single 可生成单 jar 包
    echo.
)

echo [5/5] 生成部署说明...
(
echo ==========================================
echo   商用密码检测工具箱 - 部署说明
echo ==========================================
echo.
echo [前后端分离部署]
echo.
echo   1. 后端启动:
echo      java -jar backend\crypto-toolbox-backend-1.0.0.jar
echo.
echo   2. 前端部署:
echo      将 frontend\ 目录下的文件部署到 Nginx 等 Web 服务器
echo.
echo   3. Nginx 配置参考:
echo      server {
echo          listen 80;
echo          location / {
echo              root /var/www/html;
echo              try_files $uri $uri/ /index.html;
echo          }
echo          location /api {
echo              proxy_pass http://localhost:8080;
echo          }
echo      }
echo.
) > "%RELEASE_DIR%\部署说明.txt"

if "%MODE%"=="single" (
    (
    echo [单 jar 包部署]
    echo.
    echo   直接运行:
    echo     java -jar crypto-toolbox-all-in-one.jar
    echo.
    echo   访问 http://localhost:8080 即可使用
    echo.
    ) >> "%RELEASE_DIR%\部署说明.txt"
)

echo       完成
echo.
echo ============================================
echo   打包完成！发布目录: release\
echo ============================================
echo.
dir /b "%RELEASE_DIR%"
echo.
pause
