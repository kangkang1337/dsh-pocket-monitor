@echo off
chcp 65001 > nul
setlocal
cd /d "%~dp0"

echo.
echo ================================================
echo   DSH Pocket Monitor - LAN 模式启动
echo ================================================
echo.

where node > nul 2>&1
if errorlevel 1 (
  echo [错误] 没有找到 node。请先安装 Node.js 22.6 或更高版本：https://nodejs.org/
  echo.
  pause
  exit /b 1
)

for /f "delims=" %%v in ('node -p "process.versions.node"') do set NODE_VERSION=%%v
echo Node 版本：%NODE_VERSION%

node -e "const [a,b]=process.versions.node.split('.').map(Number);process.exit(a>22||(a===22&&b>=6)?0:1)"
if errorlevel 1 (
  echo [错误] Node 版本过低，需要 22.6 或更高（当前 %NODE_VERSION%）。
  echo.
  pause
  exit /b 1
)

if not exist "node_modules" (
  echo 还没有安装依赖，正在执行 npm install（只装依赖，不改动系统）...
  call npm install --no-fund --no-audit
  if errorlevel 1 (
    echo.
    echo [错误] 依赖安装失败。请检查网络后重试：npm install
    echo.
    pause
    exit /b 1
  )
)

if not exist "frontend\dist\index.html" (
  echo 正在构建手机端页面（npm run build）...
  call npm run build
  if errorlevel 1 (
    echo.
    echo [错误] 前端构建失败。请检查上面的输出。
    echo.
    pause
    exit /b 1
  )
)

echo.
echo 正在启动服务（关闭本窗口或按 Ctrl+C 即停止服务）...
echo 提示：不要用管理员身份运行；本程序不会修改防火墙、不会改动 DSH、不会安装任何隧道客户端。
echo.

node --experimental-strip-types backend\\src\\main.ts %*

echo.
echo 服务已停止。
pause
endlocal
