#!/bin/bash

echo "============================================"
echo "   商用密码检测工具箱 - 一键打包脚本"
echo "============================================"
echo ""

PROJECT_ROOT="$(cd "$(dirname "$0")" && pwd)"
RELEASE_DIR="$PROJECT_ROOT/release"
MODE="${1:-separate}"

echo "[1/5] 清理旧的发布目录..."
rm -rf "$RELEASE_DIR"
mkdir -p "$RELEASE_DIR/backend"
mkdir -p "$RELEASE_DIR/frontend"
echo "      完成"
echo ""

echo "[2/5] 打包后端 (Maven)..."
cd "$PROJECT_ROOT/backend" || exit 1
if ! mvn clean package -DskipTests; then
    echo "[错误] 后端打包失败，请检查 Maven 环境"
    exit 1
fi
cp target/crypto-toolbox-backend-1.0.0.jar "$RELEASE_DIR/backend/"
echo "      完成: backend/crypto-toolbox-backend-1.0.0.jar"
echo ""

echo "[3/5] 打包前端 (npm)..."
cd "$PROJECT_ROOT/frontend" || exit 1
if [ ! -d "node_modules" ]; then
    echo "      首次安装依赖..."
    if ! npm install; then
        echo "[错误] npm install 失败"
        exit 1
    fi
fi
if ! npm run build; then
    echo "[错误] 前端打包失败"
    exit 1
fi
cp -r dist/* "$RELEASE_DIR/frontend/"
echo "      完成: frontend/ (静态文件)"
echo ""

if [ "$MODE" = "single" ]; then
    echo "[4/5] 合并为单 jar 包模式..."
    mkdir -p "$PROJECT_ROOT/backend/src/main/resources/static"
    cp -r "$RELEASE_DIR/frontend/"* "$PROJECT_ROOT/backend/src/main/resources/static/"
    cd "$PROJECT_ROOT/backend" || exit 1
    mvn clean package -DskipTests > /dev/null 2>&1
    cp target/crypto-toolbox-backend-1.0.0.jar "$RELEASE_DIR/crypto-toolbox-all-in-one.jar"
    rm -rf "$PROJECT_ROOT/backend/src/main/resources/static"
    echo "      完成: crypto-toolbox-all-in-one.jar"
    echo ""
else
    echo "[4/5] 跳过单 jar 合并 (使用 separate 模式)"
    echo "      提示: 运行 ./pack.sh single 可生成单 jar 包"
    echo ""
fi

echo "[5/5] 生成部署说明..."
cat > "$RELEASE_DIR/部署说明.txt" << 'EOF'
==========================================
  商用密码检测工具箱 - 部署说明
==========================================

[前后端分离部署]

  1. 后端启动:
     java -jar backend/crypto-toolbox-backend-1.0.0.jar

  2. 前端部署:
     将 frontend/ 目录下的文件部署到 Nginx 等 Web 服务器

  3. Nginx 配置参考:
     server {
         listen 80;
         location / {
             root /var/www/html;
             try_files $uri $uri/ /index.html;
         }
         location /api {
             proxy_pass http://localhost:8080;
         }
     }

EOF

if [ "$MODE" = "single" ]; then
    cat >> "$RELEASE_DIR/部署说明.txt" << 'EOF'
[单 jar 包部署]

  直接运行:
    java -jar crypto-toolbox-all-in-one.jar

  访问 http://localhost:8080 即可使用

EOF
fi

echo "      完成"
echo ""
echo "============================================"
echo "  打包完成！发布目录: release/"
echo "============================================"
echo ""
ls -lh "$RELEASE_DIR"
echo ""
