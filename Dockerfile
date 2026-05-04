# 使用轻量级 Node.js 镜像
FROM node:18-slim

# 设置工作目录
WORKDIR /app

# 先复制 package.json 和 package-lock.json 以利用 Docker 缓存
COPY package*.json ./

# 安装生产环境依赖
RUN npm install --production

# 复制项目所有文件到工作目录
COPY . .

# 添加构建时间参数以强制刷新缓存
ARG BUILD_DATE
RUN echo "Build date: $BUILD_DATE"

# 创建上传目录、数据目录并确保权限
RUN mkdir -p /app/uploads /app/data && chown -R node:node /app && chmod -R 777 /app/uploads /app/data

# 使用非 root 用户运行
USER node

# 暴露端口
EXPOSE 3000

# 启动应用
CMD ["node", "server/app.js"]
