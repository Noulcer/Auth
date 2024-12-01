# 使用Python 3.9作为基础镜像
FROM python:3.9-slim

# 设置工作目录
WORKDIR /AUTH

# 复制项目文件
COPY . .

# 安装依赖
RUN pip install --no-cache-dir -r requirements.txt

# 创建日志目录
RUN mkdir -p logs

# 暴露端口
EXPOSE 5000

# 启动命令
CMD ["flask", "run"] 