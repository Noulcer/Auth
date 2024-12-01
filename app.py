import os
import sys

# 添加项目根目录到 Python 路径
sys.path.append(os.path.abspath(os.path.dirname(__file__)))

from app import create_app, db

app = create_app()

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run() 