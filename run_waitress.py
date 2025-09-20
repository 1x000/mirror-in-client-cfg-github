from waitress import serve
from main import app

# 显式关闭Debug模式，确保生产环境安全
app.debug = False

if __name__ == '__main__':
    print("Starting production server with waitress on http://0.0.0.0:5000")
    serve(app, host='0.0.0.0', port=5000, threads=100)
