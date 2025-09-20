import sqlite3
import os
import sys

# 获取脚本所在的目录
# 如果在打包成exe后运行，sys.executable是可执行文件的路径
if getattr(sys, 'frozen', False):
    script_dir = os.path.dirname(sys.executable)
else:
    # 在正常Python环境中运行
    script_dir = os.path.dirname(os.path.abspath(__file__))

# 在脚本所在目录中查找.db文件
db_file = None
for file in os.listdir(script_dir):
    if file.endswith(".db"):
        db_file = os.path.join(script_dir, file)
        break

if not db_file:
    print("错误：在脚本目录中未找到 .db 文件。")
    input("按 Enter 键退出...")
    sys.exit()

print(f"找到数据库: {db_file}")
print("正在连接到数据库并执行垃圾回收 (VACUUM)...")

try:
    # 连接到SQLite数据库
    con = sqlite3.connect(db_file)

    # 执行 VACUUM 命令
    con.execute("VACUUM")

    print("成功！数据库已完成垃圾回收。")

except sqlite3.Error as e:
    print(f"发生错误: {e}")

finally:
    # 确保数据库连接已关闭
    if 'con' in locals() and con:
        con.close()
    
    input("按 Enter 键退出...")
