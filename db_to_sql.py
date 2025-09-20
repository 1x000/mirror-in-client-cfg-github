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

# 定义输出的SQL文件名
sql_file = os.path.join(script_dir, 'dump.sql')

print(f"正在从数据库读取: {db_file}")
print(f"将要写入SQL文件: {sql_file}")

try:
    # 连接到SQLite数据库
    con = sqlite3.connect(db_file)

    # 以写入模式打开SQL文件
    with open(sql_file, 'w', encoding='utf-8') as f:
        # iterdump() 返回一个迭代器，用于以SQL文本格式转储数据库
        for line in con.iterdump():
            f.write('%s\n' % line)

    print('成功！数据库已成功转换为SQL文件。')

except sqlite3.Error as e:
    print(f"发生错误: {e}")

finally:
    # 确保数据库连接已关闭
    if 'con' in locals() and con:
        con.close()
    
    input("按 Enter 键退出...")
