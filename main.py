import os
import sqlite3
import random
import io
import uuid
import time
import re
import json
from flask import Flask, render_template, request, redirect, url_for, flash, g, send_from_directory, abort, session, jsonify, make_response, send_file
from flask_login import LoginManager, login_user, logout_user, login_required, UserMixin, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime, timedelta
from PIL import Image, ImageDraw, ImageFont
from functools import wraps
import zipfile
# from flask_socketio import SocketIO
import psutil

# ==============================================================================
# 1. 配置中心
# ==============================================================================
class Config:
    SECRET_KEY = 'URD0M9BomMPsPMgJ6DyiMBV1F2JnWt'
    DATABASE_PATH = 'database.db'
    BASE_DIR = os.path.abspath(os.path.dirname(__file__))
    UPLOAD_FOLDER = os.path.join(BASE_DIR, 'static', 'uploads')
    LOGO_FOLDER = os.path.join(BASE_DIR, 'static', 'logos')
    PROOF_FOLDER = os.path.join(BASE_DIR, 'static', 'proofs')
    MAX_CONTENT_LENGTH = 1024 * 1024 * 1024  # 上传限制提升到500MB
    LOGO_SIZE = (256, 256)
    APPLICATION_ROOT = '/'
    WORDCLOUD_FONT_PATH = os.path.join(BASE_DIR, 'msyh.ttc')
    SERVER_NAME = None
    USER_UPLOAD_LIMIT_PER_DAY = 20
    ALLOWED_EXTENSIONS = {'zip', 'jar', '7z', 'exe'}

# ==============================================================================
# 2. Flask 应用初始化
# ==============================================================================
app = Flask(__name__)
app.config.from_object(Config)
# socketio = SocketIO(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message, login_manager.login_message_category = "请先登录以访问此页面。", "warning"
captcha_in_memory_images, download_tokens = {}, {}

# ==============================================================================
# 3. 数据库和模型
# ==============================================================================
def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(app.config['DATABASE_PATH'])
        db.row_factory = sqlite3.Row
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None: db.close()

def init_db():
    with app.app_context():
        db = get_db()
        cursor = db.cursor()
        cursor.execute("PRAGMA foreign_keys = ON;")
        cursor.execute('CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL, is_admin INTEGER DEFAULT 0, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)')
        cursor.execute('CREATE TABLE IF NOT EXISTS groups (id INTEGER PRIMARY KEY, name TEXT UNIQUE NOT NULL, display_order INTEGER DEFAULT 0, partition_id INTEGER, FOREIGN KEY(partition_id) REFERENCES partitions(id) ON DELETE SET NULL)')
        cursor.execute('''CREATE TABLE IF NOT EXISTS partitions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT UNIQUE NOT NULL,
                slug TEXT UNIQUE NOT NULL,
                display_order INTEGER DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )''')
        cursor.execute('CREATE TABLE IF NOT EXISTS folders (id INTEGER PRIMARY KEY, name TEXT UNIQUE NOT NULL, description TEXT, logo_filename TEXT, group_id INTEGER, FOREIGN KEY(group_id) REFERENCES groups(id) ON DELETE SET NULL)')
        cursor.execute('''CREATE TABLE IF NOT EXISTS files (id INTEGER PRIMARY KEY, filename TEXT NOT NULL, folder_id INTEGER, title TEXT, version TEXT, description TEXT, uploader_id INTEGER, status TEXT DEFAULT "pending", upload_type TEXT NOT NULL DEFAULT "user", download_count INTEGER NOT NULL DEFAULT 0, login_required INTEGER NOT NULL DEFAULT 1, bilibili_link TEXT, upload_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP, approve_time TIMESTAMP, FOREIGN KEY(folder_id) REFERENCES folders(id) ON DELETE CASCADE, FOREIGN KEY(uploader_id) REFERENCES users(id) ON DELETE SET NULL)''')
        cursor.execute('CREATE TABLE IF NOT EXISTS proof_images (id INTEGER PRIMARY KEY, file_id INTEGER NOT NULL, filename TEXT NOT NULL, FOREIGN KEY(file_id) REFERENCES files(id) ON DELETE CASCADE)')
        cursor.execute('CREATE TABLE IF NOT EXISTS upload_logs (id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL, upload_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP, FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE)')
        cursor.execute('CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT)')
        default_settings = {
            'announcements': json.dumps([{'date': '2025-07-28', 'text': '欢迎来到本站！'}]),
            'contact_links': json.dumps([{'text': '意见反馈', 'url': '#'}]),
            'related_links': json.dumps([{'text': '使用帮助', 'url': '#'}]),
            'friend_links': json.dumps([{'text': '友情链接', 'url': '#'}]),
            'footer_text': '本站的所有文件请在下载的24小时内删除，仅供学习如侵犯了版权请您发送邮件到 xiaopang@xpdbk.com。'
        }
        for key, value in default_settings.items():
            cursor.execute('INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)', (key, value))
        db.commit()

class User(UserMixin):
    def __init__(self, **kwargs):
        self.id, self.username, self.password_hash, self.is_admin = kwargs.get('id'), kwargs.get('username'), kwargs.get('password_hash'), bool(kwargs.get('is_admin'))
    @staticmethod
    def get(user_id):
        user_data = get_db().execute('SELECT * FROM users WHERE id=?', (user_id,)).fetchone()
        return User(**user_data) if user_data else None
    @staticmethod
    def get_by_username(username):
        user_data = get_db().execute('SELECT * FROM users WHERE username=?', (username,)).fetchone()
        return User(**user_data) if user_data else None

@login_manager.user_loader
def load_user(user_id): return User.get(user_id)

def admin_required(f):
    @wraps(f)
    @login_required
    def decorated_function(*args, **kwargs):
        if not current_user.is_admin: abort(403)
        return f(*args, **kwargs)
    return decorated_function

# ==============================================================================
# 4. 图像生成及验证路由
# ==============================================================================
def _serve_pil_image(pil_img):
    img_io = io.BytesIO(); pil_img.save(img_io, 'PNG'); img_io.seek(0)
    return send_file(img_io, mimetype='image/png')

def get_bilibili_embed_url(original_url):
    if not original_url: return None
    match = re.search(r'(BV[a-zA-Z0-9_]{10})', original_url)
    if match: return f"//player.bilibili.com/player.html?bvid={match.group(1)}&autoplay=0"
    return None

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']



@app.route('/captcha/generate')
def generate_captcha():
    try:
        width, height = 300, 150
        bg_color = (random.randint(200, 255), random.randint(200, 255), random.randint(200, 255))
        bg_image = Image.new('RGB', (width, height), bg_color); draw = ImageDraw.Draw(bg_image)
        for _ in range(random.randint(15, 25)):
            x1, y1, x2, y2 = random.randint(0, width), random.randint(0, height), random.randint(0, width), random.randint(0, height)
            line_color = (random.randint(100, 200), random.randint(100, 200), random.randint(100, 200))
            draw.line((x1, y1, x2, y2), fill=line_color, width=1)
        for _ in range(random.randint(100, 200)):
            x, y = random.randint(0, width), random.randint(0, height)
            point_color = (random.randint(120, 220), random.randint(120, 220), random.randint(120, 220))
            draw.point((x, y), fill=point_color)
        piece_size = 40
        x_pos = random.randint(piece_size + 20, width - piece_size - 20)
        y_pos = random.randint(10, height - piece_size - 10)
        box = (x_pos, y_pos, x_pos + piece_size, y_pos + piece_size)
        piece_image = bg_image.crop(box); piece_draw = ImageDraw.Draw(piece_image)
        piece_draw.rectangle((0, 0, piece_size-1, piece_size-1), outline='gray', width=1)
        draw.rectangle(box, fill='#f0f0f0', outline='#cccccc')
        ts = str(datetime.now().timestamp())
        bg_io, piece_io = io.BytesIO(), io.BytesIO()
        bg_image.save(bg_io, 'PNG'); piece_image.save(piece_io, 'PNG')
        bg_io.seek(0); piece_io.seek(0)
        captcha_in_memory_images[f"bg_{ts}"], captcha_in_memory_images[f"piece_{ts}"] = bg_io, piece_io
        session['captcha_answer'] = x_pos
        return jsonify({"type": "slider", "bg_url": url_for('serve_captcha_image', image_key=f"bg_{ts}"), "piece_url": url_for('serve_captcha_image', image_key=f"piece_{ts}"), "y_pos": y_pos})
    except Exception as e:
        print(f"FATAL: Captcha generation failed: {e}")
        return jsonify({"error": "Failed to generate CAPTCHA"}), 500

@app.route('/captcha/image/<image_key>')
def serve_captcha_image(image_key):
    image_io = captcha_in_memory_images.pop(image_key, None)
    if image_io: return _serve_pil_image(Image.open(image_io))
    abort(404)

def verify_captcha(response):
    correct_answer = session.pop('captcha_answer', None)
    if correct_answer is None or response is None: return False
    try: return abs(int(float(response)) - correct_answer) <= 5
    except (ValueError, TypeError): return False

def _parse_dynamic_links_from_form(prefix, form_data):
    """从请求表单中解析动态添加的链接列表。"""
    items = []
    i = 0
    is_announcement = prefix == 'announcement'
    while True:
        text_key = f'{prefix}_text_{i}'
        if text_key not in form_data:
            break
        text = form_data[text_key]
        if text:
            if is_announcement:
                items.append({'date': form_data.get(f'{prefix}_date_{i}', ''), 'text': text})
            else:
                items.append({'text': text, 'url': form_data.get(f'{prefix}_url_{i}', '#')})
        i += 1
    return json.dumps(items)

# ==============================================================================
# 5. 视图函数 (路由)
# ==============================================================================
@app.context_processor
def inject_settings():
    db = get_db()
    settings_raw = db.execute('SELECT key, value FROM settings').fetchall()
    settings = {row['key']: row['value'] for row in settings_raw}
    
    # 使用循环简化JSON字段的加载
    json_keys = ['announcements', 'contact_links', 'related_links', 'friend_links']
    for key in json_keys:
        try:
            settings[key] = json.loads(settings.get(key, '[]'))
        except json.JSONDecodeError:
            settings[key] = []

    partitions = db.execute('SELECT * FROM partitions ORDER BY display_order, name').fetchall()
    return dict(site_settings=settings, partitions=partitions)

@app.route('/')
def index():
    db = get_db()
    stats = {
        'folder_count': db.execute('SELECT COUNT(*) FROM folders').fetchone()[0],
        'file_count': db.execute("SELECT COUNT(*) FROM files WHERE status='approved'").fetchone()[0],
        'last_upload': db.execute("SELECT approve_time FROM files WHERE status='approved' ORDER BY approve_time DESC LIMIT 1").fetchone()
    }
    if stats['last_upload'] and stats['last_upload']['approve_time']:
        time_str = stats['last_upload']['approve_time'].split('.')[0]
        stats['last_upload_formatted'] = datetime.strptime(time_str, '%Y-%m-%d %H:%M:%S').strftime('%Y-%m-%d %H:%M')
    else:
        stats['last_upload_formatted'] = '暂无'
    
    # 获取热门下载
    hot_files = db.execute("""
        SELECT id, title, version, filename, download_count 
        FROM files 
        WHERE status='approved' 
        ORDER BY download_count DESC 
        LIMIT 10
    """).fetchall()

    # 使用 itertools.groupby 优化数据结构组织
    from itertools import groupby

    # 1. 获取所有文件夹并按 group_id 分组
    all_folders_query = db.execute("SELECT * FROM folders ORDER BY group_id, name").fetchall()
    folders_by_group = {k: list(v) for k, v in groupby(all_folders_query, key=lambda f: f['group_id'])}

    # 2. 获取所有分组并按 partition_id 分组
    all_groups_query = db.execute("SELECT g.*, p.name as partition_name, p.slug as partition_slug FROM groups g LEFT JOIN partitions p ON g.partition_id = p.id ORDER BY p.display_order, g.display_order").fetchall()
    groups_by_partition_raw = {k: list(v) for k, v in groupby(all_groups_query, key=lambda g: g['partition_id'])}

    # 3. 组合分组和文件夹
    groups_by_partition = {}
    for p_id, groups in groups_by_partition_raw.items():
        groups_with_folders = []
        for group in groups:
            group_dict = dict(group)
            group_dict['folders'] = folders_by_group.get(group['id'], [])
            groups_with_folders.append(group_dict)
        groups_by_partition[p_id] = groups_with_folders

    all_partitions = db.execute("SELECT * FROM partitions ORDER BY display_order, name").fetchall()

    return render_template('index.html', 
                           stats=stats, 
                           hot_files=hot_files,
                           all_partitions=all_partitions,
                           groups_by_partition=groups_by_partition)

@app.route('/partition/<slug>')
def partition_view(slug):
    db = get_db()
    partition = db.execute("SELECT * FROM partitions WHERE slug = ?", (slug,)).fetchone()
    if not partition:
        abort(404)

    groups = db.execute("SELECT * FROM groups WHERE partition_id = ? ORDER BY display_order, name", (partition['id'],)).fetchall()
    
    group_ids = [g['id'] for g in groups]
    all_folders = []
    if group_ids:
        # Create a string of question marks for the IN clause
        placeholders = ','.join('?' for _ in group_ids)
        all_folders = db.execute(f"SELECT * FROM folders WHERE group_id IN ({placeholders}) ORDER BY name", group_ids).fetchall()

    return render_template('partition_view.html', partition=partition, groups=groups, all_folders=all_folders)


@app.route('/folder/<int:folder_id>')
def folder_detail(folder_id):
    db = get_db()
    folder = db.execute('SELECT * FROM folders WHERE id=?', (folder_id,)).fetchone()
    if not folder: abort(404)
    
    # 获取当前文件夹所在的分区信息，用于上下文搜索
    partition_info = db.execute("""
        SELECT p.id, p.name 
        FROM partitions p
        JOIN groups g ON p.id = g.partition_id
        WHERE g.id = ?
    """, (folder['group_id'],)).fetchone()

    all_approved_files_raw = db.execute("SELECT * FROM files WHERE folder_id=? AND status='approved' ORDER BY upload_type, approve_time DESC", (folder_id,)).fetchall()
    
    # 格式化日期并使用 itertools.groupby 分离文件
    from itertools import groupby
    
    def format_and_group(files):
        for file in files:
            file_dict = dict(file)
            file_dict['formatted_date'] = 'N/A'
            if file_dict.get('approve_time'):
                try:
                    time_str = file_dict['approve_time'].split('.')[0]
                    file_dict['formatted_date'] = datetime.strptime(time_str, '%Y-%m-%d %H:%M:%S').strftime('%b %d, %Y')
                except (ValueError, TypeError): pass
            yield file_dict

    grouped_files = {k: list(v) for k, v in groupby(format_and_group(all_approved_files_raw), key=lambda f: f['upload_type'])}
    
    admin_files = grouped_files.get('admin', [])
    user_files = grouped_files.get('user', [])

    return render_template('folder.html', folder=folder, admin_files=admin_files, user_files=user_files, partition_info=partition_info)

@app.route('/file/<int:file_id>')
def file_detail(file_id):
    db = get_db()
    file = db.execute('SELECT * FROM files WHERE id=?', (file_id,)).fetchone()
    if not file or file['status'] != 'approved': abort(404)
    folder = db.execute('SELECT * FROM folders WHERE id=?', (file['folder_id'],)).fetchone()
    proof_images = db.execute('SELECT filename FROM proof_images WHERE file_id=?', (file_id,)).fetchall()
    embed_url = get_bilibili_embed_url(file['bilibili_link'])
    return render_template('file_detail.html', file=file, folder=folder, proof_images=proof_images, embed_url=embed_url)

@app.route('/download_with_token/<token>')
def download_with_token(token):
    current_time = time.time()
    # 使用字典推导式清理过期的token
    global download_tokens
    download_tokens = {k: v for k, v in download_tokens.items() if v['expires'] >= current_time}

    token_data = download_tokens.pop(token, None)
    if token_data:
        filename = token_data['filename']
        db = get_db()
        db.execute("UPDATE files SET download_count = download_count + 1 WHERE filename = ?", (filename,))
        db.commit()
        return send_from_directory(app.config['UPLOAD_FOLDER'], filename, as_attachment=True)
    else:
        flash('下载链接无效或已过期，请重新验证。', 'danger'); return redirect(url_for('index'))

@app.route('/verify_download/<int:file_id>', methods=['GET', 'POST'])
def verify_download(file_id):
    file = get_db().execute("SELECT * FROM files WHERE id=? AND status='approved'", (file_id,)).fetchone()
    if not file: abort(404)
    if file['login_required'] and not current_user.is_authenticated:
        flash('此文件需要登录后才能下载。', 'warning'); return redirect(url_for('login', next=request.url))
    if request.method == 'POST':
        if verify_captcha(request.form.get('captcha_response')):
            token = str(uuid.uuid4())
            download_tokens[token] = {'filename': file['filename'], 'expires': time.time() + 30 * 60}
            return redirect(url_for('download_with_token', token=token))
        else:
            flash('人机验证失败，请重试。', 'danger'); return render_template('verify_download.html', file=file)
    return render_template('verify_download.html', file=file)

@app.route('/search')
def search():
    query = request.args.get('query', '').strip()
    folder_id = request.args.get('folder_id', type=int)
    partition_id = request.args.get('partition_id', type=int)

    db = get_db()
    
    search_context = {'type': '全站', 'name': ''}
    
    base_file_query = "SELECT f.*, fo.name as folder_name, g.name as group_name, p.name as partition_name FROM files f JOIN folders fo ON f.folder_id = fo.id LEFT JOIN groups g ON fo.group_id = g.id LEFT JOIN partitions p ON g.partition_id = p.id WHERE (f.title LIKE ? OR f.description LIKE ? OR f.filename LIKE ? OR f.version LIKE ?) AND f.status = 'approved'"
    base_folder_query = "SELECT fo.*, g.name as group_name, p.name as partition_name FROM folders fo LEFT JOIN groups g ON fo.group_id = g.id LEFT JOIN partitions p ON g.partition_id = p.id WHERE (fo.name LIKE ? OR fo.description LIKE ?)"
    
    search_term = f'%{query}%'
    params = [search_term] * 4
    folder_params = [search_term] * 2

    if folder_id:
        folder = db.execute("SELECT name FROM folders WHERE id = ?", (folder_id,)).fetchone()
        if folder:
            search_context = {'type': '文件夹', 'name': folder['name']}
        base_file_query += " AND f.folder_id = ?"
        params.append(folder_id)
        # 在文件夹内搜索时，不搜索子文件夹
        folders_results = []
    elif partition_id:
        partition = db.execute("SELECT name FROM partitions WHERE id = ?", (partition_id,)).fetchone()
        if partition:
            search_context = {'type': '分区', 'name': partition['name']}
        
        # 找到该分区下的所有文件夹ID
        group_ids_rows = db.execute("SELECT id FROM groups WHERE partition_id = ?", (partition_id,)).fetchall()
        group_ids = [row['id'] for row in group_ids_rows]
        
        if group_ids:
            placeholders = ','.join('?' for _ in group_ids)
            folder_ids_rows = db.execute(f"SELECT id FROM folders WHERE group_id IN ({placeholders})", group_ids).fetchall()
            folder_ids = [row['id'] for row in folder_ids_rows]

            if folder_ids:
                file_placeholders = ','.join('?' for _ in folder_ids)
                base_file_query += f" AND f.folder_id IN ({file_placeholders})"
                params.extend(folder_ids)
                
                folder_placeholders = ','.join('?' for _ in group_ids)
                base_folder_query += f" AND fo.group_id IN ({folder_placeholders})"
                folder_params.extend(group_ids)
            else: # 分区下有分组但没文件夹
                base_file_query += " AND 1=0" # 返回空结果
                base_folder_query += " AND 1=0"
        else: # 分区下没分组
            base_file_query += " AND 1=0"
            base_folder_query += " AND 1=0"

    if not query:
        files_results, folders_results = [], []
    else:
        files_results = db.execute(base_file_query, params).fetchall()
        if not folder_id: # 文件夹内搜索不返回文件夹结果
            folders_results = db.execute(base_folder_query, folder_params).fetchall()

    return render_template('search_results.html', 
                           query=query, 
                           files_results=files_results, 
                           folders_results=folders_results,
                           search_context=search_context,
                           folder_id=folder_id,
                           partition_id=partition_id)


@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated: return redirect(url_for('index'))
    if request.method == 'POST':
        if not verify_captcha(request.form.get('captcha_response')):
            flash('人机验证失败，请重试。', 'danger'); return render_template('register.html')
        username, password = request.form.get('username'), request.form.get('password')
        if not username or not password: flash('用户名和密码不能为空'); return render_template('register.html')
        if User.get_by_username(username): flash('用户名已存在'); return render_template('register.html')
        db = get_db()
        is_admin = 1 if db.execute('SELECT COUNT(*) FROM users').fetchone()[0] == 0 else 0
        db.execute('INSERT INTO users (username, password_hash, is_admin) VALUES (?, ?, ?)', (username, generate_password_hash(password), is_admin))
        db.commit()
        flash('注册成功，请登录', 'success'); return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated: return redirect(url_for('index'))
    if request.method == 'POST':
        if not verify_captcha(request.form.get('captcha_response')):
            flash('人机验证失败，请重试。', 'danger'); return render_template('login.html')
        user = User.get_by_username(request.form['username'])
        if user and check_password_hash(user.password_hash, request.form['password']):
            login_user(user); flash('登录成功', 'success'); return redirect(url_for('index'))
        else: flash('用户名或密码错误', 'danger')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user(); flash('已登出'); return redirect(url_for('login'))

@app.route('/upload', methods=['GET', 'POST'])
@login_required
def upload():
    db = get_db()
    if request.method == 'POST':
        if not current_user.is_admin:
            twenty_four_hours_ago = datetime.now() - timedelta(days=1)
            upload_count = db.execute("SELECT COUNT(*) FROM upload_logs WHERE user_id = ? AND upload_time > ?", (current_user.id, twenty_four_hours_ago)).fetchone()[0]
            if upload_count >= app.config['USER_UPLOAD_LIMIT_PER_DAY']:
                flash(f"您今日上传已达上限 ({app.config['USER_UPLOAD_LIMIT_PER_DAY']}个)，请明天再试。", 'danger'); return redirect(url_for('upload'))
            main_file_check = request.files.get('file')
            if main_file_check and main_file_check.filename and not allowed_file(main_file_check.filename):
                flash(f"文件类型无效。只允许上传以下类型的文件: {', '.join(app.config['ALLOWED_EXTENSIONS'])}", 'danger'); return redirect(url_for('upload'))
        form, files = request.form, request.files
        main_file, proof_files = files.get('file'), files.getlist('proof_files')
        if not form.get('folder_id') or not main_file or not main_file.filename:
            flash('必须选择文件夹和主文件。'); return redirect(request.url)
        main_filename = f"{int(datetime.now().timestamp())}_{secure_filename(main_file.filename)}"
        main_file.save(os.path.join(app.config['UPLOAD_FOLDER'], main_filename))
        is_admin, uploader_id = current_user.is_admin, current_user.id
        status, upload_type = ('approved', 'admin') if is_admin else ('pending', 'user')
        login_required_flag = 1 if form.get('login_required') == 'on' else 0
        bilibili_link = form.get('bilibili_link', '').strip()
        cursor = db.cursor()
        cursor.execute('INSERT INTO files (filename, folder_id, title, version, description, uploader_id, status, upload_type, login_required, bilibili_link, approve_time) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',(main_filename, form.get('folder_id'), form.get('title'), form.get('version'), form.get('description'), uploader_id, status, upload_type, login_required_flag, bilibili_link, datetime.now() if is_admin else None))
        new_file_id = cursor.lastrowid
        for proof_file in proof_files:
            if proof_file and proof_file.filename:
                # 生成 .webp 文件名
                base_filename = f"{int(datetime.now().timestamp())}_{os.path.splitext(secure_filename(proof_file.filename))[0]}"
                webp_filename = f"{base_filename}.webp"
                
                try:
                    img = Image.open(proof_file.stream)
                    # 转换为RGB模式以确保可以保存为WebP
                    if img.mode in ("RGBA", "P"):
                        img = img.convert("RGB")
                    
                    img.save(os.path.join(app.config['PROOF_FOLDER'], webp_filename), 'WEBP', quality=80)
                    db.execute('INSERT INTO proof_images (file_id, filename) VALUES (?, ?)', (new_file_id, webp_filename))
                except Exception as e:
                    flash(f"凭证图片 '{proof_file.filename}' 转换WebP失败: {e}", "danger")

        if not is_admin: db.execute('INSERT INTO upload_logs (user_id) VALUES (?)', (uploader_id,))
        db.commit()
        flash('上传成功，等待管理员审核' if not is_admin else '作为管理员，您的文件已直接发布！', 'success' if is_admin else 'info')
        return redirect(url_for('index'))
    folders = db.execute('SELECT id, name FROM folders ORDER BY name').fetchall()
    return render_template('upload.html', folders=folders, allowed_extensions=app.config['ALLOWED_EXTENSIONS'])

@app.route('/myfiles')
@login_required
def my_files():
    files = get_db().execute("SELECT f.*, fo.name as folder_name FROM files f LEFT JOIN folders fo ON f.folder_id = fo.id WHERE f.uploader_id = ? ORDER BY f.upload_time DESC", (current_user.id,)).fetchall()
    return render_template('myfiles.html', files=files)

@app.route('/myfiles/edit/<int:file_id>', methods=['GET', 'POST'])
@login_required
def edit_my_file(file_id):
    db = get_db()
    query, params = 'SELECT * FROM files WHERE id=?', (file_id,)
    if not current_user.is_admin:
        query += ' AND uploader_id=?'
        params += (current_user.id,)
    file = db.execute(query, params).fetchone()
    if not file: abort(404)
    if request.method == 'POST':
        form = request.form
        login_required_flag = 1 if form.get('login_required') == 'on' else 0
        db.execute('UPDATE files SET title=?, version=?, description=?, bilibili_link=?, login_required=? WHERE id=?',(form['title'], form['version'], form['description'], form['bilibili_link'], login_required_flag, file_id))
        db.commit()
        flash('文件信息已更新')
        if current_user.is_admin and request.referrer and 'admin/all_files' in request.referrer:
            return redirect(url_for('admin_all_files'))
        return redirect(url_for('my_files'))
    return render_template('edit_myfile.html', file=file)

@app.route('/myfiles/delete/<int:file_id>', methods=['POST'])
@login_required
def delete_my_file(file_id):
    db = get_db()
    query, params = 'SELECT * FROM files WHERE id=?', (file_id,)
    if not current_user.is_admin:
        query += ' AND uploader_id=?'
        params += (current_user.id,)
    file = db.execute(query, params).fetchone()
    if not file:
        flash('文件不存在或无权删除。', 'danger'); return redirect(request.referrer or url_for('index'))
    proofs = db.execute('SELECT filename FROM proof_images WHERE file_id=?', (file_id,)).fetchall()
    db.execute('DELETE FROM files WHERE id=?', (file_id,)); db.commit()
    try: os.remove(os.path.join(app.config['UPLOAD_FOLDER'], file['filename']))
    except OSError: pass
    for proof in proofs:
        try: os.remove(os.path.join(app.config['PROOF_FOLDER'], proof['filename']))
        except OSError: pass
    flash('文件已成功删除'); return redirect(request.referrer or url_for('my_files'))

# --- 管理员路由 ---
@app.route('/admin')
@admin_required
def admin_dashboard():
    db = get_db()
    total_downloads = db.execute("SELECT SUM(download_count) FROM files").fetchone()[0] or 0
    return render_template('admin/dashboard.html', total_downloads=total_downloads)

# --- 分区管理 ---
@app.route('/admin/partitions', methods=['GET', 'POST'])
@admin_required
def admin_partitions():
    db = get_db()
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        slug = request.form.get('slug', '').strip()
        display_order = request.form.get('display_order', 0, type=int)
        if not name or not slug:
            flash('分区名称和URL标识(slug)不能为空。', 'danger')
        elif db.execute('SELECT id FROM partitions WHERE name = ?', (name,)).fetchone():
            flash('该分区名称已存在。', 'danger')
        elif db.execute('SELECT id FROM partitions WHERE slug = ?', (slug,)).fetchone():
            flash('该URL标识(slug)已存在。', 'danger')
        else:
            db.execute('INSERT INTO partitions (name, slug, display_order) VALUES (?, ?, ?)', (name, slug, display_order))
            db.commit()
            flash('新分区已添加。', 'success')
        return redirect(url_for('admin_partitions'))
    
    partitions = db.execute('SELECT * FROM partitions ORDER BY display_order, name').fetchall()
    return render_template('admin/partitions.html', partitions=partitions)

@app.route('/admin/partitions/edit/<int:partition_id>', methods=['GET', 'POST'])
@admin_required
def admin_edit_partition(partition_id):
    db = get_db()
    partition = db.execute('SELECT * FROM partitions WHERE id = ?', (partition_id,)).fetchone()
    if not partition:
        abort(404)

    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        slug = request.form.get('slug', '').strip()
        display_order = request.form.get('display_order', 0, type=int)
        
        if not name or not slug:
            flash('分区名称和URL标识(slug)不能为空。', 'danger')
        else:
            db.execute('UPDATE partitions SET name = ?, slug = ?, display_order = ? WHERE id = ?',
                       (name, slug, display_order, partition_id))
            db.commit()
            flash('分区信息已更新。', 'success')
            return redirect(url_for('admin_partitions'))

    return render_template('admin/edit_partition.html', partition=partition)

@app.route('/admin/partitions/delete/<int:partition_id>', methods=['POST'])
@admin_required
def admin_delete_partition(partition_id):
    db = get_db()
    # 检查是否有分组属于此分区
    groups_in_partition = db.execute('SELECT COUNT(*) FROM groups WHERE partition_id = ?', (partition_id,)).fetchone()[0]
    if groups_in_partition > 0:
        flash('无法删除，因为仍有分组属于此分区。请先将这些分组移至其他分区。', 'danger')
        return redirect(url_for('admin_partitions'))
    
    db.execute('DELETE FROM partitions WHERE id = ?', (partition_id,))
    db.commit()
    flash('分区已删除。', 'success')
    return redirect(url_for('admin_partitions'))


@app.route('/admin/groups', methods=['GET', 'POST'])
@admin_required
def admin_groups():
    db = get_db()
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        display_order = request.form.get('display_order', 0, type=int)
        partition_id = request.form.get('partition_id', None, type=int)
        if not name:
            flash('分组名称不能为空。', 'danger')
        elif get_db().execute('SELECT id FROM groups WHERE name = ?', (name,)).fetchone():
            flash('该分组名称已存在。', 'danger')
        else:
            get_db().execute('INSERT INTO groups (name, display_order, partition_id) VALUES (?, ?, ?)', (name, display_order, partition_id))
            get_db().commit()
            flash('新分组已添加。', 'success')
        return redirect(url_for('admin_groups'))
    
    groups = db.execute('SELECT g.*, p.name as partition_name FROM groups g LEFT JOIN partitions p ON g.partition_id = p.id ORDER BY p.display_order, g.display_order, g.name').fetchall()
    partitions = db.execute('SELECT * FROM partitions ORDER BY display_order, name').fetchall()
    return render_template('admin/groups.html', groups=groups, partitions=partitions)

@app.route('/admin/groups/edit/<int:group_id>', methods=['GET', 'POST'])
@admin_required
def admin_edit_group(group_id):
    db = get_db()
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        display_order = request.form.get('display_order', 0, type=int)
        partition_id = request.form.get('partition_id', None, type=int)
        if not name:
            flash('分组名称不能为空。', 'danger')
        else:
            db.execute('UPDATE groups SET name = ?, display_order = ?, partition_id = ? WHERE id = ?', (name, display_order, partition_id, group_id))
            db.commit()
            flash('分组信息已更新。', 'success')
            return redirect(url_for('admin_groups'))
    
    group = db.execute('SELECT * FROM groups WHERE id=?', (group_id,)).fetchone()
    if not group: abort(404)
    partitions = db.execute('SELECT * FROM partitions ORDER BY display_order, name').fetchall()
    return render_template('admin/edit_group.html', group=group, partitions=partitions)

@app.route('/admin/groups/delete/<int:group_id>', methods=['POST'])
@admin_required
def admin_delete_group(group_id):
    get_db().execute('DELETE FROM groups WHERE id=?', (group_id,)); get_db().commit()
    flash('分组已删除。'); return redirect(url_for('admin_groups'))

@app.route('/admin/folders', methods=['GET', 'POST'])
@admin_required
def admin_folders():
    db = get_db()
    if request.method == 'POST':
        name, desc, g_id = request.form.get('name','').strip(), request.form.get('description','').strip(), request.form.get('group_id')
        group_id = int(g_id) if g_id else None
        if name:
            try: db.execute('INSERT INTO folders (name, description, group_id) VALUES (?, ?, ?)', (name, desc, group_id)); db.commit(); flash('文件夹已添加')
            except sqlite3.IntegrityError: flash('错误：该文件夹名称已存在。', 'danger')
        else: flash('文件夹名称不能为空。', 'warning')
        return redirect(url_for('admin_folders'))
    folders = db.execute("SELECT f.*, g.name as group_name FROM folders f LEFT JOIN groups g ON f.group_id = g.id ORDER BY g.display_order, f.name").fetchall()
    groups = db.execute('SELECT * FROM groups ORDER BY display_order, name').fetchall()
    return render_template('admin/folders.html', folders=folders, groups=groups)

@app.route('/admin/folders/edit/<int:folder_id>', methods=['GET', 'POST'])
@admin_required
def admin_edit_folder(folder_id):
    db = get_db()
    if request.method == 'POST':
        form = request.form
        name, desc, g_id = form.get('name','').strip(), form.get('description','').strip(), form.get('group_id')
        group_id = int(g_id) if g_id else None
        if not name: flash('文件夹名称不能为空。', 'warning'); return redirect(url_for('admin_edit_folder', folder_id=folder_id))
        logo_file = request.files.get('logo_file')
        if logo_file and logo_file.filename:
            # 检查文件名是否为None
            filename = logo_file.filename
            if filename is None:
                flash('无效的文件名。', 'danger')
                return redirect(url_for('admin_edit_folder', folder_id=folder_id))
                
            old_logo = db.execute('SELECT logo_filename FROM folders WHERE id=?',(folder_id,)).fetchone()[0]
            
            # 生成 .webp 文件名
            base_filename = f"{int(datetime.now().timestamp())}_{os.path.splitext(secure_filename(filename))[0]}"
            webp_filename = f"{base_filename}.webp"
            
            try:
                img = Image.open(logo_file.stream)
                img.thumbnail(app.config['LOGO_SIZE'], Image.Resampling.LANCZOS)
                
                # 转换为RGB模式以确保可以保存为WebP
                if img.mode in ("RGBA", "P"):
                    img = img.convert("RGB")
                    
                img.save(os.path.join(app.config['LOGO_FOLDER'], webp_filename), 'WEBP', quality=85)
                
                db.execute('UPDATE folders SET logo_filename=? WHERE id=?', (webp_filename, folder_id))
                
                if old_logo:
                    try: os.remove(os.path.join(app.config['LOGO_FOLDER'], old_logo))
                    except OSError: pass
            except Exception as e: flash(f'Logo上传并转换为WebP失败: {e}', 'danger')
        db.execute('UPDATE folders SET name=?, description=?, group_id=? WHERE id=?', (name, desc, group_id, folder_id))
        db.commit(); flash('文件夹信息已更新'); return redirect(url_for('admin_folders'))
    folder = db.execute('SELECT * FROM folders WHERE id=?', (folder_id,)).fetchone()
    groups = db.execute('SELECT * FROM groups ORDER BY display_order, name').fetchall()
    if not folder: abort(404)
    return render_template('admin/edit_folder.html', folder=folder, groups=groups)

@app.route('/admin/folders/delete/<int:folder_id>', methods=['POST'])
@admin_required
def admin_delete_folder(folder_id):
    db = get_db()
    if db.execute('SELECT COUNT(*) FROM files WHERE folder_id=?', (folder_id,)).fetchone()[0] > 0:
        flash('请先删除该文件夹下的所有文件', 'warning'); return redirect(url_for('admin_folders'))
    logo = db.execute('SELECT logo_filename FROM folders WHERE id=?', (folder_id,)).fetchone()
    if logo and logo['logo_filename']:
        try: os.remove(os.path.join(app.config['LOGO_FOLDER'], logo['logo_filename']))
        except OSError: pass
    db.execute('DELETE FROM folders WHERE id=?', (folder_id,)); db.commit()
    flash('文件夹已删除'); return redirect(url_for('admin_folders'))

@app.route('/admin/review')
@admin_required
def admin_review():
    files = get_db().execute("SELECT f.*, u.username, fo.name as folder_name FROM files f LEFT JOIN users u ON f.uploader_id = u.id LEFT JOIN folders fo ON f.folder_id = fo.id WHERE f.status = 'pending' AND f.upload_type = 'user'").fetchall()
    return render_template('admin/review.html', files=files)

@app.route('/admin/review/<int:file_id>/<action>')
@admin_required
def admin_review_action(file_id, action):
    if action not in ['approve', 'reject']: abort(400)
    db = get_db()
    status = 'approved' if action == 'approve' else 'rejected'
    if status == 'approved': db.execute("UPDATE files SET status=?, approve_time=CURRENT_TIMESTAMP WHERE id=?", (status, file_id))
    else: db.execute('UPDATE files SET status=? WHERE id=?', (status, file_id))
    db.commit()
    flash(f'文件已{"通过" if status == "approved" else "拒绝"}'); return redirect(url_for('admin_review'))

@app.route('/admin/all_files')
@admin_required
def admin_all_files():
    files = get_db().execute("SELECT f.*, u.username, fo.name as folder_name FROM files f LEFT JOIN users u ON f.uploader_id = u.id LEFT JOIN folders fo ON f.folder_id = fo.id ORDER BY f.upload_time DESC").fetchall()
    return render_template('admin/all_files.html', files=files)

@app.route('/admin/settings', methods=['GET', 'POST'])
@admin_required
def admin_settings():
    db = get_db()
    if request.method == 'POST':
        form_data = request.form
        db.execute('UPDATE settings SET value = ? WHERE key = ?', (form_data.get('footer_text', ''), 'footer_text'))
        
        # 使用辅助函数处理动态链接
        db.execute('UPDATE settings SET value = ? WHERE key = ?', (_parse_dynamic_links_from_form('announcement', form_data), 'announcements'))
        db.execute('UPDATE settings SET value = ? WHERE key = ?', (_parse_dynamic_links_from_form('contact', form_data), 'contact_links'))
        db.execute('UPDATE settings SET value = ? WHERE key = ?', (_parse_dynamic_links_from_form('related', form_data), 'related_links'))
        db.execute('UPDATE settings SET value = ? WHERE key = ?', (_parse_dynamic_links_from_form('friend', form_data), 'friend_links'))
        
        db.commit()
        flash('网站设置已更新', 'success')
        return redirect(url_for('admin_settings'))
    return render_template('admin/settings.html')

@app.route('/admin/files/delete/<int:file_id>', methods=['POST'])
@admin_required
def admin_delete_file(file_id):
    db = get_db()
    file = db.execute('SELECT * FROM files WHERE id=?', (file_id,)).fetchone()
    if not file:
        flash('文件不存在。', 'danger')
        return redirect(request.referrer or url_for('admin_review'))
    proofs = db.execute('SELECT filename FROM proof_images WHERE file_id=?', (file_id,)).fetchall()
    db.execute('DELETE FROM files WHERE id=?', (file_id,))
    db.commit()
    try:
        os.remove(os.path.join(app.config['UPLOAD_FOLDER'], file['filename']))
    except OSError:
        pass
    for proof in proofs:
        try:
            os.remove(os.path.join(app.config['PROOF_FOLDER'], proof['filename']))
        except OSError:
            pass
    flash('文件已成功删除', 'success')
    return redirect(request.referrer or url_for('admin_review'))

@app.route('/batch_download', methods=['POST'])
def batch_download():
    file_ids = request.form.getlist('file_ids')
    if not file_ids:
        flash('没有选择任何文件。', 'warning')
        return redirect(request.referrer or url_for('index'))

    db = get_db()
    files_to_zip = []
    for file_id in file_ids:
        file = db.execute("SELECT * FROM files WHERE id=? AND status='approved'", (file_id,)).fetchone()
        
        # Allow admin to download any file
        if not file and current_user.is_authenticated and current_user.is_admin:
            file = db.execute("SELECT * FROM files WHERE id=?", (file_id,)).fetchone()

        if not file:
            flash(f'文件ID {file_id} 无效或不可用。', 'warning')
            return redirect(request.referrer or url_for('index'))
        
        if file['login_required'] and not current_user.is_authenticated:
            flash('您需要登录才能下载其中一个或多个所选文件。', 'warning')
            return redirect(url_for('login', next=request.referrer))
            
        files_to_zip.append(file)

    if not files_to_zip:
        flash('没有找到有效的文件进行下载。', 'warning')
        return redirect(request.referrer or url_for('index'))

    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zip_file:
        for file_data in files_to_zip:
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], file_data['filename'])
            if os.path.exists(file_path):
                zip_file.write(file_path, arcname=file_data['filename'])
                db.execute('UPDATE files SET download_count = download_count + 1 WHERE id = ?', (file_data['id'],))
            else:
                print(f"警告: 在打包下载时，文件在磁盘上未找到: {file_path}")
    
    db.commit()
    zip_buffer.seek(0)

    zip_filename = f"batch_download_{datetime.now().strftime('%Y%m%d%H%M%S')}.zip"
    
    return send_file(
        zip_buffer,
        as_attachment=True,
        download_name=zip_filename,
        mimetype='application/zip'
    )

# ==============================================================================
# 6. 应用启动
# ==============================================================================
if __name__ == '__main__':
    for folder in [app.config['UPLOAD_FOLDER'], app.config['LOGO_FOLDER'], app.config['PROOF_FOLDER']]:
        if not os.path.exists(folder): os.makedirs(folder)
    init_db()
    app.run(debug=True, host='0.0.0.0', port=5000)
