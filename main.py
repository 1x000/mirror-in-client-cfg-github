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
from wordcloud import WordCloud
import jieba
from functools import wraps
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
        cursor.execute('CREATE TABLE IF NOT EXISTS groups (id INTEGER PRIMARY KEY, name TEXT UNIQUE NOT NULL, display_order INTEGER DEFAULT 0)')
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



@app.route('/wordcloud.png')
def wordcloud_image():
    db = get_db()
    text_data = db.execute("SELECT title, description FROM files WHERE status='approved'").fetchall()
    full_text = ' '.join(item for row in text_data for item in row if item and item.strip())
    if not full_text:
        img = Image.new('RGB', (800, 400), color='white')
        d = ImageDraw.Draw(img); d.text((300, 180), "暂无数据生成词云", fill='gray')
        return _serve_pil_image(img)
    word_list = [word for word in jieba.cut(full_text, cut_all=False) if len(word) > 1 and not word.isdigit()]
    text = " ".join(word_list)
    if not text.strip():
        print(f"WordCloud Debug: Original text ('{full_text}') resulted in empty string after jieba processing.")
        img = Image.new('RGB', (800, 400), color='white')
        d = ImageDraw.Draw(img); d.text((300, 180), "暂无有效词语生成词云", fill='gray')
        return _serve_pil_image(img)
    try:
        wc = WordCloud(font_path=app.config['WORDCLOUD_FONT_PATH'], width=800, height=400, background_color='white', max_words=100).generate(text)
        img = wc.to_image()
    except ValueError as e:
        print(f"WordCloud Generation Error: {e}. Processed text: '{text}'")
        img = Image.new('RGB', (800, 400), color='white')
        d = ImageDraw.Draw(img); d.text((300, 180), "生成词云时出错", fill='orange')
    except OSError:
        img = Image.new('RGB', (800, 400), color='white')
        d = ImageDraw.Draw(img); d.text((250, 180), "错误: 找不到中文字体文件", fill='red')
    return _serve_pil_image(img)

@app.route('/placeholder/<text>')
def placeholder_image(text):
    char = text[0].upper() if text else '?'
    random.seed(char)
    color = (random.randint(100, 200), random.randint(100, 200), random.randint(100, 200))
    img = Image.new('RGB', (200, 200), color=color)
    draw = ImageDraw.Draw(img)
    try: font = ImageFont.truetype(app.config['WORDCLOUD_FONT_PATH'], 100)
    except IOError: font = ImageFont.load_default()
    text_bbox = draw.textbbox((0, 0), char, font=font)
    position = ((200 - (text_bbox[2] - text_bbox[0])) / 2, (200 - (text_bbox[3] - text_bbox[1])) / 2 - 10)
    draw.text(position, char, fill='white', font=font)
    return _serve_pil_image(img)

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

# ==============================================================================
# 5. 视图函数 (路由)
# ==============================================================================
@app.context_processor
def inject_settings():
    db = get_db()
    settings_raw = db.execute('SELECT key, value FROM settings').fetchall()
    settings = {row['key']: row['value'] for row in settings_raw}
    try:
        settings['announcements'] = json.loads(settings.get('announcements', '[]'))
        settings['contact_links'] = json.loads(settings.get('contact_links', '[]'))
        settings['related_links'] = json.loads(settings.get('related_links', '[]'))
        settings['friend_links'] = json.loads(settings.get('friend_links', '[]'))
    except json.JSONDecodeError:
        settings['announcements'], settings['contact_links'], settings['related_links'], settings['friend_links'] = [], [], [], []
    return dict(site_settings=settings)

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
    all_folders = db.execute("SELECT f.*, g.name as group_name, g.display_order FROM folders f LEFT JOIN groups g ON f.group_id = g.id ORDER BY g.display_order, g.name, f.name").fetchall()
    return render_template('index.html', stats=stats, all_folders=all_folders)

@app.route('/folder/<int:folder_id>')
def folder_detail(folder_id):
    db = get_db()
    folder = db.execute('SELECT * FROM folders WHERE id=?', (folder_id,)).fetchone()
    if not folder: abort(404)
    all_approved_files_raw = db.execute("SELECT * FROM files WHERE folder_id=? AND status='approved' ORDER BY approve_time DESC", (folder_id,)).fetchall()
    admin_files, user_files = [], []
    for row in all_approved_files_raw:
        file_dict = dict(row)
        file_dict['formatted_date'] = 'N/A'
        if file_dict.get('approve_time'):
            try:
                time_str = file_dict['approve_time'].split('.')[0]
                file_dict['formatted_date'] = datetime.strptime(time_str, '%Y-%m-%d %H:%M:%S').strftime('%b %d, %Y')
            except (ValueError, TypeError): pass
        (admin_files if file_dict['upload_type'] == 'admin' else user_files).append(file_dict)
    return render_template('folder.html', folder=folder, admin_files=admin_files, user_files=user_files)

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
    expired_tokens = [k for k, v in download_tokens.items() if v['expires'] < current_time]
    for k in expired_tokens: del download_tokens[k]
    token_data = download_tokens.pop(token, None)
    if token_data and token_data['expires'] >= current_time:
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
    if not query: return render_template('search_results.html', query=query, folders_results=[], files_results=[])
    search_term = f'%{query}%'
    db = get_db()
    folders = db.execute('SELECT * FROM folders WHERE name LIKE ? OR description LIKE ?', (search_term, search_term)).fetchall()
    files = db.execute("SELECT * FROM files WHERE (title LIKE ? OR description LIKE ? OR filename LIKE ? OR version LIKE ?) AND status = 'approved'", (search_term, search_term, search_term, search_term)).fetchall()
    return render_template('search_results.html', query=query, folders_results=folders, files_results=files)

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
                proof_filename = f"{int(datetime.now().timestamp())}_{secure_filename(proof_file.filename)}"
                proof_file.save(os.path.join(app.config['PROOF_FOLDER'], proof_filename))
                db.execute('INSERT INTO proof_images (file_id, filename) VALUES (?, ?)', (new_file_id, proof_filename))
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
    if not current_user.is_admin and file['status'] == 'approved':
        flash('已审核的文件不可编辑。', 'warning'); return redirect(url_for('my_files'))
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
    if not current_user.is_admin and file['status'] == 'approved':
        flash('已审核的文件不可删除。', 'warning'); return redirect(url_for('my_files'))
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

@app.route('/admin/groups', methods=['GET', 'POST'])
@admin_required
def admin_groups():
    db = get_db()
    if request.method == 'POST':
        name, order = request.form.get('name', '').strip(), request.form.get('display_order', 0, type=int)
        if name:
            try: db.execute('INSERT INTO groups (name, display_order) VALUES (?, ?)', (name, order)); db.commit()
            except sqlite3.IntegrityError: flash('错误：该分组名称已存在。', 'danger')
        else: flash('分组名称不能为空。', 'warning')
        return redirect(url_for('admin_groups'))
    groups = db.execute('SELECT * FROM groups ORDER BY display_order, name').fetchall()
    return render_template('admin/groups.html', groups=groups)

@app.route('/admin/groups/edit/<int:group_id>', methods=['GET', 'POST'])
@admin_required
def admin_edit_group(group_id):
    db = get_db()
    if request.method == 'POST':
        name, order = request.form.get('name', '').strip(), request.form.get('display_order', 0, type=int)
        if name:
            db.execute('UPDATE groups SET name=?, display_order=? WHERE id=?', (name, order, group_id)); db.commit(); flash('分组信息已更新')
        else: flash('分组名称不能为空。', 'warning')
        return redirect(url_for('admin_groups'))
    group = db.execute('SELECT * FROM groups WHERE id=?', (group_id,)).fetchone()
    if not group: abort(404)
    return render_template('admin/edit_group.html', group=group)

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
        if logo_file and logo_file.filename != '':
            old_logo = db.execute('SELECT logo_filename FROM folders WHERE id=?',(folder_id,)).fetchone()[0]
            filename = f"{int(datetime.now().timestamp())}_{secure_filename(logo_file.filename)}"
            try:
                img = Image.open(logo_file.stream); img.thumbnail(app.config['LOGO_SIZE'], Image.Resampling.LANCZOS); img.save(os.path.join(app.config['LOGO_FOLDER'], filename))
                db.execute('UPDATE folders SET logo_filename=? WHERE id=?', (filename, folder_id))
                if old_logo:
                    try: os.remove(os.path.join(app.config['LOGO_FOLDER'], old_logo))
                    except OSError: pass
            except Exception as e: flash(f'Logo上传失败: {e}', 'danger')
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
        db.execute('UPDATE settings SET value = ? WHERE key = ?', (request.form.get('footer_text', ''), 'footer_text'))
        def parse_from_form(prefix):
            items = []
            i = 0
            while True:
                text_key, url_key = f'{prefix}_text_{i}', f'{prefix}_url_{i}'
                date_key = f'{prefix}_date_{i}'
                if text_key not in request.form: break
                text = request.form[text_key]
                if text:
                    if prefix == 'announcement':
                        items.append({'date': request.form.get(date_key, ''), 'text': text})
                    else:
                         items.append({'text': text, 'url': request.form.get(url_key, '#')})
                i += 1
            return json.dumps(items)
        db.execute('UPDATE settings SET value = ? WHERE key = ?', (parse_from_form('announcement'), 'announcements'))
        db.execute('UPDATE settings SET value = ? WHERE key = ?', (parse_from_form('contact'), 'contact_links'))
        db.execute('UPDATE settings SET value = ? WHERE key = ?', (parse_from_form('related'), 'related_links'))
        db.execute('UPDATE settings SET value = ? WHERE key = ?', (parse_from_form('friend'), 'friend_links'))
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

# ==============================================================================
# 6. 应用启动
# ==============================================================================
if __name__ == '__main__':
    for folder in [app.config['UPLOAD_FOLDER'], app.config['LOGO_FOLDER'], app.config['PROOF_FOLDER']]:
        if not os.path.exists(folder): os.makedirs(folder)
    init_db()
    app.run(debug=True, host='0.0.0.0', port=5000)
