import os
from flask import Flask, request, jsonify, render_template_string, session, redirect, url_for
import psycopg2
from functools import wraps
from datetime import datetime

app = Flask(__name__)
app.secret_key = "tbims_super_secret_admin_key"

DATABASE_URL = os.environ.get("DATABASE_URL", "")

def get_db_connection():
    return psycopg2.connect(DATABASE_URL)

@app.before_request
def setup_db():
    app.before_request_funcs[None].remove(setup_db)
    if not DATABASE_URL: return
    conn = get_db_connection()
    cur = conn.cursor()
    
    # Tạo bảng Users
    cur.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            username VARCHAR(50) UNIQUE NOT NULL,
            password VARCHAR(255) NOT NULL,
            hwid VARCHAR(255),
            app_id VARCHAR(50),
            status VARCHAR(20) DEFAULT 'ACTIVE',
            exp_date VARCHAR(50) DEFAULT 'Chưa duyệt',
            is_admin BOOLEAN DEFAULT FALSE,
            reg_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    # Tạo bảng Config
    cur.execute('''
        CREATE TABLE IF NOT EXISTS config (
            key_name VARCHAR(50) PRIMARY KEY,
            key_value TEXT
        )
    ''')
    cur.execute("INSERT INTO config (key_name, key_value) VALUES ('version', '1.0'), ('notice', 'Chào mừng!') ON CONFLICT DO NOTHING")
    
    conn.commit()
    cur.close()
    conn.close()

@app.route('/api/config', methods=['GET'])
def get_config():
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT key_name, key_value FROM config")
    cfg = dict(cur.fetchall())
    cur.close()
    conn.close()
    return jsonify(cfg), 200

@app.route('/api/register', methods=['POST'])
def register():
    data = request.json
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute('INSERT INTO users (username, password, app_id, hwid) VALUES (%s, %s, %s, %s)',
                    (data.get('username'), data.get('password'), data.get('app_id'), ''))
        conn.commit()
        cur.close()
        conn.close()
        return jsonify({"status": "SUCCESS", "detail": "Đăng ký thành công! Chờ Admin duyệt."}), 200
    except psycopg2.errors.UniqueViolation:
        return jsonify({"detail": "Tài khoản này đã tồn tại!"}), 400
    except Exception as e:
        return jsonify({"detail": f"Lỗi Server: {str(e)}"}), 400


@app.route('/api/login', methods=['POST'])
def login():
    data = request.json
    username = data.get('username')
    password = data.get('password')
    client_hwid = data.get('hwid')

    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute('SELECT password, status, exp_date, is_admin, hwid FROM users WHERE username = %s', (username,))
        user = cur.fetchone()

        if user:
            db_pass, status, exp_date, is_admin, db_hwid = user
            
            if password != db_pass: 
                return jsonify({"detail": "Sai mật khẩu!"}), 400
            
            if is_admin: 
                return jsonify({"status": status, "exp_date": exp_date, "is_admin": True}), 200

            exp_str = str(exp_date).strip().lower()
            if 'chưa' in exp_str or 'duyệt' in exp_str:
                return jsonify({"detail": "Tài khoản đang chờ duyệt! Vui lòng liên hệ Admin."}), 400

            if exp_str != 'vĩnh viễn':
                try:
                    exp_dt = datetime.strptime(str(exp_date).strip(), '%d/%m/%Y')
                    if datetime.now() > exp_dt:
                        return jsonify({"detail": f"Tài khoản của bạn đã hết hạn từ ngày {exp_date}!"}), 400
                except ValueError:
                    pass

            if not db_hwid or db_hwid.strip() == '':
                cur.execute('UPDATE users SET hwid = %s WHERE username = %s', (client_hwid, username))
                conn.commit()
            elif db_hwid != client_hwid:
                return jsonify({"detail": "Sai mã máy tính (HWID)! Hãy liên hệ Admin."}), 400

            if status != 'ACTIVE': 
                return jsonify({"detail": "Tài khoản của bạn đã bị KHÓA!"}), 400
            
            return jsonify({"status": status, "exp_date": exp_date, "is_admin": False}), 200
        else:
            return jsonify({"detail": "Tài khoản không tồn tại!"}), 400
    except Exception as e:
        return jsonify({"detail": f"Lỗi Server: {str(e)}"}), 400
    finally:
        if 'cur' in locals(): cur.close()
        if 'conn' in locals(): conn.close()


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'admin_logged_in' not in session: return redirect(url_for('admin_login'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        user, pwd = request.form['username'], request.form['password']
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT is_admin FROM users WHERE username = %s AND password = %s", (user, pwd))
        res = cur.fetchone()
        cur.close()
        conn.close()
        if res and res[0] is True:
            session['admin_logged_in'], session['admin_username'] = user
            return redirect(url_for('admin_dashboard'))
        return render_template_string(LOGIN_HTML, error="Sai tài khoản hoặc không đủ quyền!")
    return render_template_string(LOGIN_HTML, error=None)

@app.route('/admin/logout')
def admin_logout():
    session.clear()
    return redirect(url_for('admin_login'))

@app.route('/admin')
@login_required
def admin_dashboard():
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT id, username, hwid, status, exp_date, is_admin, TO_CHAR(reg_date, 'DD/MM/YYYY'), app_id, password FROM users ORDER BY id DESC")
    users = cur.fetchall()
    cur.execute("SELECT key_name, key_value FROM config")
    cfg = dict(cur.fetchall())
    cur.close()
    conn.close()
    return render_template_string(DASHBOARD_HTML, users=users, admin_name=session.get('admin_username'), cfg=cfg)

@app.route('/admin/sys_action', methods=['POST'])
@login_required
def sys_action():
    action = request.form.get('action')
    val = request.form.get('value')
    conn = get_db_connection()
    cur = conn.cursor()
    if action == 'version': cur.execute("UPDATE config SET key_value = %s WHERE key_name = 'version'", (val,))
    if action == 'notice': cur.execute("UPDATE config SET key_value = %s WHERE key_name = 'notice'", (val,))
    conn.commit()
    cur.close()
    conn.close()
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/user_action', methods=['POST'])
@login_required
def user_action():
    uid = request.form.get('user_id')
    act = request.form.get('action')
    val = request.form.get('value', '')

    conn = get_db_connection()
    cur = conn.cursor()
    if act == 'reset_hwid': cur.execute("UPDATE users SET hwid = '' WHERE id = %s", (uid,))
    elif act == 'lifetime': cur.execute("UPDATE users SET exp_date = 'Vĩnh viễn', status='ACTIVE' WHERE id = %s", (uid,))
    elif act == 'lock': cur.execute("UPDATE users SET status = 'LOCKED' WHERE id = %s", (uid,))
    elif act == 'unlock': cur.execute("UPDATE users SET status = 'ACTIVE' WHERE id = %s", (uid,))
    elif act == 'delete': cur.execute("DELETE FROM users WHERE id = %s", (uid,))
    elif act == 'extend': cur.execute("UPDATE users SET exp_date = %s, status='ACTIVE' WHERE id = %s", (val, uid))
    elif act == 'change_pass': cur.execute("UPDATE users SET password = %s WHERE id = %s", (val, uid))
    
    conn.commit()
    cur.close()
    conn.close()
    return redirect(url_for('admin_dashboard'))

LOGIN_HTML = """
<!DOCTYPE html>
<html lang="vi" data-bs-theme="dark">
<head>
    <meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login Admin</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body class="d-flex align-items-center vh-100 bg-black">
    <div class="container"><div class="row justify-content-center"><div class="col-12 col-md-5 col-lg-4">
        <div class="card shadow border-secondary">
            <div class="card-body p-4">
                <h4 class="text-center text-info fw-bold mb-4">ADMIN C-PANEL</h4>
                {% if error %}<div class="alert alert-danger py-2">{{ error }}</div>{% endif %}
                <form method="POST">
                    <input type="text" name="username" class="form-control mb-3 bg-dark text-white" placeholder="Tài khoản" required>
                    <input type="password" name="password" class="form-control mb-4 bg-dark text-white" placeholder="Mật khẩu" required>
                    <button type="submit" class="btn btn-info w-100 fw-bold">VÀO HỆ THỐNG</button>
                </form>
            </div>
        </div>
    </div></div></div>
</body>
</html>
"""

DASHBOARD_HTML = """
<!DOCTYPE html>
<html lang="vi" data-bs-theme="dark">
<head>
    <meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Quản Lý Tài Khoản</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        body { background-color: #121212; color: #e0e0e0; }
        .table-dark { --bs-table-bg: #1e1e1e; }
        .btn-xs { padding: 0.1rem 0.4rem; font-size: 0.8rem; margin: 2px; }
        th { color: #0dcaf0 !important; }
        .eye-btn { cursor: pointer; background: none; border: none; font-size: 1.1rem; padding: 0; outline: none; }
        .eye-btn:hover { opacity: 0.7; }
    </style>
</head>
<body>
    <nav class="navbar navbar-dark bg-dark border-bottom border-secondary mb-3">
        <div class="container-fluid px-4">
            <span class="navbar-brand fw-bold text-info">QUẢN LÝ TÀI KHOẢN KHÁCH HÀNG</span>
            <div>
                <span class="me-3">Admin: <b class="text-warning">{{ admin_name }}</b></span>
                <a href="/admin/logout" class="btn btn-sm btn-outline-danger">Thoát</a>
            </div>
        </div>
    </nav>

    <div class="container-fluid px-4">
        <div class="row mb-3 g-2">
            <div class="col-md-3">
                <input type="text" id="searchInput" class="form-control bg-dark text-white" placeholder="🔍 Tìm khách hàng, App ID...">
            </div>
            <div class="col-md-9 d-flex gap-2 flex-wrap">
                <button onclick="location.reload()" class="btn btn-secondary">🔄 TẢI LẠI</button>
                <form action="/admin/sys_action" method="POST" class="d-inline d-flex gap-1">
                    <input type="hidden" name="action" value="version">
                    <input type="text" name="value" value="{{ cfg.version }}" class="form-control bg-dark text-white" style="width:100px;">
                    <button type="submit" class="btn btn-success">UP PHIÊN BẢN</button>
                </form>
                <form action="/admin/sys_action" method="POST" class="d-inline d-flex gap-1">
                    <input type="hidden" name="action" value="notice">
                    <input type="text" name="value" value="{{ cfg.notice }}" class="form-control bg-dark text-white" style="width:250px;">
                    <button type="submit" class="btn btn-warning text-dark fw-bold">THÔNG BÁO</button>
                </form>
            </div>
        </div>

        <div class="table-responsive border border-secondary rounded">
            <table class="table table-dark table-hover table-bordered align-middle mb-0" id="userTable">
                <thead>
                    <tr class="text-center text-nowrap">
                        <th>Tài khoản</th>
                        <th>Mật Khẩu</th>
                        <th>App ID</th>
                        <th>Mã Máy (HWID)</th>
                        <th>Ngày Đăng Ký</th>
                        <th>Ngày Hết Hạn</th>
                        <th>Trạng Thái</th>
                        <th>Chức Năng Điều Khiển</th>
                    </tr>
                </thead>
                <tbody>
                    {% for u in users %}
                    <tr class="text-center">
                        <td class="fw-bold {% if u[5] %}text-warning{% else %}text-light{% endif %}">
                            {{ u[1] }} {% if u[5] %}(Admin){% endif %}
                        </td>
                        
                        <td>
                            <div class="d-flex align-items-center justify-content-center gap-2">
                                <span id="pwd_mask_{{ u[0] }}" class="text-muted">••••••••</span>
                                <span id="pwd_text_{{ u[0] }}" class="text-warning fw-bold" style="display: none;">{{ u[8] }}</span>
                                <button class="eye-btn text-light" onclick="togglePwd({{ u[0] }})" title="Xem/Ẩn Mật Khẩu">👁️</button>
                            </div>
                        </td>
                        
                        <td><span class="badge bg-secondary">{{ u[7] if u[7] else 'Trống' }}</span></td>
                        <td><small class="text-muted">{{ u[2][:20] if u[2] else 'Chưa gắn' }}...</small></td>
                        <td>{{ u[6] }}</td>
                        <td class="fw-bold text-info">{{ u[4] }}</td>
                        <td>
                            {% if u[3] == 'ACTIVE' %}<span class="badge bg-success">Hoạt động</span>
                            {% else %}<span class="badge bg-danger">Khóa mõm</span>{% endif %}
                        </td>
                        <td class="text-nowrap">
                            <form action="/admin/user_action" method="POST" class="d-inline">
                                <input type="hidden" name="user_id" value="{{ u[0] }}">
                                
                                <button type="submit" name="action" value="lifetime" class="btn btn-xs btn-warning text-dark fw-bold">VĨNH VIỄN</button>
                                <button type="submit" name="action" value="reset_hwid" class="btn btn-xs btn-info text-dark fw-bold">RESET HWID</button>
                                
                                {% if u[3] == 'ACTIVE' %}
                                    <button type="submit" name="action" value="lock" class="btn btn-xs btn-danger">KHÓA MÕM</button>
                                {% else %}
                                    <button type="submit" name="action" value="unlock" class="btn btn-xs btn-success">MỞ KHÓA</button>
                                {% endif %}
                                
                                <button type="button" class="btn btn-xs btn-primary" onclick="promptExtend({{ u[0] }}, '{{ u[4] }}')">GIA HẠN</button>
                                <button type="button" class="btn btn-xs btn-secondary" onclick="promptPass({{ u[0] }})">ĐỔI PASS</button>
                                
                                <button type="submit" name="action" value="delete" class="btn btn-xs btn-outline-danger" onclick="return confirm('XÓA VĨNH VIỄN khách {{ u[1] }}?');">XÓA KHÁCH</button>
                            </form>
                        </td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
        </div>
    </div>

    <form id="actionForm" action="/admin/user_action" method="POST" style="display:none;">
        <input type="hidden" name="user_id" id="form_uid">
        <input type="hidden" name="action" id="form_act">
        <input type="hidden" name="value" id="form_val">
    </form>

    <script>
        function togglePwd(id) {
            let mask = document.getElementById('pwd_mask_' + id);
            let text = document.getElementById('pwd_text_' + id);
            if (text.style.display === 'none') {
                text.style.display = 'inline';
                mask.style.display = 'none';
            } else {
                text.style.display = 'none';
                mask.style.display = 'inline';
            }
        }

        document.getElementById('searchInput').addEventListener('keyup', function() {
            let filter = this.value.toLowerCase();
            let rows = document.querySelectorAll('#userTable tbody tr');
            rows.forEach(row => {
                let text = row.innerText.toLowerCase();
                row.style.display = text.includes(filter) ? '' : 'none';
            });
        });

        function promptExtend(uid, oldDate) {
            let newDate = prompt("Nhập hạn sử dụng mới (VD: 30/12/2026):", oldDate);
            if (newDate) submitAction(uid, 'extend', newDate);
        }

        function promptPass(uid) {
            let newPass = prompt("Nhập mật khẩu mới cho khách này:");
            if (newPass) submitAction(uid, 'change_pass', newPass);
        }

        function submitAction(uid, act, val) {
            document.getElementById('form_uid').value = uid;
            document.getElementById('form_act').value = act;
            document.getElementById('form_val').value = val;
            document.getElementById('actionForm').submit();
        }
        
        // --- CHỐNG NGỦ GẬT CHO RENDER ---
        setInterval(function() {
            fetch('/api/config').then(response => {
                console.log("Đã chọc Server thức dậy lúc: " + new Date().toLocaleTimeString());
            }).catch(err => console.log(err));
        }, 840000);
    </script>
</body>
</html>
"""
@app.route('/tao_admin')
def tao_admin():
    conn = get_db_connection()
    cur = conn.cursor()
    # Lệnh này tự động tạo mới nick TrangTbims, hoặc nếu nick đã có thì ép lên Admin
    cur.execute("""
        INSERT INTO users (username, password, is_admin, status, exp_date, hwid, app_id) 
        VALUES ('TrangTbims', '22121998', TRUE, 'ACTIVE', 'Vĩnh viễn', '', 'TBIMS_Voice') 
        ON CONFLICT (username) 
        DO UPDATE SET is_admin = TRUE, password = '22121998', status = 'ACTIVE', exp_date = 'Vĩnh viễn'
    """)
    conn.commit()
    cur.close()
    conn.close()
    return "<h1 style='color: green;'>ĐÃ TẠO ADMIN TrangTbims THÀNH CÔNG!</h1><p>Bác hãy quay lại trang /admin để đăng nhập nhé.</p>"
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
