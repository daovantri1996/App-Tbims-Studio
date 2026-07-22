import os
from flask import Flask, request, jsonify
import psycopg2

app = Flask(__name__)

# Lấy đường link kết nối Database (Lát nữa anh em mình lấy từ Neon.tech)
DATABASE_URL = os.environ.get("DATABASE_URL", "")

def get_db_connection():
    return psycopg2.connect(DATABASE_URL)

# Tự động tạo bảng lưu tài khoản nếu chưa có
@app.before_request
def setup_db():
    app.before_request_funcs[None].remove(setup_db)
    if not DATABASE_URL: return
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            username VARCHAR(50) UNIQUE NOT NULL,
            password VARCHAR(255) NOT NULL,
            hwid VARCHAR(255),
            app_id VARCHAR(50),
            status VARCHAR(20) DEFAULT 'ACTIVE',
            exp_date VARCHAR(20) DEFAULT 'Chưa duyệt',
            is_admin BOOLEAN DEFAULT FALSE
        )
    ''')
    conn.commit()
    cur.close()
    conn.close()

@app.route('/api/register', methods=['POST'])
def register():
    data = request.json
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute('INSERT INTO users (username, password, hwid, app_id) VALUES (%s, %s, %s, %s)',
                    (data.get('username'), data.get('password'), data.get('hwid'), data.get('app_id')))
        conn.commit()
        cur.close()
        conn.close()
        return jsonify({"status": "SUCCESS", "detail": "Đăng ký thành công! Vui lòng liên hệ Admin duyệt."}), 200
    except psycopg2.errors.UniqueViolation:
        return jsonify({"detail": "Tài khoản này đã tồn tại!"}), 400
    except Exception as e:
        return jsonify({"detail": f"Lỗi Server: {str(e)}"}), 400

@app.route('/api/login', methods=['POST'])
def login():
    data = request.json
    username = data.get('username')
    password = data.get('password')

    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute('SELECT password, status, exp_date, is_admin FROM users WHERE username = %s', (username,))
        user = cur.fetchone()
        cur.close()
        conn.close()

        if user:
            db_pass, status, exp_date, is_admin = user
            if password == db_pass:
                return jsonify({"status": status, "exp_date": exp_date, "is_admin": is_admin}), 200
            else:
                return jsonify({"detail": "Sai mật khẩu!"}), 400
        else:
            return jsonify({"detail": "Tài khoản không tồn tại!"}), 400
    except Exception as e:
        return jsonify({"detail": f"Lỗi Server: {str(e)}"}), 400

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
