
import sqlite3
from flask import Flask, render_template_string, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps


app = Flask(__name__)
app.secret_key = 'super-secret-key-change-this-in-production'
DATABASE = 'app.db'


# --- DATABASE SETUP ---
def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with get_db() as conn:
        conn.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'user'
            )
        ''')
        # Seed an initial Admin account (Username: admin, Password: adminpassword)
        admin_exists = conn.execute('SELECT * FROM users WHERE username = ?', ('admin',)).fetchone()
        if not admin_exists:
            hashed_pw = generate_password_hash('adminpassword')
            conn.execute('INSERT INTO users (username, password, role) VALUES (?, ?, ?)',
                         ('admin', hashed_pw, 'admin'))
        conn.commit()


# --- AUTH DECORATORS ---
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in first.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function


def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session or session.get('role') != 'admin':
            flash('Access denied. Administrator privileges required.', 'danger')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function


# --- BOOTSTRAP UI TEMPLATES ---
NAVBAR = """
<nav class="navbar navbar-expand-lg navbar-dark bg-dark mb-4">
  <div class="container">
    <a class="navbar-brand" href="#">Flask Auth App</a>
    <div class="navbar-nav ms-auto">
      {% if session.user_id %}
        <span class="nav-link text-light me-3">Welcome, {{ session.username }} ({{ session.role }})</span>
        <a class="nav-link btn btn-outline-light btn-sm" href="{{ url_for('logout') }}">Logout</a>
      {% else %}
        <a class="nav-link" href="{{ url_for('login') }}">Login</a>
        <a class="nav-link" href="{{ url_for('register') }}">Register</a>
      {% endif %}
    </div>
  </div>
</nav>
"""


BASE_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Flask App</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body class="bg-light">
    """ + NAVBAR + """
    <div class="container">
        {% with messages = get_flashed_messages(with_categories=true) %}
          {% if messages %}
            {% for category, message in messages %}
              <div class="alert alert-{{ category }} alert-dismissible fade show" role="alert">
                {{ message }}
                <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
              </div>
            {% endfor %}
          {% endif %}
        {% endwith %}
       
        {% block content %}{% endblock %}
    </div>
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
"""


LOGIN_HTML = BASE_TEMPLATE.replace('{% block content %}{% endblock %}', """
<div class="row justify-content-center">
    <div class="col-md-4">
        <div class="card shadow-sm">
            <div class="card-body">
                <h3 class="card-title text-center mb-4">Login</h3>
                <form method="POST">
                    <div class="mb-3">
                        <label class="form-label">Username</label>
                        <input type="text" name="username" class="form-control" required>
                    </div>
                    <div class="mb-3">
                        <label class="form-label">Password</label>
                        <input type="password" name="password" class="form-control" required>
                    </div>
                    <button type="submit" class="btn btn-primary w-100">Login</button>
                </form>
                <div class="mt-3 text-center">
                    <small>Don't have an account? <a href="{{ url_for('register') }}">Register</a></small>
                </div>
            </div>
        </div>
    </div>
</div>
""")


REGISTER_HTML = BASE_TEMPLATE.replace('{% block content %}{% endblock %}', """
<div class="row justify-content-center">
    <div class="col-md-4">
        <div class="card shadow-sm">
            <div class="card-body">
                <h3 class="card-title text-center mb-4">Register</h3>
                <form method="POST">
                    <div class="mb-3">
                        <label class="form-label">Username</label>
                        <input type="text" name="username" class="form-control" required>
                    </div>
                    <div class="mb-3">
                        <label class="form-label">Password</label>
                        <input type="password" name="password" class="form-control" required>
                    </div>
                    <button type="submit" class="btn btn-success w-100">Register</button>
                </form>
                <div class="mt-3 text-center">
                    <small>Already registered? <a href="{{ url_for('login') }}">Login</a></small>
                </div>
            </div>
        </div>
    </div>
</div>
""")


DASHBOARD_HTML = BASE_TEMPLATE.replace('{% block content %}{% endblock %}', """
<div class="row">
    <div class="col-md-12">
        <div class="p-5 mb-4 bg-white rounded-3 shadow-sm">
            <div class="container-fluid py-3">
                <h1 class="display-5 fw-bold">User Dashboard</h1>
                <p class="col-md-8 fs-4">Welcome back, <strong>{{ session.username }}</strong>! Your current role is <span class="badge bg-secondary">{{ session.role }}</span>.</p>
                {% if session.role == 'admin' %}
                    <a href="{{ url_for('admin_panel') }}" class="btn btn-danger btn-lg">Go to Admin Panel</a>
                {% endif %}
            </div>
        </div>
    </div>
</div>
""")


ADMIN_HTML = BASE_TEMPLATE.replace('{% block content %}{% endblock %}', """
<div class="row">
    <div class="col-md-12">
        <div class="d-flex justify-content-between align-items-center mb-4">
            <h2>Admin Control Panel</h2>
            <a href="{{ url_for('dashboard') }}" class="btn btn-secondary">Back to Dashboard</a>
        </div>
        <div class="card shadow-sm">
            <div class="card-body">
                <h5 class="card-title mb-3">Registered Users</h5>
                <table class="table table-striped table-hover">
                    <thead class="table-dark">
                        <tr>
                            <th>ID</th>
                            <th>Username</th>
                            <th>Role</th>
                        </tr>
                    </thead>
                    <tbody>
                        {% for user in users %}
                        <tr>
                            <td>{{ user.id }}</td>
                            <td>{{ user.username }}</td>
                            <td><span class="badge {% if user.role == 'admin' %}bg-danger{% else %}bg-primary{% endif %}">{{ user.role }}</span></td>
                        </tr>
                        {% endfor %}
                    </tbody>
                </table>
            </div>
        </div>
    </div>
</div>
""")


# --- ROUTES ---
@app.route('/')
def home():
    return redirect(url_for('login'))


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']
        hashed_pw = generate_password_hash(password)


        conn = get_db()
        try:
            conn.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, hashed_pw))
            conn.commit()
            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Username already exists. Try another.', 'danger')
        finally:
            conn.close()


    return render_template_string(REGISTER_HTML)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']


        conn = get_db()
        user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        conn.close()


        if user and check_password_hash(user['password'], password):
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['role'] = user['role']
            flash('Logged in successfully.', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password.', 'danger')


    return render_template_string(LOGIN_HTML)


@app.route('/dashboard')
@login_required
def dashboard():
    return render_template_string(DASHBOARD_HTML)


@app.route('/admin')
@admin_required
def admin_panel():
    conn = get_db()
    users = conn.execute('SELECT id, username, role FROM users').fetchall()
    conn.close()
    return render_template_string(ADMIN_HTML, users=users)


@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))


if __name__ == '__main__':
    init_db()
    app.run(debug=True)


