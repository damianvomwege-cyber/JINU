from functools import wraps
from datetime import datetime
import sqlite3
import uuid
import ipaddress
from flask import (
    Flask,
    flash,
    g,
    redirect,
    jsonify,
    render_template,
    request,
    session,
    url_for,
)
from werkzeug.security import check_password_hash, generate_password_hash


app = Flask(__name__)
app.config['SECRET_KEY'] = 'change-me'
app.config['DB_PATH'] = 'app.db'
ALLOWED_HISTORY_CLEAR_IP = '127.0.0.1'
ALLOWED_HISTORY_CLEAR_IPS = {'127.0.0.1'}
ALLOWED_ROLES = ('lehrer', 'schueler', 'erwachsene')


def _normalize_ip(raw_ip):
    if not raw_ip:
        return None
    first = raw_ip.split(',')[0].strip()
    first = first.strip()
    if first.startswith('['):
        if first.endswith(']'):
            first = first[1:-1]
        elif ']:' in first:
            first = first[1:first.find(']')]
    return first.split('%')[0].strip()


def _client_ips():
    ip_candidates = []
    xff = request.headers.get('X-Forwarded-For')
    if xff:
        ip_candidates.extend([_normalize_ip(part) for part in xff.split(',') if _normalize_ip(part)])
    direct = _normalize_ip(request.remote_addr)
    if direct:
        ip_candidates.append(direct)
    return ip_candidates


def _normalize_role(role):
    return role.strip().lower()


def ensure_users_schema(db):
    info = db.execute(
        "SELECT sql FROM sqlite_master WHERE type='table' AND name='users'"
    ).fetchone()
    schema_sql = info['sql'] if info else ''
    has_phone = any(
        row['name'] == 'phone_number'
        for row in db.execute('PRAGMA table_info(users)').fetchall()
    )
    needs_role_migration = 'role IN (\'lehrer\', \'schueler\')' in schema_sql

    if not has_phone:
        db.execute('ALTER TABLE users ADD COLUMN phone_number TEXT')

    if needs_role_migration:
        db.execute('PRAGMA foreign_keys=off')
        db.execute('ALTER TABLE users RENAME TO users_old')
        db.execute(
            """
            CREATE TABLE users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL CHECK(role IN ('lehrer', 'schueler', 'erwachsene')),
                points INTEGER NOT NULL DEFAULT 0,
                phone_number TEXT,
                created_at TEXT NOT NULL
            )
            """
        )
        db.execute(
            """
            INSERT INTO users (id, username, password_hash, role, points, phone_number, created_at)
            SELECT id, username, password_hash, role, points, phone_number, created_at
            FROM users_old
            """
        )
        db.execute('DROP TABLE users_old')
        db.execute('PRAGMA foreign_keys=on')


def ensure_chat_schema(db):
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS chat_threads (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            teacher_id INTEGER NOT NULL,
            adult_id INTEGER NOT NULL,
            created_at TEXT NOT NULL,
            UNIQUE(teacher_id, adult_id),
            FOREIGN KEY (teacher_id) REFERENCES users (id),
            FOREIGN KEY (adult_id) REFERENCES users (id)
        )
        """
    )
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS chat_messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            thread_id INTEGER NOT NULL,
            sender_id INTEGER NOT NULL,
            message TEXT NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY (thread_id) REFERENCES chat_threads (id),
            FOREIGN KEY (sender_id) REFERENCES users (id)
        )
        """
    )


def ensure_custom_actions_schema(db):
    existing = db.execute(
        "SELECT sql FROM sqlite_master WHERE type='table' AND name='custom_actions'"
    ).fetchone()
    desired_sql = """
        CREATE TABLE custom_actions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            teacher_id INTEGER NOT NULL,
            action_key TEXT NOT NULL UNIQUE,
            label TEXT NOT NULL,
            icon TEXT NOT NULL,
            delta INTEGER NOT NULL CHECK(delta BETWEEN -5 AND 5 AND delta != 0),
            created_at TEXT NOT NULL,
            FOREIGN KEY (teacher_id) REFERENCES users (id)
        )
    """

    if not existing:
        db.execute(desired_sql)
        return

    if 'delta BETWEEN -5 AND 5' in existing['sql']:
        return

    # Migrate old schema (for existing local DBs that only had +/-1)
    db.execute("ALTER TABLE custom_actions RENAME TO custom_actions_old")
    db.execute(desired_sql)
    db.execute(
        """
        INSERT INTO custom_actions (id, teacher_id, action_key, label, icon, delta, created_at)
        SELECT
            id,
            teacher_id,
            action_key,
            label,
            icon,
            delta,
            created_at
        FROM custom_actions_old
        """
    )
    db.execute('DROP TABLE custom_actions_old')

POSITIVE_ACTIONS = [
    ('listening', 'Listening', 1, '🎧'),
    ('participation', 'Participation', 1, '🙋'),
    ('helpful', 'Helping others', 1, '🤝'),
    ('cleaning', 'Cleaning up', 1, '🧹'),
    ('homework', 'Submitted assignment', 1, '📝'),
    ('punctuality', 'On time', 1, '⏰'),
    ('good_focus', 'Good focus', 1, '🎯'),
    ('respectful', 'Respectful behavior', 1, '🌟'),
    ('teamwork', 'Teamwork', 1, '👥'),
    ('homework_done', 'Homework completed', 1, '✅'),
    ('good_progress', 'Good progress', 1, '📈'),
    ('great_effort', 'Great effort', 1, '💪'),
]

NEEDS_WORK_ACTIONS = [
    ('failure_to_listen', 'Failure to listen', -1, '👂'),
    ('talking_out', 'Talking out', -1, '💬'),
    ('late', 'Late to class', -1, '🕒'),
    ('not_prepared', 'Not prepared', -1, '📚'),
    ('inattentive', 'Inattentive', -1, '💤'),
    ('using_phone', 'Using phone', -1, '📱'),
    ('disruptive', 'Disruptive behavior', -1, '🚫'),
    ('disrespectful', 'Disrespectful language', -1, '🗣️'),
    ('unfinished_homework', 'Homework unfinished', -1, '🗂️'),
    ('not_focused', 'Not focused in class', -1, '🧠'),
    ('talking_back', 'Talking back', -1, '⚠️'),
    ('missing_materials', 'Missing materials', -1, '🎒'),
]

ACTION_LABELS = {key: label for key, label, _, _ in POSITIVE_ACTIONS + NEEDS_WORK_ACTIONS}
ICON_CHOICES = [
    '🎧',
    '🙋',
    '🤝',
    '🧹',
    '📝',
    '⏰',
    '🎯',
    '🌟',
    '👥',
    '✅',
    '📈',
    '💪',
    '👂',
    '💬',
    '🕒',
    '📚',
    '💤',
    '📱',
    '🚫',
    '🗣️',
    '🗂️',
    '🧠',
    '⚠️',
    '🎒',
    '🧠',
    '😄',
    '🏅',
    '🧩',
    '🎨',
    '📚',
    '🌈',
]


def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(app.config['DB_PATH'])
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(exc=None):
    db = g.pop('db', None)
    if db is not None:
        db.close()


def init_db():
    db = get_db()
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL CHECK(role IN ('lehrer', 'schueler', 'erwachsene')),
            points INTEGER NOT NULL DEFAULT 0,
            phone_number TEXT,
            created_at TEXT NOT NULL
        )
        """
    )
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS teacher_students (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            teacher_id INTEGER NOT NULL,
            student_id INTEGER NOT NULL,
            created_at TEXT NOT NULL,
            UNIQUE(teacher_id, student_id),
            FOREIGN KEY (teacher_id) REFERENCES users (id),
            FOREIGN KEY (student_id) REFERENCES users (id)
        )
        """
    )
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS point_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            teacher_id INTEGER NOT NULL,
            student_id INTEGER NOT NULL,
            action_key TEXT NOT NULL,
            points_delta INTEGER NOT NULL,
            points_after INTEGER NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY (teacher_id) REFERENCES users (id),
            FOREIGN KEY (student_id) REFERENCES users (id)
        )
        """
    )
    ensure_users_schema(db)
    ensure_chat_schema(db)
    ensure_custom_actions_schema(db)
    db.commit()


def current_user():
    user_id = session.get('user_id')
    if not user_id:
        return None
    db = get_db()
    return db.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()


def login_required(view):
    @wraps(view)
    def wrapped_view(*args, **kwargs):
        if not session.get('user_id'):
            return redirect(url_for('login'))
        return view(*args, **kwargs)

    return wrapped_view


def teacher_required(view):
    @wraps(view)
    def wrapped_view(*args, **kwargs):
        user = current_user()
        if not user:
            return redirect(url_for('login'))
        if user['role'] != 'lehrer':
            flash('Only teachers can assign points.')
            return redirect(url_for('dashboard'))
        return view(*args, **kwargs)

    return wrapped_view


def chat_allowed(view):
    @wraps(view)
    def wrapped_view(*args, **kwargs):
        user = current_user()
        if not user:
            return redirect(url_for('login'))
        if user['role'] not in ('lehrer', 'erwachsene'):
            flash('Only teachers and adults can access chat.')
            return redirect(url_for('dashboard'))
        return view(*args, **kwargs)

    return wrapped_view


def _parse_thread_id(value):
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return None
    if parsed <= 0:
        return None
    return parsed


def _get_chat_thread(db, user, thread_id=None, partner_id=None, create=False):
    if not thread_id and not partner_id:
        return None

    if thread_id:
        if user['role'] == 'lehrer':
            thread = db.execute(
                'SELECT id, teacher_id, adult_id FROM chat_threads WHERE id = ? AND teacher_id = ?',
                (thread_id, user['id']),
            ).fetchone()
        else:
            thread = db.execute(
                'SELECT id, teacher_id, adult_id FROM chat_threads WHERE id = ? AND adult_id = ?',
                (thread_id, user['id']),
            ).fetchone()
        return dict(thread) if thread else None

    if user['role'] == 'lehrer':
        partner = db.execute(
            'SELECT id FROM users WHERE id = ? AND role = ?',
            (partner_id, 'erwachsene'),
        ).fetchone()
        if not partner:
            return None
        thread = db.execute(
            'SELECT id, teacher_id, adult_id FROM chat_threads WHERE teacher_id = ? AND adult_id = ?',
            (user['id'], partner_id),
        ).fetchone()
        if thread:
            return dict(thread)
        if not create:
            return None
        now = datetime.utcnow().isoformat()
        db.execute(
            'INSERT INTO chat_threads (teacher_id, adult_id, created_at) VALUES (?, ?, ?)',
            (user['id'], partner_id, now),
        )
        thread_id = db.execute('SELECT last_insert_rowid()').fetchone()[0]
        return {
            'id': thread_id,
            'teacher_id': user['id'],
            'adult_id': partner_id,
        }

    partner = db.execute(
        'SELECT id FROM users WHERE id = ? AND role = ?',
        (partner_id, 'lehrer'),
    ).fetchone()
    if not partner:
        return None
    thread = db.execute(
        'SELECT id, teacher_id, adult_id FROM chat_threads WHERE teacher_id = ? AND adult_id = ?',
        (partner_id, user['id']),
    ).fetchone()
    if thread:
        return dict(thread)
    if not create:
        return None
    now = datetime.utcnow().isoformat()
    db.execute(
        'INSERT INTO chat_threads (teacher_id, adult_id, created_at) VALUES (?, ?, ?)',
        (partner_id, user['id'], now),
    )
    thread_id = db.execute('SELECT last_insert_rowid()').fetchone()[0]
    return {
        'id': thread_id,
        'teacher_id': partner_id,
        'adult_id': user['id'],
    }


def _chat_rows_from_thread(db, thread_id):
    return [
        {
            'id': row['id'],
            'message': row['message'],
            'sender_name': row['sender_name'],
            'sender_id': row['sender_id'],
            'created_at': row['created_at'],
        }
        for row in db.execute(
            '''
            SELECT cm.id, cm.message, cm.created_at, cm.sender_id, u.username AS sender_name
            FROM chat_messages cm
            JOIN users u ON u.id = cm.sender_id
            WHERE cm.thread_id = ?
            ORDER BY cm.id ASC
            ''',
            (thread_id,),
        ).fetchall()
    ]


def _allow_clear_history_from_ip():
    try:
        allowed = {str(ipaddress.ip_address(ip)) for ip in ALLOWED_HISTORY_CLEAR_IPS}
        for candidate in _client_ips():
            try:
                if str(ipaddress.ip_address(candidate)) in allowed:
                    return True
            except Exception:
                continue
        return False
    except Exception:
        return False


@app.before_request
def setup_db():
    init_db()

@app.route('/')
def index():
    if session.get('user_id'):
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        role = request.form.get('role', '').strip().lower()
        phone_number = request.form.get('phone_number', '').strip()

        if role not in ALLOWED_ROLES:
            flash('Please choose a valid role.')
            return render_template('register.html')
        if role == 'erwachsene' and not phone_number:
            flash('Adults need a phone number.')
            return render_template('register.html')
        if not username or not password:
            flash('Username and password are required.')
            return render_template('register.html')

        db = get_db()
        exists = db.execute('SELECT id FROM users WHERE username = ?', (username,)).fetchone()
        if exists:
            flash('Username is already taken.')
            return render_template('register.html')

        password_hash = generate_password_hash(password)
        db.execute(
            'INSERT INTO users (username, password_hash, role, points, phone_number, created_at) VALUES (?, ?, ?, 0, ?, ?)',
            (username, password_hash, role, phone_number, datetime.utcnow().isoformat()),
        )
        db.commit()
        flash('Registration successful. Please log in.')
        return redirect(url_for('login'))

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        user = get_db().execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        if user and check_password_hash(user['password_hash'], password):
            session['user_id'] = user['id']
            return redirect(url_for('dashboard'))
        flash('Login failed.')
    return render_template('login.html')


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))


@app.route('/dashboard')
@login_required
def dashboard():
    user = current_user()
    db = get_db()
    if user['role'] == 'lehrer':
        students = db.execute(
            """
            SELECT u.id, u.username, u.points
            FROM users u
            INNER JOIN teacher_students ts ON ts.student_id = u.id
            WHERE ts.teacher_id = ? AND u.role = "schueler"
            ORDER BY u.username ASC
            """,
            (user['id'],),
        ).fetchall()
        history_rows = db.execute(
            """
            SELECT ph.created_at,
                   s.username AS student_name,
                   t.username AS teacher_name,
                   ph.action_key,
                   ph.points_delta,
                   ph.points_after
                   ,ca.label AS custom_label
            FROM point_history ph
            JOIN users s ON s.id = ph.student_id
            JOIN users t ON t.id = ph.teacher_id
            LEFT JOIN custom_actions ca
              ON ca.teacher_id = ph.teacher_id AND ca.action_key = ph.action_key
            WHERE ph.teacher_id = ?
            ORDER BY ph.created_at DESC
            LIMIT 80
            """,
            (user['id'],),
        ).fetchall()
        positive_custom = db.execute(
            """
            SELECT action_key, label, icon
            FROM custom_actions
            WHERE teacher_id = ? AND delta > 0
            ORDER BY created_at ASC
            """,
            (user['id'],),
        ).fetchall()
        needs_work_custom = db.execute(
            """
            SELECT action_key, label, icon
            FROM custom_actions
            WHERE teacher_id = ? AND delta < 0
            ORDER BY created_at ASC
            """,
            (user['id'],),
        ).fetchall()
        history = [
            {
                **dict(row),
                'action_label': row['custom_label']
                if row['custom_label']
                else ACTION_LABELS.get(row['action_key'], row['action_key']),
            }
            for row in history_rows
        ]
        return render_template(
            'dashboard.html',
            user=user,
            students=students,
            positive_actions=POSITIVE_ACTIONS,
            needs_work_actions=NEEDS_WORK_ACTIONS,
            icon_choices=ICON_CHOICES,
            positive_custom_actions=positive_custom,
            needs_work_custom_actions=needs_work_custom,
            positive_custom_count=len(positive_custom),
            needs_work_custom_count=len(needs_work_custom),
            points_history=history,
        )

    history_rows = db.execute(
        """
        SELECT ph.created_at,
               s.username AS student_name,
               t.username AS teacher_name,
               ph.action_key,
               ph.points_delta,
               ph.points_after
               ,ca.label AS custom_label
        FROM point_history ph
        JOIN users s ON s.id = ph.student_id
        JOIN users t ON t.id = ph.teacher_id
        LEFT JOIN custom_actions ca
          ON ca.teacher_id = ph.teacher_id AND ca.action_key = ph.action_key
        WHERE ph.student_id = ?
        ORDER BY ph.created_at DESC
        LIMIT 40
        """,
        (user['id'],),
    ).fetchall()
    history = [
        {
            **dict(row),
            'action_label': row['custom_label']
            if row['custom_label']
            else ACTION_LABELS.get(row['action_key'], row['action_key']),
        }
        for row in history_rows
    ]

    return render_template(
        'dashboard.html',
        user=user,
        students=[],
        points_history=history,
    )


@app.route('/chat')
@login_required
@chat_allowed
def chat():
    user = current_user()
    db = get_db()

    if user['role'] == 'lehrer':
        threads = db.execute(
            '''
            SELECT
                ct.id,
                u.id AS partner_id,
                u.username AS partner_name,
                u.phone_number AS partner_phone,
                cm.id AS last_message_id,
                cm.message AS last_message,
                cm.created_at AS last_message_at
            FROM chat_threads ct
            JOIN users u ON u.id = ct.adult_id
            LEFT JOIN chat_messages cm ON cm.id = (
                SELECT id FROM chat_messages m WHERE m.thread_id = ct.id ORDER BY m.id DESC LIMIT 1
            )
            WHERE ct.teacher_id = ?
            ORDER BY COALESCE(cm.created_at, ct.created_at) DESC
            ''',
            (user['id'],),
        ).fetchall()
        partner_pool = db.execute(
            "SELECT id, username, phone_number FROM users WHERE role = 'erwachsene' ORDER BY username ASC"
        ).fetchall()
    else:
        threads = db.execute(
            '''
            SELECT
                ct.id,
                u.id AS partner_id,
                u.username AS partner_name,
                cm.id AS last_message_id,
                cm.message AS last_message,
                cm.created_at AS last_message_at
            FROM chat_threads ct
            JOIN users u ON u.id = ct.teacher_id
            LEFT JOIN chat_messages cm ON cm.id = (
                SELECT id FROM chat_messages m WHERE m.thread_id = ct.id ORDER BY m.id DESC LIMIT 1
            )
            WHERE ct.adult_id = ?
            ORDER BY COALESCE(cm.created_at, ct.created_at) DESC
            ''',
            (user['id'],),
        ).fetchall()
        partner_pool = db.execute(
            "SELECT id, username FROM users WHERE role = 'lehrer' ORDER BY username ASC"
        ).fetchall()

    requested_thread_id = _parse_thread_id(request.args.get('thread_id'))
    requested_partner_id = _parse_thread_id(request.args.get('partner_id'))

    selected_thread = None
    if requested_thread_id:
        selected_thread = _get_chat_thread(db, user, thread_id=requested_thread_id)
    elif requested_partner_id:
        selected_thread = _get_chat_thread(
            db,
            user,
            partner_id=requested_partner_id,
            create=True,
        )
    elif threads:
        selected_thread = {'id': threads[0]['id']}

    messages = []
    if selected_thread:
        messages = _chat_rows_from_thread(db, selected_thread['id'])
        db.commit()

    return render_template(
        'chat.html',
        user=user,
        threads=threads,
        partner_pool=partner_pool,
        selected_thread=selected_thread,
        messages=messages,
        last_message_id=messages[-1]['id'] if messages else 0,
        partner_type='Adults' if user['role'] == 'lehrer' else 'Teachers',
    )


@app.route('/chat/messages')
@login_required
@chat_allowed
def chat_messages():
    user = current_user()
    db = get_db()
    thread_id = _parse_thread_id(request.args.get('thread_id'))
    after_id = _parse_thread_id(request.args.get('after_id')) or 0

    if not thread_id:
        return jsonify({'ok': False, 'error': 'invalid_thread'}), 400

    thread = _get_chat_thread(db, user, thread_id=thread_id)
    if not thread:
        return jsonify({'ok': False, 'error': 'forbidden'}), 403

    messages = db.execute(
        '''
        SELECT cm.id, cm.message, cm.created_at, cm.sender_id, u.username AS sender_name
        FROM chat_messages cm
        JOIN users u ON u.id = cm.sender_id
        WHERE cm.thread_id = ?
        ORDER BY cm.id ASC
        ''',
        (thread_id,),
    ).fetchall()
    new_messages = [
        {
            'id': row['id'],
            'message': row['message'],
            'created_at': row['created_at'],
            'sender_id': row['sender_id'],
            'sender_name': row['sender_name'],
        }
        for row in messages
        if row['id'] > after_id
    ]
    latest = messages[-1]['id'] if messages else after_id
    return jsonify(
        {
            'ok': True,
            'thread_id': thread_id,
            'messages': new_messages,
            'latest_id': latest,
        }
    )


@app.route('/chat/send', methods=['POST'])
@login_required
@chat_allowed
def chat_send():
    user = current_user()
    db = get_db()
    thread_id = _parse_thread_id(request.form.get('thread_id'))
    partner_id = _parse_thread_id(request.form.get('partner_id'))
    message = request.form.get('message', '').strip()

    if not message:
        flash('Message cannot be empty.')
        if partner_id:
            return redirect(url_for('chat', partner_id=partner_id))
        if thread_id:
            return redirect(url_for('chat', thread_id=thread_id))
        return redirect(url_for('chat'))

    if thread_id:
        thread = _get_chat_thread(db, user, thread_id=thread_id)
    else:
        thread = _get_chat_thread(db, user, partner_id=partner_id, create=True)

    if not thread:
        flash('Select a valid chat partner first.')
        return redirect(url_for('chat'))

    db.execute(
        '''
        INSERT INTO chat_messages (thread_id, sender_id, message, created_at)
        VALUES (?, ?, ?, ?)
        ''',
        (thread['id'], user['id'], message, datetime.utcnow().isoformat()),
    )
    db.commit()
    return redirect(url_for('chat', thread_id=thread['id']))


@app.route('/students/add', methods=['POST'])
@teacher_required
def add_student():
    username = request.form.get('username', '').strip()
    if not username:
        flash('Please enter the student username.')
        return redirect(url_for('dashboard'))

    db = get_db()
    student = db.execute('SELECT id, role FROM users WHERE username = ?', (username,)).fetchone()
    if not student:
        flash('The entered user does not exist.')
        return redirect(url_for('dashboard'))

    if student['role'] != 'schueler':
        flash('Only accounts with role "student" can be assigned.')
        return redirect(url_for('dashboard'))

    try:
        db.execute(
            'INSERT INTO teacher_students (teacher_id, student_id, created_at) VALUES (?, ?, ?)',
            (session['user_id'], student['id'], datetime.utcnow().isoformat()),
        )
    except sqlite3.IntegrityError:
        flash('This student is already assigned.')
        return redirect(url_for('dashboard'))

    db.commit()
    flash('Student assigned.')
    return redirect(url_for('dashboard'))


@app.route('/actions/add', methods=['POST'])
@teacher_required
def add_action():
    delta_raw = request.form.get('delta', '').strip()
    if not delta_raw:
        flash('Please choose a point value.')
        return redirect(url_for('dashboard'))

    try:
        delta = int(delta_raw)
    except ValueError:
        flash('Invalid action type.')
        return redirect(url_for('dashboard'))

    if delta == 0 or delta < -5 or delta > 5:
        flash('Point value must be between -5 and 5 (excluding 0).')
        return redirect(url_for('dashboard'))

    label = request.form.get('label', '').strip()
    icon = request.form.get('icon', '').strip()

    if not label:
        flash('Please enter a label for the new icon.')
        return redirect(url_for('dashboard'))
    if not icon:
        flash('Please enter an icon for the new icon.')
        return redirect(url_for('dashboard'))
    if len(label) > 24:
        flash('Label is too long (max 24).')
        return redirect(url_for('dashboard'))
    if len(icon) > 8:
        flash('Icon is too long (max 8).')
        return redirect(url_for('dashboard'))

    db = get_db()
    sign = 'positive' if delta > 0 else 'negative'
    sign_count = db.execute(
        'SELECT COUNT(*) AS c FROM custom_actions WHERE teacher_id = ? AND delta {} 0'.format('>' if sign == 'positive' else '<'),
        (session['user_id'],),
    ).fetchone()['c']
    if sign_count >= 5:
        flash('You can only add up to 5 icons for each sign.')
        return redirect(url_for('dashboard'))

    action_key = f'custom_{uuid.uuid4().hex[:12]}'
    db.execute(
        """
        INSERT INTO custom_actions
            (teacher_id, action_key, label, icon, delta, created_at)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            session['user_id'],
            action_key,
            label,
            icon,
            delta,
            datetime.utcnow().isoformat(),
        ),
    )
    db.commit()
    flash('Custom icon added.')
    return redirect(url_for('dashboard'))


@app.route('/students/<int:student_id>/remove', methods=['POST'])
@teacher_required
def remove_student(student_id):
    db = get_db()
    result = db.execute(
        'DELETE FROM teacher_students WHERE teacher_id = ? AND student_id = ?',
        (session['user_id'], student_id),
    )

    if result.rowcount == 0:
        flash('Student not found in your list.')
    else:
        db.commit()
        flash('Student removed.')

    return redirect(url_for('dashboard'))


@app.route('/history/clear', methods=['POST'])
@teacher_required
def clear_history():
    if not _allow_clear_history_from_ip():
        flash(f'History can only be cleared from {ALLOWED_HISTORY_CLEAR_IP}. Current IPs: {", ".join(_client_ips())}.')
        return redirect(url_for('dashboard'))

    db = get_db()
    db.execute('DELETE FROM point_history WHERE teacher_id = ?', (session['user_id'],))
    db.commit()
    flash('Point history cleared.')
    return redirect(url_for('dashboard'))


@app.route('/students/<int:student_id>/points', methods=['POST'])
@teacher_required
def award_points(student_id):
    current = current_user()
    if not current:
        return redirect(url_for('login'))

    action_key = request.form.get('action', '').strip()

    action_delta = {action[0]: action[2] for action in POSITIVE_ACTIONS + NEEDS_WORK_ACTIONS}
    action_delta.update(
        {
            row['action_key']: row['delta']
            for row in get_db().execute(
                'SELECT action_key, delta FROM custom_actions WHERE teacher_id = ?',
                (current['id'],),
            ).fetchall()
        }
    )

    if action_key not in action_delta:
        flash('Choose a valid action.')
        return redirect(url_for('dashboard'))

    delta_int = action_delta[action_key]

    db = get_db()
    student = db.execute(
        'SELECT u.id, u.points FROM users u INNER JOIN teacher_students ts ON ts.student_id = u.id WHERE ts.teacher_id = ? AND u.id = ? AND u.role = "schueler"',
        (current['id'], student_id),
    ).fetchone()

    if not student:
        flash('Student not found or not assigned to you.')
        return redirect(url_for('dashboard'))

    new_points = student['points'] + delta_int
    db.execute('UPDATE users SET points = ? WHERE id = ?', (new_points, student_id))
    db.execute(
        '''
        INSERT INTO point_history
            (teacher_id, student_id, action_key, points_delta, points_after, created_at)
        VALUES (?, ?, ?, ?, ?, ?)
        ''',
        (
            current['id'],
            student_id,
            action_key,
            delta_int,
            new_points,
            datetime.utcnow().isoformat(),
        ),
    )
    db.commit()
    flash('Points updated.')
    return redirect(url_for('dashboard'))


if __name__ == '__main__':
    app.run(debug=True)

