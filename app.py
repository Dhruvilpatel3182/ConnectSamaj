# -*- coding: utf-8 -*-
from flask import Flask, render_template, request, redirect, url_for, session, flash, send_from_directory
import sqlite3, os
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from datetime import datetime, timedelta

app = Flask(__name__)
app.secret_key = 'samaj-seva-secret-key-2024'

@app.route('/')
def home():
    return redirect('/dashboard')




# ---------- CONFIG ----------
UPLOAD_FOLDER = 'static/uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

# ---------- DATABASE ----------
def init_db():
    conn = sqlite3.connect('database.db')
    c = conn.cursor()

    # Drop all tables to start fresh (for development)
    c.execute("DROP TABLE IF EXISTS users")
    c.execute("DROP TABLE IF EXISTS villages")
    c.execute("DROP TABLE IF EXISTS families")
    c.execute("DROP TABLE IF EXISTS members")
    c.execute("DROP TABLE IF EXISTS events")

    # Users table for authentication
    c.execute('''CREATE TABLE users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE,
                    password TEXT,
                    role TEXT,
                    village TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )''')

    # Villages table for village management
    c.execute('''CREATE TABLE villages (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT UNIQUE,
                    created_by INTEGER,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (created_by) REFERENCES users(id)
                )''')

    # Families table with all required fields including head photo, birthdate and mosad
    c.execute('''CREATE TABLE families (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    family_no INTEGER,
                    head_name TEXT,
                    head_photo TEXT,
                    head_birthdate TEXT,
                    head_mosad TEXT,
                    village TEXT,
                    address TEXT,
                    contact TEXT,
                    created_by INTEGER,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (created_by) REFERENCES users(id)
                )''')

    # Members table with birthdate, age, birth_place, and photo
    c.execute('''CREATE TABLE members (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    family_id INTEGER,
                    unique_id INTEGER,
                    name TEXT,
                    father_husband_name TEXT,
                    gender TEXT,
                    birthdate TEXT,
                    age INTEGER,
                    birth_place TEXT,
                    mobile TEXT,
                    address TEXT,
                    photo TEXT,
                    education TEXT,
                    occupation TEXT,
                    relation TEXT,
                    remark TEXT,
                    created_by INTEGER,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (family_id) REFERENCES families(id),
                    FOREIGN KEY (created_by) REFERENCES users(id)
                )''')

    # Events table
    c.execute('''CREATE TABLE events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_type TEXT,
                    event_name TEXT,
                    description TEXT,
                    village TEXT,
                    date TEXT,
                    time TEXT,
                    created_by INTEGER,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (created_by) REFERENCES users(id)
                )''')

    # Insert default admin user
    c.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", 
              ('admin', generate_password_hash('admin123'), 'admin'))

    # Insert sample villages
    sample_villages = ['Parabiya', 'Jorapura', 'Jetholi', 'Rajpur']
    for village in sample_villages:
        c.execute("INSERT INTO villages (name, created_by) VALUES (?, ?)", 
                  (village, 1))

    # Insert sample families with head photo, birthdate and mosad
    sample_families = [
        (1, 'Patel Vitthalbhai Dahyabhai', None, '1975-05-15', 'Farmer', 'Parabiya', 'Main Street, Parabiya', '9825094655'),
        (2, 'Rajesh Kumar', None, '1980-08-20', 'Business', 'Parabiya', 'Gandhi Road', '9876543210'),
        (3, 'Suresh Patel', None, '1978-12-10', 'Teacher', 'Jorapura', 'Nehru Nagar', '9876543211'),
        (4, 'Mahesh Sharma', None, '1982-03-25', 'Shopkeeper', 'Jetholi', 'Station Road', '9876543212')
    ]
    
    for family_no, head_name, head_photo, head_birthdate, head_mosad, village, address, contact in sample_families:
        c.execute('''INSERT INTO families 
                    (family_no, head_name, head_photo, head_birthdate, head_mosad, village, address, contact, created_by) 
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                    (family_no, head_name, head_photo, head_birthdate, head_mosad, village, address, contact, 1))

    # Insert sample members with birthdate, birth_place, and photo
    sample_members = [
        (1, 1, 'Patel Vitthalbhai Dahyabhai', 'Dahyabhai Patel', 'Male', '1975-05-15', 48, 'Parabiya', '9825094655', 'Main Street, Parabiya', None, '10th Pass', 'Farmer', 'Head', 'Family Head'),
        (1, 2, 'Sunita Patel', 'Vitthalbhai Patel', 'Female', '1978-08-20', 45, 'Parabiya', '9825094656', 'Main Street, Parabiya', None, '12th Pass', 'Housewife', 'Wife', ''),
        (1, 3, 'Amit Patel', 'Vitthalbhai Patel', 'Male', '2005-03-10', 18, 'Parabiya', '9825094657', 'Main Street, Parabiya', None, 'B.Tech', 'Student', 'Son', 'College Student'),
        (2, 1, 'Rajesh Kumar', 'Suresh Kumar', 'Male', '1980-08-20', 43, 'Ahmedabad', '9876543210', 'Main Street', None, 'B.Com', 'Business', 'Head', 'Family Head')
    ]
    
    for family_id, unique_id, name, father_husband_name, gender, birthdate, age, birth_place, mobile, address, photo, education, occupation, relation, remark in sample_members:
        c.execute('''INSERT INTO members 
                    (family_id, unique_id, name, father_husband_name, gender, birthdate, age, birth_place, mobile, address, photo, education, occupation, relation, remark, created_by)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                    (family_id, unique_id, name, father_husband_name, gender, birthdate, age, birth_place, mobile, address, photo, education, occupation, relation, remark, 1))

    # Insert sample events
    sample_events = [
        ('Marriage', 'Rahul Wedding', 'Wedding ceremony of Rahul and Priya', 'Parabiya', '2024-12-15', '18:00'),
        ('Festival', 'Diwali Celebration', 'Community Diwali celebration', 'Parabiya', '2024-11-12', '19:00'),
        ('Meeting', 'Village Meeting', 'Monthly village committee meeting', 'Jorapura', '2024-10-20', '17:00')
    ]
    
    for event_type, event_name, description, village, date, time in sample_events:
        c.execute('''INSERT INTO events 
                    (event_type, event_name, description, village, date, time, created_by)
                    VALUES (?, ?, ?, ?, ?, ?, ?)''',
                    (event_type, event_name, description, village, date, time, 1))

    conn.commit()
    conn.close()
    print("Database initialized successfully with sample data!")

def check_and_fix_database():
    """Check if database has all required columns and fix if missing"""
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    
    try:
        # Check families table structure
        c.execute("PRAGMA table_info(families)")
        columns = [col[1] for col in c.fetchall()]
        print("Current families table columns:", columns)
        
        # Add missing columns to families table
        if 'head_photo' not in columns:
            c.execute("ALTER TABLE families ADD COLUMN head_photo TEXT")
            print("Added head_photo column to families")
        
        if 'head_birthdate' not in columns:
            c.execute("ALTER TABLE families ADD COLUMN head_birthdate TEXT")
            print("Added head_birthdate column to families")
            
        if 'head_mosad' not in columns:
            c.execute("ALTER TABLE families ADD COLUMN head_mosad TEXT")
            print("Added head_mosad column to families")
        
        # Check members table structure
        c.execute("PRAGMA table_info(members)")
        columns = [col[1] for col in c.fetchall()]
        print("Current members table columns:", columns)
        
        # Add missing columns to members table
        if 'birthdate' not in columns:
            c.execute("ALTER TABLE members ADD COLUMN birthdate TEXT")
            print("Added birthdate column to members")
        
        if 'age' not in columns:
            c.execute("ALTER TABLE members ADD COLUMN age INTEGER")
            print("Added age column to members")
            
        if 'birth_place' not in columns:
            c.execute("ALTER TABLE members ADD COLUMN birth_place TEXT")
            print("Added birth_place column to members")
            
        if 'mobile' not in columns:
            c.execute("ALTER TABLE members ADD COLUMN mobile TEXT")
            print("Added mobile column to members")
            
        if 'education' not in columns:
            c.execute("ALTER TABLE members ADD COLUMN education TEXT")
            print("Added education column to members")
            
        if 'occupation' not in columns:
            c.execute("ALTER TABLE members ADD COLUMN occupation TEXT")
            print("Added occupation column to members")
        
        conn.commit()
    except Exception as e:
        print(f"Error checking/fixing database: {e}")
    finally:
        conn.close()

def calculate_age(birthdate):
    """Calculate age from birthdate"""
    if not birthdate:
        return None
    try:
        today = datetime.today()
        birth_date = datetime.strptime(birthdate, '%Y-%m-%d')
        age = today.year - birth_date.year - ((today.month, today.day) < (birth_date.month, birth_date.day))
        return age
    except ValueError:
        return None

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# ---------- AUTHENTICATION DECORATORS ----------
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please login first', 'error')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session or session.get('role') != 'admin':
            flash('Admin access required', 'error')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

def village_manager_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session or session.get('role') not in ['admin', 'village_manager']:
            flash('Village manager access required', 'error')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

def admin_verified_required(f):
    """Decorator to require admin verification for sensitive actions"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session or session.get('role') != 'admin':
            flash('Admin access required', 'error')
            return redirect(url_for('login'))
        
        # Check if admin is verified (within last 30 minutes)
        if not session.get('admin_verified'):
            flash('Admin verification required for this action', 'error')
            return redirect(url_for('admin_verify', next=request.url))
        
        # Check if verification is still valid (30 minutes)
        verified_at = session.get('admin_verified_at')
        if verified_at:
            verified_time = datetime.fromisoformat(verified_at)
            if datetime.now() - verified_time > timedelta(minutes=30):
                session.pop('admin_verified', None)
                session.pop('admin_verified_at', None)
                flash('Admin verification expired. Please verify again.', 'error')
                return redirect(url_for('admin_verify', next=request.url))
        
        return f(*args, **kwargs)
    return decorated_function

# ---------- AUTHENTICATION ROUTES ----------
@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
        
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = sqlite3.connect('database.db')
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE username = ?", (username,))
        user = c.fetchone()
        conn.close()
        
        if user and check_password_hash(user[2], password):
            session['user_id'] = user[0]
            session['username'] = user[1]
            session['role'] = user[3]
            session['village'] = user[4]
            # Clear any previous admin verification on new login
            session.pop('admin_verified', None)
            session.pop('admin_verified_at', None)
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password', 'error')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out successfully', 'success')
    return redirect(url_for('login'))

# ---------- ADMIN VERIFICATION ROUTES ----------
@app.route('/admin/verify', methods=['GET', 'POST'])
@admin_required
def admin_verify():
    """Verify admin credentials before allowing edits"""
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = sqlite3.connect('database.db')
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE username = ? AND role = 'admin'", (username,))
        user = c.fetchone()
        conn.close()
        
        if user and check_password_hash(user[2], password):
            # Store admin verification in session
            session['admin_verified'] = True
            session['admin_verified_at'] = datetime.now().isoformat()
            flash('Admin verification successful!', 'success')
            
            # Redirect to intended page or dashboard
            next_page = request.args.get('next', url_for('dashboard'))
            return redirect(next_page)
        else:
            flash('Invalid admin credentials', 'error')
    
    # Get the intended next page
    next_page = request.args.get('next', url_for('dashboard'))
    return render_template('admin_verify.html', next_page=next_page)

@app.route('/admin/logout_verify')
@admin_required
def admin_logout_verify():
    """Logout from admin verification"""
    session.pop('admin_verified', None)
    session.pop('admin_verified_at', None)
    flash('Admin verification logged out', 'success')
    return redirect(url_for('dashboard'))

# ---------- DASHBOARD ----------
@app.route('/dashboard')
@login_required
def dashboard():
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    
    # Get counts based on user role
    if session['role'] == 'admin':
        c.execute("SELECT COUNT(*) FROM families")
        families_count = c.fetchone()[0]
        
        c.execute("SELECT COUNT(*) FROM members")
        members_count = c.fetchone()[0]
        
        c.execute("SELECT COUNT(*) FROM events")
        events_count = c.fetchone()[0]
        
        c.execute("SELECT COUNT(*) FROM villages")
        villages_count = c.fetchone()[0]
    else:
        # Village manager or member - only their village
        village = session.get('village', '')
        c.execute("SELECT COUNT(*) FROM families WHERE village = ?", (village,))
        families_count = c.fetchone()[0]
        
        c.execute('''SELECT COUNT(*) FROM members m 
                     JOIN families f ON m.family_id = f.id 
                     WHERE f.village = ?''', (village,))
        members_count = c.fetchone()[0]
        
        c.execute("SELECT COUNT(*) FROM events WHERE village = ?", (village,))
        events_count = c.fetchone()[0]
        
        villages_count = 1
    
    conn.close()
    
    return render_template('dashboard.html', 
                         families_count=families_count,
                         members_count=members_count,
                         events_count=events_count,
                         villages_count=villages_count)

# ---------- USER MANAGEMENT ----------
@app.route('/admin/users')
@admin_required
def manage_users():
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute('''SELECT u.id, u.username, u.role, u.village, v.name 
                 FROM users u LEFT JOIN villages v ON u.village = v.name 
                 ORDER BY u.id''')
    users = c.fetchall()
    
    c.execute("SELECT name FROM villages ORDER BY name")
    villages = [row[0] for row in c.fetchall()]
    conn.close()
    
    return render_template('manage_users.html', users=users, villages=villages)

@app.route('/admin/add_user', methods=['GET', 'POST'])
@admin_verified_required
def add_user():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        role = request.form['role']
        village = request.form.get('village', '')
        
        hashed_password = generate_password_hash(password)
        
        conn = sqlite3.connect('database.db')
        c = conn.cursor()
        try:
            c.execute('''INSERT INTO users (username, password, role, village) 
                        VALUES (?, ?, ?, ?)''', 
                        (username, hashed_password, role, village))
            conn.commit()
            flash('User added successfully', 'success')
        except sqlite3.IntegrityError:
            flash('Username already exists', 'error')
        finally:
            conn.close()
        
        return redirect(url_for('manage_users'))

    # For GET request — render Add User form
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute("SELECT name FROM villages ORDER BY name")
    villages = [row[0] for row in c.fetchall()]
    conn.close()

    return render_template('add_user.html', villages=villages)

    username = request.form['username']
    password = request.form['password']
    role = request.form['role']
    village = request.form.get('village', '')
    
    hashed_password = generate_password_hash(password)
    
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    try:
        c.execute('''INSERT INTO users (username, password, role, village) 
                     VALUES (?, ?, ?, ?)''', 
                     (username, hashed_password, role, village))
        conn.commit()
        flash('User added successfully', 'success')
    except sqlite3.IntegrityError:
        flash('Username already exists', 'error')
    finally:
        conn.close()
    
    return redirect(url_for('manage_users'))

@app.route('/admin/delete_user/<int:user_id>')
@admin_verified_required
def delete_user(user_id):
    if user_id == 1:  # Prevent deleting main admin
        flash('Cannot delete main administrator', 'error')
        return redirect(url_for('manage_users'))
        
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute("DELETE FROM users WHERE id = ?", (user_id,))
    conn.commit()
    conn.close()
    flash('User deleted successfully', 'success')
    return redirect(url_for('manage_users'))

# ---------- VILLAGE MANAGEMENT ----------
@app.route('/admin/villages')
@admin_required
def manage_villages():
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute('''SELECT v.id, v.name, v.created_at, u.username,
                 (SELECT COUNT(*) FROM families WHERE village = v.name) as family_count
                 FROM villages v 
                 LEFT JOIN users u ON v.created_by = u.id 
                 ORDER BY v.name''')
    villages = c.fetchall()
    conn.close()
    return render_template('manage_villages.html', villages=villages)

@app.route('/admin/add_village', methods=['POST'])
@admin_verified_required
def add_village():
    village_name = request.form['name'].strip()
    
    if not village_name:
        flash('Village name cannot be empty', 'error')
        return redirect(url_for('manage_villages'))
    
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    try:
        c.execute('''INSERT INTO villages (name, created_by) 
                     VALUES (?, ?)''', 
                     (village_name, session['user_id']))
        conn.commit()
        flash('Village added successfully', 'success')
    except sqlite3.IntegrityError:
        flash('Village name already exists', 'error')
    finally:
        conn.close()
    
    return redirect(url_for('manage_villages'))

@app.route('/admin/delete_village/<int:village_id>')
@admin_verified_required
def delete_village(village_id):
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    
    # First get the village name
    c.execute("SELECT name FROM villages WHERE id = ?", (village_id,))
    village_result = c.fetchone()
    
    if not village_result:
        flash('Village not found', 'error')
        conn.close()
        return redirect(url_for('manage_villages'))
    
    village_name = village_result[0]
    
    # Check if village has families
    c.execute("SELECT COUNT(*) FROM families WHERE village = ?", (village_name,))
    family_count = c.fetchone()[0]
    
    if family_count > 0:
        flash(f'Cannot delete {village_name} - it has {family_count} families. Please delete families first.', 'error')
    else:
        # Delete the village
        c.execute("DELETE FROM villages WHERE id = ?", (village_id,))
        conn.commit()
        flash(f'Village {village_name} deleted successfully', 'success')
    
    conn.close()
    return redirect(url_for('manage_villages'))

# ---------- FAMILY MANAGEMENT ----------
@app.route('/families')
@login_required
def families():
    village_filter = request.args.get('village', '')
    
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    
    # ALL users can see all villages
    c.execute("SELECT name FROM villages ORDER BY name")
    villages = [row[0] for row in c.fetchall()]
    
    # Build query with ALL columns including head_photo, head_birthdate, head_mosad
    query = '''SELECT f.id, f.family_no, f.head_name, f.village, f.contact, f.address,
                      COUNT(m.id) as member_count, 
                      f.head_photo, f.head_birthdate, f.head_mosad
               FROM families f 
               LEFT JOIN members m ON f.id = m.family_id'''
    
    where_conditions = []
    params = []
    
    if village_filter:
        where_conditions.append("f.village = ?")
        params.append(village_filter)
    
    if where_conditions:
        query += " WHERE " + " AND ".join(where_conditions)
    
    query += " GROUP BY f.id ORDER BY f.family_no"
    
    c.execute(query, params)
    families_data = c.fetchall()
    
    # Debug: Print column structure
    if families_data:
        print("DEBUG - Family data structure:")
        print("Number of columns:", len(families_data[0]))
        for i, col in enumerate(families_data[0]):
            print(f"Column {i}: {col}")
    
    conn.close()
    
    return render_template('families.html', 
                         families=families_data, 
                         villages=villages,
                         selected_village=village_filter)
    village_filter = request.args.get('village', '')
    
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    
    # ALL users can see ALL villages in filter dropdown
    c.execute("SELECT name FROM villages ORDER BY name")
    villages = [row[0] for row in c.fetchall()]
    
    # Build query - NO village restrictions for viewing
    query = '''SELECT f.id, f.family_no, f.head_name, f.village, f.contact, f.address,
                      COUNT(m.id) as member_count
               FROM families f 
               LEFT JOIN members m ON f.id = m.family_id'''
    
    where_conditions = []
    params = []
    
    if village_filter:
        where_conditions.append("f.village = ?")
        params.append(village_filter)
    
    # NO village restrictions for any logged-in users
    
    if where_conditions:
        query += " WHERE " + " AND ".join(where_conditions)
    
    query += " GROUP BY f.id ORDER BY f.family_no"
    
    c.execute(query, params)
    families_data = c.fetchall()
    conn.close()
    
    return render_template('families.html', 
                         families=families_data, 
                         villages=villages,
                         selected_village=village_filter)
    village_filter = request.args.get('village', '')
    
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    
    # Get villages for filter dropdown
    if session['role'] == 'admin':
        c.execute("SELECT name FROM villages ORDER BY name")
    else:
        c.execute("SELECT name FROM villages WHERE name = ?", (session['village'],))
    
    villages = [row[0] for row in c.fetchall()]
    
    # Build query based on user role - UPDATED to include new columns
    query = '''SELECT f.id, f.family_no, f.head_name, f.village, f.contact, f.address,
                      COUNT(m.id) as member_count, f.head_photo, f.head_birthdate, f.head_mosad
               FROM families f 
               LEFT JOIN members m ON f.id = m.family_id'''
    
    where_conditions = []
    params = []
    
    if village_filter:
        where_conditions.append("f.village = ?")
        params.append(village_filter)
    
    # Restrict village managers to their village
    if session['role'] == 'village_manager':
        where_conditions.append("f.village = ?")
        params.append(session['village'])
    
    if where_conditions:
        query += " WHERE " + " AND ".join(where_conditions)
    
    query += " GROUP BY f.id ORDER BY f.family_no"
    
    c.execute(query, params)
    families_data = c.fetchall()
    conn.close()
    
    return render_template('families.html', 
                         families=families_data, 
                         villages=villages,
                         selected_village=village_filter)

@app.route('/add_family', methods=['GET', 'POST'])
@village_manager_required
def add_family():
    if request.method == 'POST':
        head_name = request.form['head_name']
        village = request.form['village']
        address = request.form.get('address', '')
        contact = request.form.get('contact', '')
        head_birthdate = request.form.get('head_birthdate', '')
        head_mosad = request.form.get('head_mosad', '')
        
        conn = sqlite3.connect('database.db')
        c = conn.cursor()
        
        # Auto-generate family number
        c.execute("SELECT COALESCE(MAX(family_no), 0) + 1 FROM families")
        family_no = c.fetchone()[0]
        
        # Handle head photo upload
        head_photo = None
        if 'head_photo' in request.files:
            file = request.files['head_photo']
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                filename = f"head_{timestamp}_{filename}"
                filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(filepath)
                head_photo = filename
        
        c.execute('''INSERT INTO families 
                    (family_no, head_name, head_photo, head_birthdate, head_mosad, village, address, contact, created_by) 
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                    (family_no, head_name, head_photo, head_birthdate, head_mosad, village, address, contact, session['user_id']))
        
        conn.commit()
        conn.close()
        
        flash(f'Family added successfully with Family No: {family_no}', 'success')
        return redirect(url_for('families'))
    
    # GET request - show form
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    
    if session['role'] == 'admin':
        c.execute("SELECT name FROM villages ORDER BY name")
    else:
        c.execute("SELECT name FROM villages WHERE name = ?", (session['village'],))
    
    villages = [row[0] for row in c.fetchall()]
    conn.close()
    
    return render_template('add_family.html', villages=villages)

@app.route('/family/<int:family_id>')
@login_required
def view_family(family_id):
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    
    # Get family details - UPDATED to include new columns
    c.execute('''SELECT f.*, u.username as created_by_name 
                 FROM families f 
                 LEFT JOIN users u ON f.created_by = u.id 
                 WHERE f.id = ?''', (family_id,))
    family = c.fetchone()
    
    if not family:
        flash('Family not found', 'error')
        return redirect(url_for('families'))
    
    # Check if user has access to this family
    if session['role'] == 'village_manager' and family[6] != session['village']:
        flash('Access denied', 'error')
        return redirect(url_for('families'))
    
    # Get family members
    c.execute('''SELECT * FROM members 
                 WHERE family_id = ? 
                 ORDER BY unique_id''', (family_id,))
    members = c.fetchall()
    
    conn.close()
    
    return render_template('view_family.html', family=family, members=members)

# ---------- MEMBER MANAGEMENT ----------
@app.route('/add_member', methods=['GET', 'POST'])
@village_manager_required
def add_member():
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    
    # Get families for dropdown
    if session['role'] == 'admin':
        c.execute("SELECT id, family_no, head_name, village FROM families ORDER BY family_no")
    else:
        c.execute('''SELECT id, family_no, head_name, village 
                     FROM families WHERE village = ? 
                     ORDER BY family_no''', (session['village'],))
    
    families_data = c.fetchall()
    
    if request.method == 'POST':
        family_id = request.form['family_id']
        name = request.form['name']
        father_husband_name = request.form.get('father_husband_name', '')
        gender = request.form['gender']
        birthdate = request.form.get('birthdate')
        birth_place = request.form.get('birth_place', '')
        mobile = request.form.get('mobile')
        address = request.form.get('address', '')
        education = request.form.get('education', '')
        occupation = request.form.get('occupation', '')
        relation = request.form.get('relation', '')
        remark = request.form.get('remark', '')
        
        # Calculate age from birthdate if provided, otherwise use form age
        if birthdate:
            age = calculate_age(birthdate)
        else:
            age = request.form.get('age')
            age = int(age) if age and age.isdigit() else None
        
        # Auto-generate unique ID for member
        c.execute("SELECT COALESCE(MAX(unique_id), 0) + 1 FROM members WHERE family_id = ?", 
                  (family_id,))
        unique_id = c.fetchone()[0]
        
        # Handle photo upload
        photo = None
        if 'photo' in request.files:
            file = request.files['photo']
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                # Add timestamp to make filename unique
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                filename = f"member_{timestamp}_{filename}"
                filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(filepath)
                photo = filename
        
        c.execute('''INSERT INTO members 
                    (family_id, unique_id, name, father_husband_name, gender, birthdate, age, birth_place, mobile, address, photo, education, occupation, relation, remark, created_by)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                    (family_id, unique_id, name, father_husband_name, gender, birthdate, age, birth_place, mobile, address, photo, education, occupation, relation, remark, session['user_id']))
        
        conn.commit()
        conn.close()
        flash(f'Member added successfully with ID: {unique_id}', 'success')
        return redirect(url_for('view_members'))
    
    conn.close()
    return render_template('add_member.html', families=families_data)

@app.route('/members')
@login_required
def view_members():
    village_filter = request.args.get('village', '')
    search_query = request.args.get('search', '')
    
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    
    # UPDATED query with all columns
    query = '''SELECT m.id, m.unique_id, m.name, m.father_husband_name, m.gender, 
                      m.birthdate, m.age, m.birth_place, m.mobile, m.photo,
                      f.village, f.head_name, f.family_no, m.education, m.occupation
               FROM members m
               JOIN families f ON m.family_id = f.id'''
    
    where_conditions = []
    params = []
    
    if village_filter:
        where_conditions.append("f.village = ?")
        params.append(village_filter)
    
    if search_query:
        where_conditions.append("(m.name LIKE ? OR m.father_husband_name LIKE ? OR m.mobile LIKE ? OR m.birth_place LIKE ?)")
        params.extend([f'%{search_query}%', f'%{search_query}%', f'%{search_query}%', f'%{search_query}%'])
    
    if where_conditions:
        query += " WHERE " + " AND ".join(where_conditions)
    
    query += " ORDER BY f.family_no, m.unique_id"
    
    c.execute(query, params)
    members = c.fetchall()
    
    # Debug: Check if we're getting data
    print(f"DEBUG: Found {len(members)} members")
    if members:
        print(f"DEBUG: First member: {members[0]}")
    
    # Get villages for filter
    c.execute("SELECT name FROM villages ORDER BY name")
    villages = [row[0] for row in c.fetchall()]
    conn.close()
    
    return render_template('members.html', 
                         members=members, 
                         villages=villages,
                         selected_village=village_filter,
                         search_query=search_query)
# ---------- EVENT MANAGEMENT ----------
@app.route('/events')
@login_required
def view_events():
    village_filter = request.args.get('village', '')
    
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    
    # Build query - NO village restrictions
    query = '''SELECT e.*, u.username 
               FROM events e 
               LEFT JOIN users u ON e.created_by = u.id'''
    
    where_conditions = []
    params = []
    
    if village_filter:
        where_conditions.append("e.village = ?")
        params.append(village_filter)
    
    # NO village restrictions for any logged-in users
    
    if where_conditions:
        query += " WHERE " + " AND ".join(where_conditions)
    
    query += " ORDER BY e.date DESC, e.time DESC"
    
    c.execute(query, params)
    events = c.fetchall()
    
    # Get villages for filter - ALL users can see all villages
    c.execute("SELECT name FROM villages ORDER BY name")
    villages = [row[0] for row in c.fetchall()]
    
    conn.close()
    
    return render_template('view_events.html', 
                         events=events, 
                         villages=villages,
                         selected_village=village_filter)
    village_filter = request.args.get('village', '')
    event_type_filter = request.args.get('event_type', '')
    
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    
    # Build query
    query = '''SELECT e.*, u.username 
               FROM events e 
               LEFT JOIN users u ON e.created_by = u.id'''
    
    where_conditions = []
    params = []
    
    if village_filter:
        where_conditions.append("e.village = ?")
        params.append(village_filter)
    
    if event_type_filter:
        where_conditions.append("e.event_type = ?")
        params.append(event_type_filter)
    
    # Restrict village managers to their village
    if session['role'] == 'village_manager':
        where_conditions.append("e.village = ?")
        params.append(session['village'])
    
    if where_conditions:
        query += " WHERE " + " AND ".join(where_conditions)
    
    query += " ORDER BY e.date DESC, e.time DESC"
    
    c.execute(query, params)
    events = c.fetchall()
    
    # Get villages for filter
    if session['role'] == 'admin':
        c.execute("SELECT name FROM villages ORDER BY name")
    else:
        c.execute("SELECT name FROM villages WHERE name = ?", (session['village'],))
    
    villages = [row[0] for row in c.fetchall()]
    
    # Get event types
    c.execute("SELECT DISTINCT event_type FROM events ORDER BY event_type")
    event_types = [row[0] for row in c.fetchall()]
    
    conn.close()
    
    return render_template('view_events.html', 
                         events=events, 
                         villages=villages,
                         event_types=event_types,
                         selected_village=village_filter,
                         selected_event_type=event_type_filter)

@app.route('/add_event', methods=['GET', 'POST'])
@village_manager_required
def add_event():
    if request.method == 'POST':
        event_type = request.form['event_type']
        event_name = request.form['event_name']
        village = request.form['village']
        date = request.form['date']
        time = request.form.get('time', '')
        description = request.form.get('description', '')
        
        conn = sqlite3.connect('database.db')
        c = conn.cursor()
        c.execute('''INSERT INTO events 
                    (event_type, event_name, village, date, time, description, created_by)
                    VALUES (?, ?, ?, ?, ?, ?, ?)''',
                    (event_type, event_name, village, date, time, description, session['user_id']))
        conn.commit()
        conn.close()
        
        flash('Event added successfully', 'success')
        return redirect(url_for('view_events'))

    # GET request - show form
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    
    if session['role'] == 'admin':
        c.execute("SELECT name FROM villages ORDER BY name")
    else:
        c.execute("SELECT name FROM villages WHERE name = ?", (session['village'],))
    
    villages = [row[0] for row in c.fetchall()]
    conn.close()
    
    return render_template('add_event.html', villages=villages)

@app.route('/public/villages')
def public_villages():
    """Public view of villages - no login required"""
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute("SELECT id, name FROM villages ORDER BY name")
    villages = c.fetchall()
    conn.close()
    
    return render_template('login.html', villages=villages)

@app.route('/public/families/<village_name>')
def public_families(village_name):
    """Public view of families in a village - no login required"""
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    
    # Get families in this village
    c.execute('''SELECT f.id, f.family_no, f.head_name, f.village, f.contact, f.address,
                        COUNT(m.id) as member_count
                 FROM families f 
                 LEFT JOIN members m ON f.id = m.family_id
                 WHERE f.village = ?
                 GROUP BY f.id ORDER BY f.family_no''', (village_name,))
    
    families = c.fetchall()
    conn.close()
    
    return render_template('public_families.html', families=families, village_name=village_name)

# ---------- DELETE ROUTES ----------
@app.route('/admin/delete_family/<int:family_id>')
@admin_required
def delete_family(family_id):
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    
    # Get family info for confirmation message
    c.execute("SELECT family_no, head_name FROM families WHERE id = ?", (family_id,))
    family = c.fetchone()
    
    if not family:
        flash('Family not found', 'error')
        return redirect(url_for('families'))
    
    # First delete all members of this family
    c.execute("DELETE FROM members WHERE family_id = ?", (family_id,))
    # Then delete the family
    c.execute("DELETE FROM families WHERE id = ?", (family_id,))
    
    conn.commit()
    conn.close()
    
    flash(f'Family {family[1]} and all members deleted successfully', 'success')
    return redirect(url_for('families'))

@app.route('/admin/delete_member/<int:member_id>')
@admin_required
def delete_member(member_id):
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    
    # Get member info for confirmation message
    c.execute("SELECT name FROM members WHERE id = ?", (member_id,))
    member = c.fetchone()
    
    if not member:
        flash('Member not found', 'error')
        return redirect(url_for('view_members'))
    
    # Delete the member
    c.execute("DELETE FROM members WHERE id = ?", (member_id,))
    
    conn.commit()
    conn.close()
    
    flash(f'Member {member[0]} deleted successfully', 'success')
    return redirect(url_for('view_members'))

@app.route('/admin/delete_event/<int:event_id>')
@admin_required
def delete_event(event_id):
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    
    # Get event info for confirmation message
    c.execute("SELECT event_name FROM events WHERE id = ?", (event_id,))
    event = c.fetchone()
    
    if not event:
        flash('Event not found', 'error')
        return redirect(url_for('view_events'))
    
    # Delete the event
    c.execute("DELETE FROM events WHERE id = ?", (event_id,))
    
    conn.commit()
    conn.close()
    
    flash(f'Event {event[0]} deleted successfully', 'success')
    return redirect(url_for('view_events'))

@app.route('/admin/force_delete_village/<int:village_id>')
@admin_required
def force_delete_village(village_id):
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    
    # Get village name first
    c.execute("SELECT name FROM villages WHERE id = ?", (village_id,))
    village = c.fetchone()
    
    if not village:
        flash('Village not found', 'error')
        return redirect(url_for('manage_villages'))
    
    village_name = village[0]
    
    # Delete all members from families in this village
    c.execute('''DELETE FROM members 
                 WHERE family_id IN (SELECT id FROM families WHERE village = ?)''', 
                 (village_name,))
    
    # Delete all families in this village
    c.execute("DELETE FROM families WHERE village = ?", (village_name,))
    
    # Delete events in this village
    c.execute("DELETE FROM events WHERE village = ?", (village_name,))
    
    # Update users who were assigned to this village
    c.execute("UPDATE users SET village = NULL WHERE village = ?", (village_name,))
    
    # Finally delete the village
    c.execute("DELETE FROM villages WHERE id = ?", (village_id,))
    
    conn.commit()
    conn.close()
    
    flash(f'Village {village_name} and all associated data deleted successfully', 'success')
    return redirect(url_for('manage_villages'))
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    
    # Get village name first
    c.execute("SELECT name FROM villages WHERE id = ?", (village_id,))
    village = c.fetchone()
    
    if not village:
        flash('Village not found', 'error')
        return redirect(url_for('manage_villages'))
    
    village_name = village[0]
    
    # Delete all members from families in this village (and their photos)
    c.execute('''SELECT m.photo FROM members m 
                 JOIN families f ON m.family_id = f.id 
                 WHERE f.village = ?''', (village_name,))
    members_photos = c.fetchall()
    for photo in members_photos:
        if photo[0]:
            member_photo_path = os.path.join(app.config['UPLOAD_FOLDER'], photo[0])
            if os.path.exists(member_photo_path):
                os.remove(member_photo_path)
    
    # Delete all family head photos in this village
    c.execute("SELECT head_photo FROM families WHERE village = ?", (village_name,))
    family_photos = c.fetchall()
    for photo in family_photos:
        if photo[0]:
            family_photo_path = os.path.join(app.config['UPLOAD_FOLDER'], photo[0])
            if os.path.exists(family_photo_path):
                os.remove(family_photo_path)
    
    # Delete all members from families in this village
    c.execute('''DELETE FROM members 
                 WHERE family_id IN (SELECT id FROM families WHERE village = ?)''', 
                 (village_name,))
    
    # Delete all families in this village
    c.execute("DELETE FROM families WHERE village = ?", (village_name,))
    
    # Delete events in this village
    c.execute("DELETE FROM events WHERE village = ?", (village_name,))
    
    # Update users who were assigned to this village
    c.execute("UPDATE users SET village = NULL WHERE village = ?", (village_name,))
    
    # Finally delete the village
    c.execute("DELETE FROM villages WHERE id = ?", (village_id,))
    
    conn.commit()
    conn.close()
    
    flash(f'Village {village_name} and all associated data deleted successfully', 'success')
    return redirect(url_for('manage_villages'))

# ---------- USER SIDE ROUTES ----------
# ---------- VIEWER ROUTES (For Members to View All Villages) ----------
@app.route('/user/villages')
@login_required
def user_villages():
    """Show ALL villages to ALL users (Members can see all villages)"""
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    
    # ALL users can see ALL villages
    c.execute("SELECT id, name FROM villages ORDER BY name")
    villages = c.fetchall()
    conn.close()
    
    return render_template('user_villages.html', villages=villages)

@app.route('/user/families/<village_name>')
@login_required
def user_families(village_name):
    """Show families in a specific village for ALL users"""
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    
    # Get families with member counts
    c.execute('''SELECT f.id, f.family_no, f.head_name, f.village, f.contact, f.address,
                        COUNT(m.id) as member_count
                 FROM families f 
                 LEFT JOIN members m ON f.id = m.family_id
                 WHERE f.village = ?
                 GROUP BY f.id ORDER BY f.family_no''', (village_name,))
    
    families = c.fetchall()
    
    # Get village info
    c.execute("SELECT name FROM villages WHERE name = ?", (village_name,))
    village = c.fetchone()
    
    conn.close()
    
    if not village:
        flash('Village not found', 'error')
        return redirect(url_for('user_villages'))
    
    return render_template('user_families.html', 
                         families=families, 
                         village_name=village_name)

@app.route('/user/family/<int:family_id>')
@login_required
def user_view_family(family_id):
    """View family details for ALL users"""
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    
    # Get family details
    c.execute('''SELECT * FROM families WHERE id = ?''', (family_id,))
    family = c.fetchone()
    
    if not family:
        flash('Family not found', 'error')
        return redirect(url_for('user_villages'))
    
    # Get family members
    c.execute('''SELECT * FROM members 
                 WHERE family_id = ? 
                 ORDER BY unique_id''', (family_id,))
    members = c.fetchall()
    
    conn.close()
    
    return render_template('user_view_family.html', family=family, members=members)

@app.route('/user/events/<village_name>')
@login_required
def user_events(village_name):
    """Show events for a specific village for ALL users"""
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    
    # Get events
    c.execute('''SELECT e.*, u.username 
                 FROM events e 
                 LEFT JOIN users u ON e.created_by = u.id
                 WHERE e.village = ?
                 ORDER BY e.date DESC, e.time DESC''', (village_name,))
    
    events = c.fetchall()
    
    # Get village info
    c.execute("SELECT name FROM villages WHERE name = ?", (village_name,))
    village = c.fetchone()
    
    conn.close()
    
    if not village:
        flash('Village not found', 'error')
        return redirect(url_for('user_villages'))
    
    return render_template('user_events.html', 
                         events=events, 
                         village_name=village_name)
    """Show events for a specific village for users"""
    # Check if user has access to this village
    if session['role'] not in ['admin', 'village_manager'] and session.get('village') != village_name:
        flash('Access denied to this village', 'error')
        return redirect(url_for('user_villages'))
    
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    
    # Get events
    c.execute('''SELECT e.*, u.username 
                 FROM events e 
                 LEFT JOIN users u ON e.created_by = u.id
                 WHERE e.village = ?
                 ORDER BY e.date DESC, e.time DESC''', (village_name,))
    
    events = c.fetchall()
    
    # Get village info
    c.execute("SELECT name FROM villages WHERE name = ?", (village_name,))
    village = c.fetchone()
    
    conn.close()
    
    if not village:
        flash('Village not found', 'error')
        return redirect(url_for('user_villages'))
    
    return render_template('user_events.html', 
                         events=events, 
                         village_name=village_name)



# ---------- PHOTO ROUTE ----------
@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

# Google Verification Routes - ADD THIS TO YOUR app.py
@app.route('/ads.txt')
def ads_txt():
    return "google.com, pub-4575841956746799, DIRECT, f08c47fec0942fa0"

@app.route('/robots.txt')
def robots_txt():
    return "User-agent: *\nAllow: /"

# Add this if you use HTML file verification
@app.route('/google*.html')
def google_verification():
    return "google-site-verification: google1234567890abcdef.html"

# ---------- MAIN ----------
if __name__ == '__main__':
    # Initialize database if it doesn't exist
    if not os.path.exists('database.db'):
        init_db()
        print("New database created with all columns!")
    else:
        check_and_fix_database()
        print("Existing database checked and fixed!")
    
    app.run(debug=True, host='0.0.0.0', port=5000)