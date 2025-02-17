from flask import Flask, render_template, request, redirect, url_for, flash, session
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Change this to a secure secret key

# Initialize the database
def init_db():
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL UNIQUE,
        password TEXT NOT NULL,
        firstname TEXT NOT NULL,
        lastname TEXT NOT NULL,
        email TEXT NOT NULL
    )
    ''')
    conn.commit()
    conn.close()

# Index route (landing page)
@app.route('/')
def index():
    return render_template('index.html')

# Register route
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = generate_password_hash(request.form['password'], method='pbkdf2:sha256')
        firstname = request.form['firstname']
        lastname = request.form['lastname']
        email = request.form['email']

        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()

        cursor.execute('''
            INSERT INTO users (username, password, firstname, lastname, email)
            VALUES (?, ?, ?, ?, ?)
        ''', (username, password, firstname, lastname, email))

        conn.commit()
        conn.close()

        flash('Registration successful! Please log in.')
        return redirect(url_for('login'))

    return render_template('register.html')

# Login route

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()

        cursor.execute('''
            SELECT * FROM users WHERE username = ?
        ''', (username,))
        user = cursor.fetchone()
        conn.close()

        if user and check_password_hash(user[2], password):
            session['user_id'] = user[0]
            session['username'] = user[1]
            return redirect(url_for('profile'))
        else:
            flash('Invalid username or password.', 'error')  # Flash error message
            return redirect(url_for('login'))  # Redirect back to login page

    return render_template('login.html')


# Profile route (accessible after login)
@app.route('/profile')
def profile():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user_id = session['user_id']

    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute('''
        SELECT * FROM users WHERE id = ?
    ''', (user_id,))
    user = cursor.fetchone()
    conn.close()

    return render_template('profile.html', user=user)

# Logout route
@app.route('/logout')
def logout():
    session.pop('user_id', None)
    session.pop('username', None)
    return redirect(url_for('login'))

if __name__ == '__main__':
    init_db()  # Initialize DB if needed
    app.run(host='0.0.0.0', port=5000, debug=True)