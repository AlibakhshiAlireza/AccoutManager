import sqlite3
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
import bcrypt

app = Flask(__name__)
app.secret_key = 'your_secret_key'

def create_db():
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS users
                      (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE, hashed_password TEXT)''')
    conn.commit()
    conn.close()

create_db()

def add_user_to_db(username, hashed_password):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute('INSERT INTO users (username, hashed_password) VALUES (?, ?)', (username, hashed_password))
    conn.commit()
    conn.close()

def get_hashed_password(username):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute('SELECT hashed_password FROM users WHERE username=?', (username,))
    result = cursor.fetchone()
    conn.close()
    return result[0] if result else None

def get_user_id(username):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute('SELECT id FROM users WHERE username=?', (username,))
    result = cursor.fetchone()
    conn.close()
    return result[0] if result else None

@app.route('/')
def home():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        hashed_password = get_hashed_password(username)

        if hashed_password and bcrypt.checkpw(password.encode('utf-8'), hashed_password):
            flash('Logged in successfully!', 'success')
            user_id = get_user_id(username)
            return redirect(url_for('show_hashed_password', user_id=user_id))
        else:
            flash('Invalid credentials', 'danger')

    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

        try:
            add_user_to_db(username, hashed_password)
            flash('Account created successfully!', 'success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Username already taken', 'danger')

    return render_template('login.html')

@app.route('/hashed_password/<int:user_id>')
def show_hashed_password(user_id):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute('SELECT username, hashed_password FROM users WHERE id=?', (user_id,))
    result = cursor.fetchone()
    conn.close()

    if result:
        username, hashed_password = result
        return jsonify({'user_id': user_id, 'username': username, 'hashed_password': hashed_password.decode('utf-8')})
    else:
        return 'User not found', 404


if __name__ == '__main__':
    app.run(debug=True)
