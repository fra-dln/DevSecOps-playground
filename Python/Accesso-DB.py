from flask import Flask, render_template, request, redirect, url_for, session
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Cambia questa chiave segreta

# Funzione per inizializzare il database SQLite
def init_db():
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT NOT NULL,
            password TEXT NOT NULL
        )
    ''')
    conn.commit()
    conn.close()

init_db()

# Pagina di registrazione
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        # Controllo se l'email esiste già
        conn = sqlite3.connect('database.db')
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE email = ?', (email,))
        user = cursor.fetchone()
        conn.close()

        if user:
            return 'Email già registrata.'

        # Salva la password con hash
        password_hash = generate_password_hash(password)

        # Salva l'utente nel database
        conn = sqlite3.connect('database.db')
        cursor = conn.cursor()
        cursor.execute('INSERT INTO users (email, password) VALUES (?, ?)', (email, password_hash))
        conn.commit()
        conn.close()

        return 'Registrazione effettuata con successo.'

    return render_template('register.html')

# Pagina di login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        # Verifica le credenziali
        conn = sqlite3.connect('database.db')
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE email = ?', (email,))
        user = cursor.fetchone()
        conn.close()

        if user and check_password_hash(user[2], password):
            session['user_id'] = user[0]
            return 'Accesso effettuato con successo.'
        else:
            return 'Credenziali non valide. Riprova.'

    return render_template('login.html')

# Pagina di logout
@app.route('/logout')
def logout():
    session.clear()
    return 'Logout effettuato con successo.'

if __name__ == '__main__':
    app.run(debug=True)
