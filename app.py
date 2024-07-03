from flask import Flask, render_template, request, redirect, url_for, session, jsonify
import json

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Clave secreta para la sesión

# Datos de ejemplo (reemplazar con una base de datos real en producción)
users = {'santos': {'password': 'santos1', 'name': 'User One'},
         'user2': {'password': 'password2', 'name': 'User Two'}}

@app.route('/')
def home():
    return render_template('login.html')

@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']
    
    if username in users and users[username]['password'] == password:
        session['username'] = username
        return redirect(url_for('success'))
    else:
        return "Login fallido. Por favor, verifica tus credenciales."

@app.route('/success')
def success():
    if 'username' in session:
        username = session['username']
        return render_template('home.html', username=username)
    else:
        return redirect(url_for('home'))

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('home'))

@app.route('/data')
def data():
    with open('data.json') as f:
        data = json.load(f)
    return jsonify(data)

if __name__ == '__main__':
    app.run(debug=True)
