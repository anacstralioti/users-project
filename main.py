import os
from flask import Flask, request, jsonify, render_template, url_for, redirect, flash, session, make_response
import sqlite3, bcrypt, re
from flask_babel import Babel, _
from datetime import datetime
from flask_dance.contrib.google import make_google_blueprint, google
from flask_dance.contrib.github import make_github_blueprint, github
import logging
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature

app = Flask(__name__)

# Google OAuth
client_id = ""
client_secret = ""

# GitHub OAuth
github_client_id = ""
github_client_secret = ""

app.secret_key = ""

os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'
os.environ['OAUTHLIB_RELAX_TOKEN_SCOPE'] = '1'

# Blueprint do Google
google_blueprint = make_google_blueprint(
    client_id=client_id,
    client_secret=client_secret,
    reprompt_consent=True,
    scope=["profile", "email"]
)
app.register_blueprint(google_blueprint, url_prefix="/login")

# Blueprint do GitHub
github_blueprint = make_github_blueprint(
    client_id=github_client_id,
    client_secret=github_client_secret
)
app.register_blueprint(github_blueprint, url_prefix="/login")

DATABASE = 'database.db'

app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USERNAME'] = ''
app.config["MAIL_PASSWORD"] = ''
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False

mail = Mail(app)

s = URLSafeTimedSerializer(app.secret_key)

app.config['BABEL_DEFAULT_LOCALE'] = 'pt_BR'
app.config['BABEL_TRANSLATION_DIRECTORIES'] = 'translations'

def get_db():
   db = sqlite3.connect(DATABASE)
   db.row_factory = sqlite3.Row
   return db

def init_db():
   with app.app_context():
       db = get_db()
       with app.open_resource('schema.sql', mode='r') as f:
           db.cursor().executescript(f.read())
           db.commit()

def is_valid_email(email):
   return re.match(r"[^@]+@[^@]+\.[^@]+", email)

def get_current_time():
   return datetime.now().isoformat()

@app.route('/')
def home():
    if google.authorized:
        return redirect(url_for('pagina_final'))

    if github.authorized:
        return redirect(url_for('pagina_final'))

    return render_template('index.html')

def get_locale():
    # Verifica se o parâmetro 'lang' está na URL, caso contrário usa o cookie
    lang = request.args.get('lang')  # Pega o parâmetro 'lang' da URL
    if lang and lang in ['en', 'es', 'pt_BR']:
        resp = make_response(redirect(request.url))  # Redireciona para a mesma página com o novo idioma
        resp.set_cookie('language', lang)  # Armazena no cookie
        return lang

    # Se não passar o parâmetro na URL, usa o valor armazenado no cookie
    lang = request.cookies.get('language')
    if lang and lang in ['en', 'es', 'pt_BR']:
        return lang

    # Caso contrário, usa o melhor idioma do Accept-Language do navegador
    return request.accept_languages.best_match(['en', 'es', 'pt_BR'])

babel = Babel(app, locale_selector=get_locale)

@app.context_processor
def inject_locale():
    return {'get_locale': get_locale}

@app.route('/initdb')
def initialize_database():
   init_db()
   return 'Banco de dados inicializado'

@app.route('/cadastro', methods=['GET', 'POST'])
def cadastro():
    if request.method == 'POST':
        login = request.json.get('login')
        senha = request.json.get('senha')
        nome = request.json.get('nome')

        if not login or not senha or not nome:
            return jsonify({'error': 'Login, senha e nome são obrigatórios'}), 400

        if not is_valid_email(login):
            return jsonify({'error': 'Login deve ser um e-mail válido'}), 400

        try:
            db = get_db()
            cursor = db.cursor()
            cursor.execute('SELECT * FROM usuarios WHERE login = ?', (login,))
            if cursor.fetchone():
                return jsonify({'error': 'Login já existe'}), 400

            # criptografa a senha
            hashed_senha = bcrypt.hashpw(senha.encode('utf-8'), bcrypt.gensalt())
            created_at = get_current_time()
            cursor.execute('INSERT INTO usuarios (login, senha, nome, created) VALUES (?, ?, ?, ?)',
                           (login, hashed_senha, nome, created_at))
            db.commit()
            return jsonify({'message': 'Usuário cadastrado com sucesso!'}), 201
        except sqlite3.Error as e:
            return jsonify({'error': str(e)}), 500
        finally:
            db.close()

    return render_template('cadastro.html')

@app.route('/login', methods=['GET', 'POST'])
def login_usuario():
    if request.method == 'POST':
        login = request.json.get('login')
        senha = request.json.get('senha')

        if not login or not senha:
            return jsonify({'error': 'Login e senha são obrigatórios'}), 400

        try:
            db = get_db()
            cursor = db.cursor()
            cursor.execute('SELECT * FROM usuarios WHERE login = ?', (login,))
            usuario = cursor.fetchone()

            if usuario:
                if usuario['status'] == 0:
                    return jsonify({'error': 'Usuário bloqueado, não é possível fazer login'}), 403

                if bcrypt.checkpw(senha.encode('utf-8'), usuario['senha']):
                    session['user_id'] = usuario['id']  # Armazenar o ID do usuário na sessão
                    session['is_admin'] = usuario['is_admin']  # Armazenar o status de administrador
                    return jsonify({'redirect': url_for('pagina_final')}), 200

            return jsonify({'error': 'Login ou senha inválidos'}), 401
        except sqlite3.Error as e:
            return jsonify({'error': str(e)}), 500
        finally:
            db.close()

    google_data = None
    github_data = None
    user_info_endpoint = '/oauth2/v2/userinfo'

    if google.authorized:
        google_data = google.get(user_info_endpoint).json()

    if github.authorized:
        github_data = github.get(user_info_endpoint).json()

    return render_template('login.html', google_data=google_data, github_data=github_data,
                           fetch_url=google.base_url + user_info_endpoint)

@app.route("/login/google")
def login_google():
    return redirect(url_for('google.login'))

@app.route("/login/github")
def login_github():
    return redirect(url_for('github.login'))

# Rota para solicitar redefinição de senha
@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']

        try:
            db = get_db()
            cursor = db.cursor()
            cursor.execute('SELECT * FROM usuarios WHERE login = ?', (email,))
            usuario = cursor.fetchone()

            if not usuario:
                flash('Este e-mail não está cadastrado.', category='error')
                return render_template('forgot_password.html')

            token = s.dumps(email, salt='password_recovery')
            msg = Message('Redefinição de senha', sender='', recipients=[email])

            link = url_for('reset_password', token=token, _external=True)
            msg.body = f'Clique no link para redefinir a sua senha: {link}'
            mail.send(msg)

            flash('Um link de recuperação de senha foi enviado para o seu email', category='success')
            return redirect(url_for('login_usuario'))

        except sqlite3.Error as e:
            flash('Erro ao acessar o banco de dados.', category='error')
            return render_template('forgot_password.html')
        finally:
            db.close()

    return render_template('forgot_password.html')

# Rota para redefinir a senha
@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    try:
        email = s.loads(token, salt='password_recovery', max_age=3600)  # 1h
    except SignatureExpired:
        return '<h1>O link de redefinição de senha expirou</h1>'
    except BadSignature:
        return '<h1>Token inválido</h1>'

    if request.method == 'POST':
        new_password = request.form['password']

        try:
            db = get_db()
            cursor = db.cursor()
            hashed_senha = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())
            cursor.execute('UPDATE usuarios SET senha = ? WHERE login = ?', (hashed_senha, email))
            db.commit()
            flash('Sua senha foi redefinida com sucesso!', category='success')
            return redirect(url_for('login_usuario'))
        except sqlite3.Error as e:
            flash('Erro ao atualizar a senha.', category='error')
            return render_template('reset_password.html', token=token)
        finally:
            db.close()

    return render_template('reset_password.html', token=token)

@app.route('/alteracao')
def alteracao():
    if 'is_admin' not in session or session['is_admin'] != 1:
        return redirect(url_for('forbidden'))

    return render_template('alteracao.html')

@app.route("/forbidden")
def forbidden():
    return render_template("403.html"), 403

@app.route('/usuarios/<int:usuario_id>', methods=['GET'])
def get_usuario(usuario_id):
   try:
       db = get_db()
       cursor = db.cursor()
       cursor.execute('SELECT id, login, nome, status FROM usuarios WHERE id = ?', (usuario_id,))
       usuario = cursor.fetchone()

       if usuario:
           return jsonify({
               'id': usuario['id'],
               'login': usuario['login'],
               'nome': usuario['nome'],
               'status': usuario['status']
           }), 200
       else:
           return jsonify({'error': 'Usuário não encontrado'}), 404
   except sqlite3.Error as e:
       return jsonify({'error': str(e)}), 500
   finally:
       db.close()

@app.route('/usuarios/<int:usuario_id>', methods=['PUT'])
def update_usuario(usuario_id):
   novo_login = request.json.get('login')
   senha = request.json.get('senha')
   nome = request.json.get('nome')
   status = request.json.get('status')

   try:
       db = get_db()
       cursor = db.cursor()
       cursor.execute('SELECT * FROM usuarios WHERE id = ?', (usuario_id,))
       usuario = cursor.fetchone()

       if not usuario:
           return jsonify({'error': 'Usuário não encontrado'}), 404

       if novo_login and novo_login != usuario['login']:
           cursor.execute('SELECT * FROM usuarios WHERE login = ? AND id != ?', (novo_login, usuario_id))
           if cursor.fetchone():
               return jsonify({'error': 'Login já existe'}), 400

       if senha:
           hashed_senha = bcrypt.hashpw(senha.encode('utf-8'), bcrypt.gensalt())
           cursor.execute('UPDATE usuarios SET login = ?, senha = ?, nome = ?, status = ?, modified = ? WHERE id = ?',
                          (novo_login if novo_login else usuario['login'], hashed_senha, nome if nome else usuario['nome'], status if status else usuario['status'], get_current_time(), usuario_id))
       else:
           cursor.execute('UPDATE usuarios SET login = ?, nome = ?, status = ?, modified = ? WHERE id = ?',
                          (novo_login if novo_login else usuario['login'], nome if nome else usuario['nome'], status if status else usuario['status'], get_current_time(), usuario_id))

       db.commit()
       return jsonify({'message': 'Usuário atualizado com sucesso!'})
   except sqlite3.Error as e:
       return jsonify({'error': str(e)}), 500
   finally:
       db.close()

@app.route('/usuarios/<int:usuario_id>', methods=['DELETE'])
def delete_usuario(usuario_id):
   try:
       db = get_db()
       cursor = db.cursor()
       cursor.execute('UPDATE usuarios SET status = 0 WHERE id = ?', (usuario_id,))
       db.commit()
       return jsonify({'message': 'Usuário bloqueado com sucesso'})
   except sqlite3.Error as e:
       return jsonify({'error': str(e)}), 500
   finally:
       db.close()

@app.route('/pagina_final')
def pagina_final():
    return render_template('pagina_final.html')

@app.route('/pagina_seguinte')
def pagina_seguinte():
    return render_template('pagina_seguinte.html')


@app.route('/navegar/<pagina>')
def navegar(pagina):
    if pagina == "final":
        return redirect(url_for('pagina_final'))
    elif pagina == "seguinte":
        return redirect(url_for('pagina_seguinte'))
    elif pagina == "forbidden":
        return redirect(url_for('forbidden'))
    else:
        return redirect(url_for('pagina_final'))

@app.route('/logout')
def logout():
    if google.authorized:
        token = google.access_token
        if token:
            resp = google.get('https://accounts.google.com/o/oauth2/revoke', params={'token': token})
            if resp.ok:
                print("Desconectado do Google com sucesso.")

    session.clear()

    return redirect(url_for('home'))

if __name__ == '__main__':
   app.run(debug=True)