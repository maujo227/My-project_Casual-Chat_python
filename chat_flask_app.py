from flask import Flask, render_template, request, redirect, url_for, session, jsonify, flash, Response
from flask_sqlalchemy import SQLAlchemy
from werkzeug.utils import secure_filename
import os
from datetime import datetime
import bcrypt
import random
import time
import html
import secrets
from collections import defaultdict


# Configurazioni
UPLOAD_FOLDER = '/home/maujo227/chatmmy/uploads'  # Directory di upload
MAX_FILE_SIZE = 500 * 1024  # 500 KB in byte
ALLOWED_EXTENSIONS = {'jpeg', 'jpg', 'png', 'gif'}

def allowed_file(filename):
    """
    Verifica se il file ha un'estensione valida.
    """
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)  # Genera una chiave segreta casuale
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///chat.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = '/home/maujo227/chatmmy/static/uploads'

# Creazione della cartella uploads in /home/maujo227/chatmmy/uploads se non esiste
uploads_folder = app.config['UPLOAD_FOLDER']
if not os.path.exists(uploads_folder):
    os.makedirs(uploads_folder)

# Funzione di autenticazione
def check_auth(username, password):
    """Verifica username e password."""
    return username == 'ALAdino83' and password == 'PLUto270883##'

def authenticate():
    """Risponde con una richiesta di login."""
    return Response(
        'Devi effettuare l\'accesso per accedere a questa pagina.\n'
        'Usa username e password corretti.', 401,
        {'WWW-Authenticate': 'Basic realm="Login richiesto"'})

@app.before_request
def require_auth():
    """Protegge ogni richiesta con autenticazione."""
    auth = request.authorization
    if not auth or not check_auth(auth.username, auth.password):
        return authenticate()

# Rate limiting personalizzato per utente
WINDOW_SIZE = 60  # Finestra temporale in secondi
user_request_logs = defaultdict(list)
request_logs = defaultdict(list)  # Aggiunto per il fallback su IP

@app.before_request
def rate_limit():
    """Implementa il rate limiting personalizzato per utente."""
    if 'user_id' in session:
        user_id = session['user_id']
        current_time = time.time()

        # Rimuovi vecchie richieste fuori dalla finestra temporale
        user_request_logs[user_id] = [
            timestamp for timestamp in user_request_logs[user_id]
            if current_time - timestamp <= WINDOW_SIZE
        ]


        # Registra la nuova richiesta
        user_request_logs[user_id].append(current_time)
    else:
        # Limite basato sugli indirizzi IP per utenti non autenticati
        remote_addr = request.remote_addr
        current_time = time.time()

        request_logs[remote_addr] = [
            timestamp for timestamp in request_logs[remote_addr]
            if current_time - timestamp <= WINDOW_SIZE
        ]

        request_logs[remote_addr].append(current_time)

MAX_MESSAGE_LENGTH = 1000  # Lunghezza massima di un messaggio

db = SQLAlchemy(app)



# Database models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    photo = db.Column(db.String(100), nullable=False)
    age = db.Column(db.Integer, nullable=False)
    gender = db.Column(db.String(10), nullable=False)
    chatlanguage = db.Column(db.String(50), nullable=False)
    password = db.Column(db.String(100), nullable=False)
    is_online = db.Column(db.Boolean, default=False)
    switch_active = db.Column(db.Boolean, default=False)
    min_age = db.Column(db.Integer, nullable=False, default=18)  # Età minima con valore predefinito
    max_age = db.Column(db.Integer, nullable=False, default=100)  # Età massima con valore predefinito


class UserNewchat(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    added_at = db.Column(db.DateTime, default=db.func.now())  # Timestamp opzionale
    notified = db.Column(db.Boolean, default=False)  # Flag di notifica
    message_count = db.Column(db.Integer, default=0)  # Conteggio messaggi

    user = db.relationship('User', backref='newchat_entries')



class Favorite(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    favorite_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    receiver_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    content = db.Column(db.String(500), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

# Routes
@app.route('/')
def index():
    return render_template('index.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        photo = request.files['photo']
        try:
            age = int(request.form['age'])
        except ValueError:
            return jsonify({'success': False, 'message': 'Age must be a number'}), 400
        gender = request.form['gender']
        chatlanguage = request.form['chatlanguage']
        password = request.form['password']
        
        # Controlla se l'username è già preso
        if User.query.filter_by(username=username).first():
            return jsonify({'success': False, 'message': 'Username already taken'}), 400

        # Hash della password
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

        photo_path = ''
        if photo:
            # Controlla la dimensione del file
            photo.seek(0, os.SEEK_END)
            file_length = photo.tell()
            photo.seek(0)

            if file_length > MAX_FILE_SIZE:
                return jsonify({'success': False, 'message': 'Photo exceeds size limit of 500 KB'}), 400

            # Controlla estensione del file
            if allowed_file(photo.filename):
                # Salva il file in modo sicuro
                filename = secure_filename(f"{username}_{int(time.time())}_{photo.filename}")
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                photo.save(file_path)

                # Salva solo il percorso relativo
                photo_path = f"uploads/{filename}"
            else:
                return jsonify({'success': False, 'message': 'Unsupported file format. Use PNG, JPG, JPEG, or GIF.'}), 400

        # Crea l'utente
        user = User(username=username, photo=photo_path, age=age, gender=gender, chatlanguage=chatlanguage, password=hashed_password.decode('utf-8'))
        db.session.add(user)
        db.session.commit()

        return redirect(url_for('login'))

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = User.query.filter_by(username=username).first()
        if user and bcrypt.checkpw(password.encode('utf-8'), user.password.encode('utf-8')):
            session['user_id'] = user.id
            user.is_online = True
            db.session.commit()
            return redirect(url_for('home'))

        return 'Invalid credentials', 401

    return render_template('login.html')


@app.route('/forgotusername')
def forgot_username():
    return render_template('forgotusername.html')

@app.route('/forgotpassword')
def forgot_password():
    return render_template('forgotpassword.html')


@app.route('/update-username', methods=['POST'])
def update_username():
    new_username = request.form.get('new_username')
    password = request.form.get('password')

    if not new_username or not password:
        return "Both new username and password are required", 400

    user = User.query.filter_by(username=session.get('user_id')).first()
    if user and bcrypt.checkpw(password.encode('utf-8'), user.password.encode('utf-8')):
        if User.query.filter_by(username=new_username).first():
            return "Username already exists", 400

        user.username = new_username
        db.session.commit()
        return "Username updated successfully!"
    
    return "Invalid password", 401


@app.route('/update-password', methods=['POST'])
def update_password():
    username = request.form.get('username')
    new_password = request.form.get('new_password')

    if not username or not new_password:
        return "Both username and new password are required", 400

    user = User.query.filter_by(username=username).first()
    if user:
        hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())
        user.password = hashed_password.decode('utf-8')
        db.session.commit()
        return "Password updated successfully!"
    
    return "Invalid username", 401


@app.route('/home', methods=['GET', 'POST'])
def home():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user = User.query.get(session['user_id'])
    if not user:
        flash('Utente non trovato!', 'danger')
        return redirect(url_for('login'))

    # Normalizza le lingue salvate e quelle confrontate
    def normalize_languages(languages):
        if not languages:
            return []
        return sorted([lang.strip().lower() for lang in languages.split(',')])

    user_languages = normalize_languages(user.chatlanguage)
    switch_active = user.switch_active

    if switch_active:
        # Filtra i match in base alla lingua e all'età
        potential_matches = User.query.filter(
            User.id != user.id,
            User.is_online == True,
            User.age >= user.min_age,  # Filtro età minima
            User.age <= user.max_age,  # Filtro età massima
        ).all()

        # Filtra ulteriormente in base alla lingua
        potential_matches = [
            match for match in potential_matches
            if normalize_languages(match.chatlanguage) == user_languages
        ]
    else:
        # Mostra tutti gli utenti online filtrati per età
        potential_matches = User.query.filter(
            User.id != user.id,
            User.is_online == True,
            User.age >= user.min_age,  # Filtro età minima
            User.age <= user.max_age,  # Filtro età massima
        ).all()

    if potential_matches:
        match = random.choice(potential_matches)
        return render_template('home.html', match=match, user=user, switch_active=switch_active)

    return render_template('waiting.html', user=user, switch_active=switch_active)




@app.route('/check_for_match')
def check_for_match():
    if 'user_id' not in session:
        return jsonify({"redirect": url_for('login')})

    user = User.query.get(session['user_id'])
    potential_matches = User.query.filter(User.id != user.id, User.is_online == True).filter((User.age - user.age).between(-5, 5)).all()

    if potential_matches:
        return jsonify({"redirect": url_for('home')})

    return jsonify({"redirect": None})

@app.route('/chat/<int:match_id>')
def chat(match_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))  # Verifica che l'utente sia loggato

    # Recupera l'utente loggato
    user = User.query.get(session['user_id'])
    if not user:
        flash('User not found!', 'danger')  # Messaggio di errore se l'utente loggato non esiste
        return redirect(url_for('login'))

    # Recupera il match
    match = User.query.get(match_id)
    if not match:
        flash('Match not found!', 'danger')  # Messaggio di errore se il match non esiste
        return redirect(url_for('home'))

    # Aggiorna il percorso della foto del match
    match.photo = url_for('static', filename=f'uploads/{os.path.basename(match.photo)}')

    # Passa user e match al template
    return render_template('chat.html', user=user, match=match)



@app.route('/send_message/<int:receiver_id>', methods=['POST'])
def send_message(receiver_id):
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Effettua il login per inviare messaggi.'}), 401

    sender_id = session['user_id']
    current_time = time.time()

    # Rate limiting personalizzato per l'utente
    user_request_logs[sender_id] = [
        timestamp for timestamp in user_request_logs[sender_id]
        if current_time - timestamp <= WINDOW_SIZE
    ]

    # Registra la nuova richiesta
    user_request_logs[sender_id].append(current_time)

    data = request.get_json() or {}
    content = data.get('message', '').strip()

    # Verifica se il messaggio è vuoto o supera la lunghezza massima
    if not content:
        return jsonify({'success': False, 'message': 'Il messaggio non può essere vuoto.'}), 400
    if len(content) > MAX_MESSAGE_LENGTH:
        return jsonify({'success': False, 'message': 'Il messaggio supera la lunghezza massima consentita.'}), 400

    # Verifica che il destinatario esista
    receiver = User.query.get(receiver_id)
    if not receiver:
        return jsonify({'success': False, 'message': 'Destinatario non valido.'}), 404

    # Sanifica il contenuto del messaggio
    sanitized_content = html.escape(content)

    # Aggiungi il messaggio
    message = Message(sender_id=sender_id, receiver_id=receiver_id, content=sanitized_content)
    db.session.add(message)

    # Aggiorna o aggiungi il destinatario in UserNewchat
    user_newchat_entry = UserNewchat.query.filter_by(user_id=receiver_id).first()
    if user_newchat_entry:
        user_newchat_entry.message_count += 1
    else:
        user_newchat_entry = UserNewchat(user_id=receiver_id, message_count=1)
        db.session.add(user_newchat_entry)

    # Aggiungi il mittente a UserNewchat se non esiste
    if not UserNewchat.query.filter_by(user_id=sender_id).first():
        new_entry_sender = UserNewchat(user_id=sender_id, message_count=0)
        db.session.add(new_entry_sender)

    db.session.commit()
    return jsonify({'success': True, 'message': 'Messaggio inviato con successo.'}), 204


@app.route('/get_messages/<int:chat_id>', methods=['GET'])
def get_messages(chat_id):
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Effettua il login per visualizzare i messaggi.'}), 401

    user_id = session['user_id']

    # Verifica che l'utente abbia i permessi per visualizzare i messaggi
    chat_user = User.query.get(chat_id)
    if not chat_user:
        return jsonify({'success': False, 'message': 'Chat non trovata.'}), 404

    # Recupera i messaggi tra gli utenti
    messages = Message.query.filter(
        ((Message.sender_id == user_id) & (Message.receiver_id == chat_id)) |
        ((Message.sender_id == chat_id) & (Message.receiver_id == user_id))
    ).order_by(Message.timestamp).all()

    # Costruisci la risposta
    return jsonify([
        {
            "sender": "me" if msg.sender_id == user_id else "them",
            "username": User.query.get(msg.sender_id).username,
            "content": html.escape(msg.content)  # Sanifica l'output
        } for msg in messages
    ])

@app.route('/favorite/<int:match_id>', methods=['POST'])
def favorite(match_id):
    if 'user_id' not in session:
        return jsonify({"success": False, "error": "User not logged in"}), 403

    user_id = session['user_id']

    if user_id == match_id:
        return jsonify({"success": False, "error": "You cannot add yourself to favorites."}), 400

    existing_favorite = Favorite.query.filter_by(user_id=user_id, favorite_id=match_id).first()

    if not existing_favorite:
        favorite = Favorite(user_id=user_id, favorite_id=match_id)
        db.session.add(favorite)
        db.session.commit()
        return jsonify({"success": True, "message": "User added to favorites successfully."})

    return jsonify({"success": False, "message": "User already in favorites."})  

@app.route('/skip')
def skip():
    return redirect(url_for('home'))

@app.route('/favorites')
def favorites():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    favorites = Favorite.query.filter_by(user_id=session['user_id']).all()
    favorite_users = [User.query.get(f.favorite_id) for f in favorites]
    return render_template('favorites.html', favorites=favorite_users)

@app.route('/remove_favorite/<int:favorite_id>')
def remove_favorite(favorite_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    favorite = Favorite.query.filter_by(user_id=session['user_id'], favorite_id=favorite_id).first()
    if favorite:
        db.session.delete(favorite)
        db.session.commit()

    return redirect(url_for('favorites'))


@app.route('/newchat')
def newchat():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    current_user_id = session['user_id']

    try:
        # Recupera o crea l'entry per l'utente corrente in UserNewchat
        user_newchat_entry = UserNewchat.query.filter_by(user_id=current_user_id).first()
        if not user_newchat_entry:
            user_newchat_entry = UserNewchat(user_id=current_user_id, added_at=datetime.utcnow())
            db.session.add(user_newchat_entry)
            db.session.commit()

        # Memorizza il valore di `added_at` prima di aggiornarlo
        last_checked = user_newchat_entry.added_at

        # Recupera tutti gli utenti che hanno inviato messaggi in passato
        all_messages_users = (
            db.session.query(User, db.func.count(Message.id).label('total_message_count'))
            .join(Message, User.id == Message.sender_id)
            .filter(Message.receiver_id == current_user_id)
            .group_by(User.id)
            .order_by(db.func.max(Message.timestamp).desc())
            .all()
        )

        # Recupera gli utenti con nuovi messaggi
        new_messages_users = {
            user.id: count for user, count in (
                db.session.query(User, db.func.count(Message.id).label('new_message_count'))
                .join(Message, User.id == Message.sender_id)
                .filter(Message.receiver_id == current_user_id)
                .filter(Message.timestamp > last_checked)  # Considera solo i nuovi messaggi
                .group_by(User.id)
                .all()
            )
        }

        # Aggiorna il timestamp di `added_at` a ora per segnare i messaggi come letti
        user_newchat_entry.added_at = datetime.utcnow()
        db.session.commit()

        # Combina i dati di tutti gli utenti con quelli che hanno nuovi messaggi
        users_with_message_count = []
        for user, total_message_count in all_messages_users:
            new_message_count = new_messages_users.get(user.id, 0)  # Prendi il conteggio dei nuovi messaggi, 0 se nessuno
            is_new = new_message_count > 0  # Indica se ci sono nuovi messaggi
            users_with_message_count.append((user, new_message_count if is_new else total_message_count, is_new))

        return render_template('newchat.html', users=users_with_message_count)

    except Exception as e:
        print("Errore durante il caricamento di newchat:", e)
        return "Internal Server Error", 500






@app.route('/add-to-newchat', methods=['POST'])
def add_to_newchat():
    data = request.json
    user_id = data.get('userId')

    if not user_id:
        return jsonify({"error": "User ID is required"}), 400

    # Controlla che l'utente esista
    user_exists = User.query.get(user_id)
    if not user_exists:
        return jsonify({"error": "User does not exist"}), 400

    # Controlla se l'utente è già nella tabella
    existing_entry = UserNewchat.query.filter_by(user_id=user_id).first()
    if existing_entry:
        return jsonify({"message": "User already added to newchat"}), 200

    # Aggiungi l'utente alla tabella UserNewchat
    new_entry = UserNewchat(user_id=user_id)
    db.session.add(new_entry)
    db.session.commit()

    return jsonify({"message": "User added to newchat successfully"}), 201




@app.route('/remove_from_newchat/<int:user_id>', methods=['POST'])
def remove_from_newchat(user_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    # Trova l'entry dell'utente nella tabella UserNewchat
    entry = UserNewchat.query.filter_by(user_id=user_id).first()
    if entry:
        db.session.delete(entry)
        db.session.commit()
        flash("User removed from Newchat successfully.", "success")
    else:
        flash("User not found in Newchat.", "danger")

    return redirect(url_for('newchat'))


@app.route('/settings', methods=['GET', 'POST'])
def settings():
    # Controlla se l'utente è loggato
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Effettua il login per accedere alle impostazioni.'}), 401

    # Recupera l'utente corrente dalla sessione
    user = User.query.get(session['user_id'])
    if not user:
        return jsonify({'success': False, 'message': 'Utente non trovato.'}), 404

    # Inizializza valori di default per min_age e max_age alla prima apertura
    if user.min_age is None or user.max_age is None:
        user.min_age = user.min_age or 18
        user.max_age = user.max_age or 100
        db.session.commit()

    if request.method == 'POST':
        try:
            # Validazione di min_age e max_age
            min_age = request.form.get('min_age', None)
            max_age = request.form.get('max_age', None)
            if min_age:
                min_age = int(min_age)
                if min_age < 18 or min_age > 100:
                    return jsonify({'success': False, 'message': 'Invalid min_age. Must be between 18 and 100.'}), 400
                user.min_age = min_age

            if max_age:
                max_age = int(max_age)
                if max_age < 18 or max_age > 100 or max_age < user.min_age:
                    return jsonify({'success': False, 'message': 'Invalid max_age. Must be between 18 and 100, and greater than or equal to min_age.'}), 400
                user.max_age = max_age

            # Aggiorna altri campi (validazione base)
            age = request.form.get('age', None)
            if age:
                age = int(age)
                if age < 18 or age > 100:
                    return jsonify({'success': False, 'message': 'Invalid age. Must be between 18 and 100.'}), 400
                user.age = age

            chatlanguage = request.form.get('chatlanguage', '').strip()
            user.chatlanguage = chatlanguage

            user.switch_active = 'switch' in request.form

            # Gestione dell'upload della foto
            if 'photo' in request.files:
                file = request.files['photo']
                if file and file.filename:
                    # Verifica la dimensione del file
                    file.seek(0, os.SEEK_END)
                    file_length = file.tell()
                    file.seek(0)

                    if file_length > MAX_FILE_SIZE:
                        return jsonify({'success': False, 'message': 'Photo exceeds size limit of 500 KB.'}), 400

                    # Controlla l'estensione del file
                    if allowed_file(file.filename):
                        # Cancella la foto attuale se esiste
                        if user.photo:
                            old_photo_path = os.path.join(app.config['UPLOAD_FOLDER'], user.photo)
                            if os.path.exists(old_photo_path):
                                os.remove(old_photo_path)

                        # Salva il nuovo file
                        filename = secure_filename(f"{user.id}_{int(time.time())}_{file.filename}")
                        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                        file.save(file_path)

                        # Salva solo il percorso relativo
                        user.photo = f"uploads/{filename}"
                    else:
                        return jsonify({'success': False, 'message': 'Unsupported file format. Use PNG, JPG, JPEG, or GIF.'}), 400

            db.session.commit()
        except Exception as e:
            return jsonify({'success': False, 'message': 'An error occurred while processing your request.'}), 500

    return render_template('settings.html', user=user)




@app.route('/logout')
def logout():
    if 'user_id' in session:
        user = User.query.get(session['user_id'])
        user.is_online = False
        db.session.commit()
        session.pop('user_id', None)
    return redirect(url_for('index'))

@app.context_processor
def inject_year():
    from datetime import datetime
    return {'year': datetime.now().year}

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=False)