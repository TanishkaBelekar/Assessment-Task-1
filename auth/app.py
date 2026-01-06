from flask import Flask, request, render_template, redirect, session, flash
from flask_sqlalchemy import SQLAlchemy
import bcrypt

app = Flask(__name__, template_folder='templates')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.secret_key = 'super_secret_key'

db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.LargeBinary(128), nullable=False)

    def __init__(self, name, email, password):
        self.name = name
        self.email = email
        self.password = bcrypt.hashpw(
            password.encode('utf-8'),
            bcrypt.gensalt()
        )

    def check_password(self, password):
        return bcrypt.checkpw(
            password.encode('utf-8'),
            self.password
        )

with app.app_context():
    db.create_all()


@app.route('/')
def home():
    return redirect('/login')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']

        
        if User.query.filter_by(email=email).first():
            return render_template(
                'register.html',
                error='Email already registered'
            )

        user = User(name=name, email=email, password=password)
        db.session.add(user)
        db.session.commit()

        return redirect('/login')

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        user = User.query.filter_by(email=email).first()

        if user and user.check_password(password):
            session['user'] = user.name
            return redirect('/dashboard')

        return render_template(
            'login.html',
            error='Invalid email or password'
        )

    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    if 'user' in session:
        return render_template('dashboard.html', name=session['user'])
    return redirect('/login')

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/login')


@app.route('/change_password', methods=['GET', 'POST'])
def change_password():
    if 'user' not in session:
        return redirect('/login')

    user = User.query.filter_by(name=session['user']).first()
    if not user:
        return redirect('/login')

    if request.method == 'POST':
        old_password = request.form['old_password']
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']

        if not user.check_password(old_password):
            return render_template('change_password.html', error='Old password is incorrect')

        if new_password != confirm_password:
            return render_template('change_password.html', error='New passwords do not match')

        #update password
        user.password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())
        db.session.commit()

        flash('Password changed successfully')
        return redirect('/dashboard')

    return render_template('change_password.html')


@app.route('/profile', methods=['GET', 'POST'])
def profile():
    if 'user' not in session:
        return redirect('/login')

    user = User.query.filter_by(name=session['user']).first()
    if not user:
        return redirect('/login')

    if request.method == 'POST':
        new_name = request.form['name']
        new_email = request.form['email']

        
        existing_user = User.query.filter_by(email=new_email).first()
        if existing_user and existing_user.id != user.id:
            return render_template('profile.html', user=user, error='Email already registered')

        user.name = new_name
        user.email = new_email
        db.session.commit()

        session['user'] = new_name 
        flash('Profile updated successfully')
        return redirect('/dashboard')

    return render_template('profile.html', user=user)




if __name__ == '__main__':
    app.run(debug=True)
