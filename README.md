#MedAura
ring(1from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from datetime import datetime
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///medical_app.db'
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.St20), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    role = db.Column(db.String(10), nullable=False, default='patient')
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_doctor = db.Column(db.Boolean, default=False)
    specialty = db.Column(db.String(100), nullable=True)
    contact_info = db.Column(db.String(200), nullable=True)
    trial_period_end = db.Column(db.DateTime, nullable=True)

    def __repr__(self):
        return f"User('{self.username}', '{self.email}', '{self.role}')"

class Department(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), unique=True, nullable=False)

    def __repr__(self):
        return f"Department('{self.name}')"

class Feedback(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    message = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f"Feedback('{self.message}')"

@app.route('/')
def home():
    if current_user.is_authenticated:
        if current_user.is_doctor:
            return redirect(url_for('doctor_dashboard'))
        else:
            return redirect(url_for('patient_dashboard'))
    else:
        return render_template('home.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        role = request.form.get('role')
        if role == 'doctor':
            specialty = request.form.get('specialty')
            contact_info = request.form.get('contact_info')
        else:
            specialty = None
            contact_info = None
        if username and email and password:
            hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
            user = User(username=username, email=email, password=hashed_password, role=role, specialty=specialty, contact_info=contact_info)
            try:
                db.session.add(user)
                db.session.commit()
                flash('Account created successfully!', 'success')
                return redirect(url_for('login'))
            except:
                flash('Username or email already exists.', 'danger')
        else:
            flash('Please fill all fields.', 'danger')
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        if user and bcrypt.check_password_hash(user.password, password):
            login_user(user)
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('home'))
        else:
            flash('Login unsuccessful. Please check your credentials.', 'danger')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))

@app.route('/doctor/dashboard')
@login_required
def doctor_dashboard():
    if current_user.role != 'doctor':
        return redirect(url_for('home'))
    return render_template('doctor_dashboard.html')

@app.route('/patient/dashboard')
@login_required
def patient_dashboard():
    if current_user.role != 'patient':
        return redirect(url_for('home'))
    departments = Department.query.all()
    return render_template('patient_dashboard.html', departments=departments)

@app.route('/departments/<department_id>')
@login_required
def department_doctors(department_id):
    if current_user.role != 'patient':
        return redirect(url_for('home'))
    department = Department.query.get_or_404(department_id)
    doctors = User.query.filter_by(role='doctor', is_active=True, specialty=department.name).all()
    return render_template('department_doctors.html', department=department, doctors=doctors)

@app.route('/doctor/<doctor_id>')
@login_required
def doctor_profile(doctor_id):
    if current_user.role != 'patient':
        return redirect(url_for('home'))
    doctor = User.query.get_or_404(doctor_id)
    return render_template('doctor_profile.html', doctor=doctor)

@app.route('/feedback', methods=['POST'])
@login_required
def feedback():
    message = request.form.get('message')
    if message:
        feedback = Feedback(user_id=current_user.id, message=message)
        db.session.add(feedback)
        db.session.commit()
        flash('Feedback submitted successfully!', 'success')
    return redirect(url_for('patient_dashboard'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        app.run(debug=True)
