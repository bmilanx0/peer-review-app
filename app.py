# app.py
from flask import Flask, request, jsonify, render_template, redirect, session, url_for
from flask_talisman import Talisman
from config import Config
from models import db, User, Class, Team, TeamMembership, ReviewAssignment
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config.from_object(Config)
app.secret_key = 'super-secret-key'
db.init_app(app)
Talisman(app)  # Enforce HTTPS + security headers

@app.route('/')
def index():
    return redirect('/login')

@app.route('/register', methods=['GET', 'POST'])
def register():
    classes = Class.query.all()

    if request.method == 'POST':
        first = request.form['first_name']
        last = request.form['last_name']
        email = request.form['email']
        password = request.form['password']
        role = request.form['role']
        class_id = request.form.get('class_id')

        if role not in ['student', 'professor']:
            return "Invalid role", 400

        if User.query.filter_by(email=email).first():
            return "Email already registered", 400

        user = User(first_name=first, last_name=last, email=email, role=role)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()

        if class_id and role == 'student':
            default_team = Team.query.filter_by(class_id=class_id).first()
            if default_team:
                db.session.add(TeamMembership(user_id=user.id, team_id=default_team.id))
                db.session.commit()

        return redirect('/login')

    return render_template('register.html', classes=classes)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        try:
            email = request.form['email']
            password = request.form['password']
        except KeyError:
            return render_template('login.html', error="Missing form fields. Please try again.")

        user = User.query.filter_by(email=email).first()
        if user and user.check_password(password):
            session['user_id'] = user.id
            return redirect('/dashboard')
        return render_template('login.html', error="Invalid credentials. Please try again.")
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/login')

@app.route('/dashboard')
def dashboard():
    user = User.query.get(session.get('user_id'))
    if not user:
        return redirect('/login')

    if user.role == 'professor':
        classes = Class.query.filter_by(professor_id=user.id).all()
        for cls in classes:
            cls.teams = Team.query.filter_by(class_id=cls.id).all()
        return render_template('professor_dashboard.html', user=user, classes=classes)
    
    elif user.role == 'student':
        return render_template('student_dashboard.html', user=user)

@app.route('/create_class_ui', methods=['POST'])
def create_class_ui():
    user = User.query.get(session.get('user_id'))
    if not user or user.role != 'professor':
        return redirect('/login')
    name = request.form['class_name']
    new_class = Class(name=name, professor_id=user.id)
    db.session.add(new_class)
    db.session.commit()
    return redirect('/dashboard')

@app.route('/create_team_ui', methods=['POST'])
def create_team_ui():
    class_id = request.form['class_id']
    new_team = Team(class_id=class_id)
    db.session.add(new_team)
    db.session.commit()
    return redirect('/dashboard')

@app.route('/assign_student_ui', methods=['POST'])
def assign_student_ui():
    email = request.form['student_email']
    team_id = request.form['team_id']

    student = User.query.filter_by(email=email, role='student').first()
    if not student:
        return "Student not found", 404

    membership = TeamMembership(user_id=student.id, team_id=team_id)
    db.session.add(membership)
    db.session.commit()
    return redirect('/dashboard')

@app.route('/submit_review_form', methods=['POST'])
def submit_review_form():
    user = User.query.get(session.get('user_id'))
    if not user or user.role != 'student':
        return redirect('/login')

    data = request.form
    reviewee = User.query.filter_by(email=data['reviewee_email']).first()
    if not reviewee:
        return "Reviewee not found", 404

    review = ReviewAssignment(
        reviewer_id=user.id,
        reviewee_id=reviewee.id,
        class_id=data['class_id'],
        team_id=data['team_id'],
        score=data['score'],
        comment=data['comment']
    )
    db.session.add(review)
    db.session.commit()
    return redirect('/dashboard')

@app.route('/reviews/<int:team_id>', methods=['GET'])
def get_reviews_for_team(team_id):
    reviews = ReviewAssignment.query.filter_by(team_id=team_id).all()
    results = []
    for r in reviews:
        reviewer = User.query.get(r.reviewer_id)
        reviewee = User.query.get(r.reviewee_id)
        results.append({
            "from": reviewer.first_name + " " + reviewer.last_name,
            "to": reviewee.first_name + " " + reviewee.last_name,
            "score": r.score,
            "comment": r.comment
        })
    return jsonify(results)

@app.route('/class_reviews/<int:class_id>', methods=['GET'])
def get_class_reviews(class_id):
    reviews = ReviewAssignment.query.filter_by(class_id=class_id).all()
    scores = {}
    counts = {}

    for r in reviews:
        if r.reviewee_id not in scores:
            scores[r.reviewee_id] = 0
            counts[r.reviewee_id] = 0
        scores[r.reviewee_id] += int(r.score)
        counts[r.reviewee_id] += 1

    results = []
    for student_id, total_score in scores.items():
        student = User.query.get(student_id)
        avg_score = round(total_score / counts[student_id], 2)
        results.append({
            "student": student.first_name + " " + student.last_name,
            "email": student.email,
            "average_score": avg_score
        })

    return jsonify(results)

import os

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    port = int(os.environ.get("PORT", 5000))
    app.run(debug=False, host='0.0.0.0', port=port)

