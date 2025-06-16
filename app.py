# app.py
from flask import Flask, request, jsonify, render_template, redirect, session, url_for, flash
from flask_talisman import Talisman
from config import Config
from models import db, User, Class, Team, TeamMembership, ReviewAssignment, ReviewQuestion, ReviewAnswer
from werkzeug.security import generate_password_hash, check_password_hash
import os

app = Flask(__name__)
app.config.from_object(Config)
app.secret_key = 'super-secret-key'
db.init_app(app)

# Add this CSP dictionary
csp = {
    'default-src': "'self'",
    'style-src': [
        "'self'",
        'https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css'
    ],
    'script-src': [
        "'self'",
        'https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js'
    ]
}

# Attach Flask-Talisman with custom CSP
Talisman(app, content_security_policy=csp)


@app.route('/')
def index():
    return redirect('/login')

@app.route('/register', methods=['GET', 'POST'])
def register():
    classes = Class.query.all()

    if request.method == 'POST':
        first = request.form['first_name'].strip()
        last = request.form['last_name'].strip()
        email = request.form['email'].strip().lower()
        password = request.form['password']
        role = request.form['role']
        class_id = request.form.get('class_id')

        if not all([first, last, email, password, role]):
            flash("All fields are required.", "danger")
            return render_template('register.html', classes=classes)

        if User.query.filter_by(email=email).first():
            flash("That email is already registered.", "warning")
            return render_template('register.html', classes=classes)

        user = User(first_name=first, last_name=last, email=email, role=role)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()

        if class_id and role == 'student':
            default_team = Team.query.filter_by(class_id=class_id).first()
            if default_team:
                db.session.add(TeamMembership(user_id=user.id, team_id=default_team.id))
                db.session.commit()

        flash("Account created successfully. You can now log in.", "success")
        return redirect('/login')

    return render_template('register.html', classes=classes)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        try:
            email = request.form['email'].strip().lower()
            password = request.form['password']
        except KeyError:
            flash("Invalid form submission. Try again.", "danger")
            return render_template('login.html')

        user = User.query.filter_by(email=email).first()
        if user and user.check_password(password):
            session['user_id'] = user.id
            flash(f"Welcome back, {user.first_name}!", "success")
            return redirect('/dashboard')

        flash("Invalid credentials. Please try again.", "danger")
        return render_template('login.html')

    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash("You have been logged out.", "info")
    return redirect('/login')

@app.route('/dashboard')
def dashboard():
    user = User.query.get(session.get('user_id'))
    if not user:
        flash("Please log in to access your dashboard.", "warning")
        return redirect('/login')

    if user.role == 'professor':
        classes = Class.query.filter_by(professor_id=user.id).all()
        for cls in classes:
            cls.teams = Team.query.filter_by(class_id=cls.id).all()
        return render_template('professor_dashboard.html', user=user, classes=classes)

elif user.role == 'student':
    membership = TeamMembership.query.filter_by(user_id=user.id).first()
    teammates = []
    already_reviewed_ids = []

    if membership:
        team = Team.query.get(membership.team_id)
        if team:
            class_id = team.class_id
            # All teammates except self
            all_members = TeamMembership.query.filter_by(team_id=team.id).all()
            teammates = [User.query.get(m.user_id) for m in all_members if m.user_id != user.id]

            # Find who the student already reviewed
            reviews_done = ReviewAnswer.query.filter_by(reviewer_id=user.id, class_id=class_id).all()
            already_reviewed_ids = list(set([r.reviewee_id for r in reviews_done]))

            questions = ReviewQuestion.query.filter_by(class_id=class_id).all()
        else:
            questions = []
    else:
        questions = []

    return render_template('student_dashboard.html', user=user, teammates=teammates, questions=questions, already_reviewed_ids=already_reviewed_ids)


@app.route('/create_class_ui', methods=['POST'])
def create_class_ui():
    user = User.query.get(session.get('user_id'))
    if not user or user.role != 'professor':
        return redirect('/login')
    name = request.form['class_name'].strip()
    if not name:
        flash("Class name cannot be empty.", "danger")
        return redirect('/dashboard')
    new_class = Class(name=name, professor_id=user.id)
    db.session.add(new_class)
    db.session.commit()
    flash(f"Class '{name}' created.", "success")
    return redirect('/dashboard')

@app.route('/create_team_ui', methods=['POST'])
def create_team_ui():
    class_id = request.form['class_id']
    new_team = Team(class_id=class_id)
    db.session.add(new_team)
    db.session.commit()
    flash("Team created successfully.", "success")
    return redirect(f'/class/{class_id}')

@app.route('/assign_student_ui', methods=['POST'])
def assign_student_ui():
    email = request.form['student_email'].strip().lower()
    team_id = request.form['team_id']
    student = User.query.filter_by(email=email, role='student').first()
    if not student:
        flash("Student not found.", "danger")
        return redirect('/dashboard')

# Remove existing team memberships for this class
existing = TeamMembership.query.filter_by(user_id=student.id).all()
for m in existing:
    existing_team = Team.query.get(m.team_id)
    if existing_team and existing_team.class_id == Team.query.get(team_id).class_id:
        db.session.delete(m)

# Assign to new team
membership = TeamMembership(user_id=student.id, team_id=team_id)
db.session.add(membership)
    db.session.commit()

    # Get class ID from team
    team = Team.query.get(team_id)
    flash(f"{student.first_name} assigned to Team {team.id}", "success")
    return redirect(f'/class/{team.class_id}')


@app.route('/submit_review_form', methods=['POST'])
def submit_review_form():
    user = User.query.get(session.get('user_id'))
    if not user or user.role != 'student':
        return redirect('/login')
reviewee_id = int(request.form['reviewee_id'])
reviewee = User.query.get(reviewee_id)

    if not reviewee:
        flash("Reviewee not found.", "danger")
        return redirect('/dashboard')

    class_id = int(request.form['class_id'])
    team_id = int(request.form['team_id'])

    questions = ReviewQuestion.query.filter_by(class_id=class_id).all()

    for q in questions:
        score = int(request.form.get(f"q_{q.id}", 0))
        answer = ReviewAnswer(
            reviewer_id=user.id,
            reviewee_id=reviewee.id,
            class_id=class_id,
            team_id=team_id,
            question_id=q.id,
            score=score
        )
        db.session.add(answer)

    db.session.commit()
    flash("Review submitted successfully.", "success")
    return redirect('/dashboard')


@app.route('/class_reviews/<int:class_id>')
def get_class_reviews(class_id):
    user = User.query.get(session.get('user_id'))
    if not user or user.role != 'professor':
        flash("Access denied.", "danger")
        return redirect('/login')

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
            "student": f"{student.first_name} {student.last_name}",
            "email": student.email,
            "average_score": avg_score
        })

    return render_template("class_scores.html", scores=results)


@app.route('/class/<int:class_id>')
def class_dashboard(class_id):
    user = User.query.get(session.get('user_id'))
    if not user or user.role != 'professor':
        flash("Access denied.", "danger")
        return redirect('/login')

    cls = Class.query.get_or_404(class_id)
    teams = Team.query.filter_by(class_id=class_id).all()

    # Get all students enrolled in any team for this class

    # Build a dictionary: team_id -> list of students
    team_memberships = {}
    for team in teams:
        members = TeamMembership.query.filter_by(team_id=team.id).all()
        team_memberships[team.id] = [User.query.get(m.user_id) for m in members]

    return render_template(
        "class_dashboard.html",
        cls=cls,
        teams=teams,
        students=enrolled_students,
        team_memberships=team_memberships
    )


@app.route('/add_question/<int:class_id>', methods=['GET', 'POST'])
def add_question(class_id):
    user = User.query.get(session.get('user_id'))
    if not user or user.role != 'professor':
        flash("Access denied.", "danger")
        return redirect('/login')

    if request.method == 'POST':
        question_text = request.form['question_text'].strip()
        if not question_text:
            flash("Question text cannot be empty.", "danger")
        else:
            new_q = ReviewQuestion(class_id=class_id, question_text=question_text)
            db.session.add(new_q)
            db.session.commit()
            flash("Question added successfully.", "success")

        return redirect(f"/add_question/{class_id}")

    questions = ReviewQuestion.query.filter_by(class_id=class_id).all()
    return render_template("add_question.html", class_id=class_id, questions=questions)

@app.route('/class_summary/<int:class_id>')
def class_summary(class_id):
    user = User.query.get(session.get('user_id'))
    if not user or user.role != 'professor':
        flash("Access denied.", "danger")
        return redirect('/login')

    # Get scores from ReviewAnswer
    answers = ReviewAnswer.query.filter_by(class_id=class_id).all()
    students = {}

    for ans in answers:
        if ans.reviewee_id not in students:
            students[ans.reviewee_id] = []
        students[ans.reviewee_id].append(ans.score)

    results = []
    for student_id, scores in students.items():
        student = User.query.get(student_id)
        avg_score = round(sum(scores) / len(scores), 2)
        results.append({
            "student": f"{student.first_name} {student.last_name}",
            "email": student.email,
            "average_score": avg_score
        })

    # Get peer comments
    comments = ReviewAssignment.query.filter_by(class_id=class_id).all()

    return render_template("class_summary.html", results=results, comments=comments)


# Final run setup for Render
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    port = int(os.environ.get("PORT", 5000))
    app.run(debug=False, host='0.0.0.0', port=port)
