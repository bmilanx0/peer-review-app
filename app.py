# app.py
from flask import Flask, request, jsonify, render_template, redirect, session, url_for, flash, abort
from flask_talisman import Talisman
from flask_login import current_user, login_required
from config import Config
from models import db, User, Class, Team, TeamMembership, ReviewAssignment, ReviewQuestion, ReviewAnswer, JoinRequest
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
        confirm_password = request.form['confirm_password']
        role = request.form['role']
        class_id = request.form.get('class_id')

        if not all([first, last, email, password, confirm_password, role]):
            flash("All fields are required.", "danger")
            return render_template('register.html', classes=classes)

        if password != confirm_password:
            flash("Passwords do not match.", "danger")
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


@app.route('/student/join_class', methods=['GET', 'POST'])
@login_required
def join_class():
    if current_user.role != 'student':
        abort(403)

    if request.method == 'POST':
        class_id = int(request.form['class_id'])
        existing = JoinRequest.query.filter_by(student_id=current_user.id, class_id=class_id).first()
        if not existing:
            db.session.add(JoinRequest(student_id=current_user.id, class_id=class_id, approved=False))
            db.session.commit()
            flash("Join request submitted.")
        else:
            flash("You have already submitted a request for this class.")
        return redirect(url_for('student_dashboard'))

    classes = Class.query.all()
    return render_template('join_class.html', classes=classes)

@app.route('/approve_join/<int:request_id>', methods=['POST'])
def approve_join(request_id):
    req = JoinRequest.query.get_or_404(request_id)
    if req.status != 'pending':
        flash("Request already processed.", "warning")
        return redirect('/dashboard')

    team = Team.query.filter_by(class_id=req.class_id).first()
    if team:
        membership = TeamMembership(user_id=req.student_id, team_id=team.id)
        db.session.add(membership)
        req.status = 'approved'
        db.session.commit()
        flash("Student approved and added to class.", "success")
    else:
        flash("No team exists for this class yet.", "danger")

    return redirect('/dashboard')

@app.route('/reject_join/<int:request_id>', methods=['POST'])
def reject_join(request_id):
    req = JoinRequest.query.get_or_404(request_id)
    req.status = 'rejected'
    db.session.commit()
    flash("Join request rejected.", "info")
    return redirect('/dashboard')

@app.route('/professor/approve_requests/<int:class_id>', methods=['GET', 'POST'])
@login_required
def approve_requests(class_id):
    if current_user.role != 'professor':
        abort(403)

    if request.method == 'POST':
        for req_id, decision in request.form.items():
            join_request = JoinRequest.query.get(int(req_id))
            if decision == 'approve':
                join_request.approved = True
            elif decision == 'deny':
                db.session.delete(join_request)
        db.session.commit()
        flash("Join requests updated.")
        return redirect(url_for('class_dashboard', class_id=class_id))

    requests = JoinRequest.query.filter_by(class_id=class_id, approved=False).all()
    return render_template('approve_requests.html', requests=requests)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')

        user = User.query.filter_by(email=email).first()
        if user and user.check_password(password):
            session['user_id'] = user.id

            if user.role == 'professor':
                flash(f"Welcome, {user.first_name}!", "success")
                return redirect('/dashboard')

            elif user.role == 'student':
                flash(f"Welcome, {user.first_name}!", "success")
                return redirect('/select_class')

        flash("Invalid credentials. Please try again.", "danger")
        return render_template('login.html')

    return render_template('login.html')


@app.route('/select_class', methods=['GET', 'POST'])
def select_class():
    user = User.query.get(session.get('user_id'))
    if not user or user.role != 'student':
        return redirect('/login')

    memberships = TeamMembership.query.filter_by(user_id=user.id).all()
    class_ids = list(set([Team.query.get(m.team_id).class_id for m in memberships]))
    classes = Class.query.filter(Class.id.in_(class_ids)).all()

    if request.method == 'POST':
        session['class_id'] = int(request.form['class_id'])
        return redirect('/dashboard')

    return render_template('select_class.html', classes=classes)


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
            cls.students = (
                db.session.query(User)
                .join(TeamMembership, User.id == TeamMembership.user_id)
                .join(Team, TeamMembership.team_id == Team.id)
                .filter(Team.class_id == cls.id)
                .distinct()
                .all()
            )
            cls.join_requests = JoinRequest.query.filter_by(class_id=cls.id, status='pending').all()
        return render_template('professor_dashboard.html', user=user, classes=classes)

    elif user.role == 'student':
        class_id = session.get("class_id")
        if not class_id:
            flash("Please select a class to continue.", "info")
            return redirect("/select_class")

        membership = TeamMembership.query.join(Team).filter(
            Team.class_id == class_id,
            TeamMembership.user_id == user.id
        ).first()

        teammates = []
        already_reviewed_ids = []

        if membership:
            team = Team.query.get(membership.team_id)
            all_members = TeamMembership.query.filter_by(team_id=team.id).all()
            teammates = [User.query.get(m.user_id) for m in all_members if m.user_id != user.id]

            reviews_done = ReviewAnswer.query.filter_by(reviewer_id=user.id, class_id=class_id).all()
            already_reviewed_ids = list(set([r.reviewee_id for r in reviews_done]))

            questions = ReviewQuestion.query.filter_by(class_id=class_id).all()
            return render_template('student_dashboard.html',
                                   user=user,
                                   teammates=teammates,
                                   questions=questions,
                                   already_reviewed_ids=already_reviewed_ids,
                                   class_id=class_id,
                                   team_id=team.id)
        else:
            flash("You're not yet in a team for this class.", "warning")
            return redirect('/select_class')

    flash("Unknown user role.", "danger")
    return redirect('/login')



@app.route('/choose_class', methods=['POST'])
def choose_class():
    session['class_id'] = request.form['class_id']
    return redirect('/dashboard')


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

@app.route('/professor/create_team/<int:class_id>', methods=['POST'])
@login_required
def create_team(class_id):
    if current_user.role != 'professor':
        abort(403)

    team_count = Team.query.filter_by(class_id=class_id).count()
    new_team_name = f"Team {team_count + 1}"
    team = Team(name=new_team_name, class_id=class_id)
    db.session.add(team)
    db.session.commit()
    flash("Team created.")
    return redirect(url_for('class_dashboard', class_id=class_id))

@app.route('/professor/class/<int:class_id>')
@login_required
def class_dashboard(class_id):
    if current_user.role != 'professor':
        abort(403)

    approved_students = db.session.query(Student).join(JoinRequest).filter(
        JoinRequest.class_id == class_id,
        JoinRequest.approved == True
    ).all()

    teams = Team.query.filter_by(class_id=class_id).all()
    return render_template('class_dashboard.html', students=approved_students, teams=teams, class_id=class_id)

@app.route('/student/class/<int:class_id>')
@login_required
def student_class_view(class_id):
    if current_user.role != 'student':
        abort(403)

    approved = JoinRequest.query.filter_by(student_id=current_user.id, class_id=class_id, approved=True).first()
    if not approved:
        flash("You are not registered in this class.")
        return redirect(url_for('student_dashboard'))

    team = db.session.query(Team).join(StudentTeam).filter(
        Team.class_id == class_id,
        StudentTeam.student_id == current_user.id
    ).first()

    if not team:
        flash("You are not assigned to a team in this class.")

    return render_template('student_class_view.html', team=team, class_id=class_id)


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
    # Remove existing answers by this student for this reviewee in this class/team
    existing_answers = ReviewAnswer.query.filter_by(
        reviewer_id=user.id,
        reviewee_id=reviewee.id,
        class_id=class_id,
        team_id=team_id
    ).all()
    for ea in existing_answers:
        db.session.delete(ea)

    # Remove existing comment for this reviewee by this reviewer
    existing_comment = ReviewAssignment.query.filter_by(
        reviewer_id=user.id,
        reviewee_id=reviewee.id,
        class_id=class_id
    ).first()
    if existing_comment:
        db.session.delete(existing_comment)

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

    # Get the comment from the form AFTER the loop
    student_comment = request.form.get('student_comment', '').strip()

    if student_comment:
        comment_entry = ReviewAssignment(
            reviewer_id=user.id,
            reviewee_id=reviewee.id,
            class_id=class_id,
            comment=student_comment
        )
        db.session.add(comment_entry)

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

    # Add this line to define enrolled_students
    enrolled_students = User.query.filter_by(role='student').all()

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

@app.route('/delete_question/<int:question_id>/<int:class_id>', methods=['POST'])
def delete_question(question_id, class_id):
    user = User.query.get(session.get('user_id'))
    if not user or user.role != 'professor':
        flash("Access denied.", "danger")
        return redirect('/login')

    question = ReviewQuestion.query.get_or_404(question_id)
    db.session.delete(question)
    db.session.commit()
    flash("Question deleted.", "info")
    return redirect(f'/add_question/{class_id}')

@app.route('/class_summary/<int:class_id>')
def class_summary(class_id):
    user = User.query.get(session.get('user_id'))
    if not user or user.role != 'professor':
        flash("Access denied.", "danger")
        return redirect('/login')

    # Get teams in this class
    teams = Team.query.filter_by(class_id=class_id).all()
    team_memberships = {}
    all_students = []

    for team in teams:
        members = TeamMembership.query.filter_by(team_id=team.id).all()
        users = [User.query.get(m.user_id) for m in members]
        team_memberships[team.id] = users
        all_students.extend(users)

    # Remove duplicates
    all_students = list({s.id: s for s in all_students}.values())

    # Gather scores per student
    answers = ReviewAnswer.query.filter_by(class_id=class_id).all()
    scores = {}
    counts = {}
    for a in answers:
        if a.reviewee_id not in scores:
            scores[a.reviewee_id] = 0
            counts[a.reviewee_id] = 0
        scores[a.reviewee_id] += a.score
        counts[a.reviewee_id] += 1

    # Compile result rows
    results = []
    for student in all_students:
        avg_score = round(scores.get(student.id, 0) / counts.get(student.id, 1), 2)
        team_id = TeamMembership.query.filter_by(user_id=student.id).first().team_id
        results.append({
            "student": f"{student.first_name} {student.last_name}",
            "email": student.email,
            "average_score": avg_score,
            "team": team_id,
            "id": student.id
        })

    return render_template("class_summary.html", results=results, class_id=class_id)



@app.route('/review_detail/<int:class_id>/<int:student_id>')
def review_detail(class_id, student_id):
    user = User.query.get(session.get('user_id'))
    if not user or user.role != 'professor':
        flash("Access denied.", "danger")
        return redirect('/login')

    # Get the student object for header
    student = User.query.get_or_404(student_id)

    # Get all scores given by the student in that class
    answers = ReviewAnswer.query.filter_by(class_id=class_id, reviewer_id=student_id).all()
    questions = {q.id: q.question_text for q in ReviewQuestion.query.filter_by(class_id=class_id).all()}
    reviewees = {a.reviewee_id: User.query.get(a.reviewee_id) for a in answers}

    # Get overall comment
    assignments = ReviewAssignment.query.filter_by(class_id=class_id, reviewer_id=student_id).all()
    comments_map = {a.reviewee_id: a.comment for a in assignments}

    return render_template(
        "review_detail.html",
        student=student,
        answers=answers,
        questions=questions,
        reviewees=reviewees,
        comments_map=comments_map
    )




# Final run setup for Render
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    port = int(os.environ.get("PORT", 5000))
    app.run(debug=False, host='0.0.0.0', port=port)

