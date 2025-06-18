# app.py
from flask import Flask, request, render_template, redirect, session, url_for, flash
from flask_talisman import Talisman
from config import Config
from models import db, User, Class, Team, TeamMembership, ReviewAssignment, ReviewQuestion, ReviewAnswer, JoinRequest
from werkzeug.security import generate_password_hash, check_password_hash
import os

app = Flask(__name__)
app.config.from_object(Config)
app.secret_key = 'super-secret-key'
db.init_app(app)

csp = {
    'default-src': "'self'",
    'style-src': ["'self'", 'https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css'],
    'script-src': ["'self'", 'https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js']
}
Talisman(app, content_security_policy=csp)

@app.route('/')
def index():
    return redirect('/register')

@app.route('/register', methods=['GET', 'POST'])
def register():
    classes = Class.query.all()
    if request.method == 'POST':
        first = request.form['first_name'].strip()
        last = request.form['last_name'].strip()
        email = request.form['email'].strip().lower()
        password = request.form['password']
        confirm = request.form['confirm_password']
        role = request.form['role']
        class_id = request.form.get('class_id')

        if not all([first, last, email, password, confirm, role]):
            flash("All fields are required.", "danger")
            return render_template('register.html', classes=classes)
        if password != confirm:
            flash("Passwords do not match.", "danger")
            return render_template('register.html', classes=classes)
        if User.query.filter_by(email=email).first():
            flash("Email already registered.", "warning")
            return render_template('register.html', classes=classes)

        user = User(first_name=first, last_name=last, email=email, role=role)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()

        if role == 'student' and class_id:
            req = JoinRequest(student_id=user.id, class_id=class_id)
            db.session.add(req)
            db.session.commit()

        flash("Account created successfully.", "success")
        return redirect('/login')
    return render_template('register.html', classes=classes)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        user = User.query.filter_by(email=email).first()
        if user and user.check_password(password):
            session['user_id'] = user.id
            if user.role == 'professor':
                return redirect('/dashboard')
            return redirect('/select_class')
        flash("Invalid credentials.", "danger")
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash("Logged out.", "info")
    return redirect('/login')

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

@app.route('/join_additional_class', methods=['GET', 'POST'])
def join_additional_class():
    user = User.query.get(session.get('user_id'))
    if not user or user.role != 'student':
        return redirect('/login')
    existing_class_ids = [Team.query.get(m.team_id).class_id for m in TeamMembership.query.filter_by(user_id=user.id).all()]
    available_classes = Class.query.filter(~Class.id.in_(existing_class_ids)).all()
    if request.method == 'POST':
        class_id = int(request.form['class_id'])
        req = JoinRequest(student_id=user.id, class_id=class_id)
        db.session.add(req)
        db.session.commit()
        flash("Join request sent.", "info")
        return redirect('/select_class')
    return render_template('join_additional_class.html', classes=available_classes)

@app.route('/dashboard')
def dashboard():
    user = User.query.get(session.get('user_id'))
    if not user:
        return redirect('/login')

    if user.role == 'professor':
        classes = Class.query.filter_by(professor_id=user.id).all()
        join_requests_by_class = {}
        student_ids = set()

        for cls in classes:
            cls.teams = Team.query.filter_by(class_id=cls.id).all()
            cls.students = (
                db.session.query(User)
                .join(TeamMembership, User.id == TeamMembership.user_id)
                .join(Team, TeamMembership.team_id == Team.id)
                .filter(Team.class_id == cls.id)
                .all()
            )
            cls.join_requests = JoinRequest.query.filter_by(class_id=cls.id, status='pending').all()
            for req in cls.join_requests:
                student_ids.add(req.student_id)

        students = User.query.filter(User.id.in_(student_ids)).all()
        student_map = {s.id: s for s in students}

        return render_template('professor_dashboard.html', user=user, classes=classes, student_map=student_map)

    elif user.role == 'student':
        class_id = session.get("class_id")
        if not class_id:
            return redirect("/select_class")
        membership = TeamMembership.query.join(Team).filter(
            Team.class_id == class_id,
            TeamMembership.user_id == user.id
        ).first()
        teammates, questions = [], []
        already_reviewed_ids = []

        if membership:
            team = Team.query.get(membership.team_id)
            teammates = [User.query.get(m.user_id) for m in TeamMembership.query.filter_by(team_id=team.id).all() if m.user_id != user.id]
            reviews_done = ReviewAnswer.query.filter_by(reviewer_id=user.id, class_id=class_id).all()
            already_reviewed_ids = list(set([r.reviewee_id for r in reviews_done]))
            questions = ReviewQuestion.query.filter_by(class_id=class_id).all()
            return render_template('student_dashboard.html', user=user, teammates=teammates,
                                   questions=questions, already_reviewed_ids=already_reviewed_ids,
                                   class_id=class_id, team_id=team.id)
        else:
            flash("Not in a team for this class.", "warning")
            return redirect('/select_class')


@app.route('/create_class_ui', methods=['POST'])
def create_class_ui():
    user = User.query.get(session.get('user_id'))
    if not user or user.role != 'professor':
        return redirect('/login')
    name = request.form['class_name'].strip()
    if not name:
        flash("Class name required.", "danger")
        return redirect('/dashboard')
    new_class = Class(name=name, professor_id=user.id)
    db.session.add(new_class)
    db.session.commit()
    flash(f"Class '{name}' created.", "success")
    return redirect('/dashboard')

@app.route('/create_team_ui', methods=['POST'])
def create_team_ui():
    class_id = int(request.form['class_id'])
    current_teams = Team.query.filter_by(class_id=class_id).count()
    new_team = Team(class_id=class_id)
    db.session.add(new_team)
    db.session.commit()
    flash("Team created successfully.", "success")
    return redirect(f'/class/{class_id}')

@app.route('/assign_student_ui', methods=['POST'])
def assign_student_ui():
    student_id = int(request.form['student_id'])
    team_id = int(request.form['team_id'])
    student = User.query.get(student_id)
    if not student or student.role != 'student':
        flash("Student not found.", "danger")
        return redirect('/dashboard')

    class_id = Team.query.get(team_id).class_id

    # Remove any existing team memberships in the same class
    existing = TeamMembership.query.filter_by(user_id=student_id).all()
    for m in existing:
        team = Team.query.get(m.team_id)
        if team and team.class_id == class_id:
            db.session.delete(m)

    membership = TeamMembership(user_id=student_id, team_id=team_id)
    db.session.add(membership)
    db.session.commit()

    flash(f"{student.first_name} assigned to Team {team_id}.", "success")
    return redirect(f'/class/{class_id}')

@app.route('/add_question/<int:class_id>', methods=['GET', 'POST'])
def add_question(class_id):
    user = User.query.get(session.get('user_id'))
    if not user or user.role != 'professor':
        return redirect('/login')
    if request.method == 'POST':
        text = request.form['question_text'].strip()
        if text:
            db.session.add(ReviewQuestion(class_id=class_id, question_text=text))
            db.session.commit()
            flash("Question added.", "success")
        return redirect(f"/add_question/{class_id}")
    questions = ReviewQuestion.query.filter_by(class_id=class_id).all()
    return render_template("add_question.html", class_id=class_id, questions=questions)

@app.route('/delete_question/<int:question_id>/<int:class_id>', methods=['POST'])
def delete_question(question_id, class_id):
    user = User.query.get(session.get('user_id'))
    if not user or user.role != 'professor':
        return redirect('/login')
    q = ReviewQuestion.query.get_or_404(question_id)
    db.session.delete(q)
    db.session.commit()
    flash("Question deleted.", "info")
    return redirect(f'/add_question/{class_id}')

@app.route('/submit_review_form', methods=['POST'])
def submit_review_form():
    user = User.query.get(session.get('user_id'))
    if not user or user.role != 'student':
        return redirect('/login')

    reviewee_id = int(request.form['reviewee_id'])
    class_id = int(request.form['class_id'])
    team_id = int(request.form['team_id'])

    # Remove previous answers and comment
    ReviewAnswer.query.filter_by(reviewer_id=user.id, reviewee_id=reviewee_id, class_id=class_id).delete()
    ReviewAssignment.query.filter_by(reviewer_id=user.id, reviewee_id=reviewee_id, class_id=class_id).delete()

    # Submit answers
    questions = ReviewQuestion.query.filter_by(class_id=class_id).all()
    for q in questions:
        score = int(request.form.get(f"q_{q.id}", 0))
        db.session.add(ReviewAnswer(
            reviewer_id=user.id,
            reviewee_id=reviewee_id,
            class_id=class_id,
            team_id=team_id,
            question_id=q.id,
            score=score
        ))

    comment = request.form.get('student_comment', '').strip()
    if comment:
        db.session.add(ReviewAssignment(
            reviewer_id=user.id,
            reviewee_id=reviewee_id,
            class_id=class_id,
            team_id=team_id,
            comment=comment
        ))

    db.session.commit()
    flash("Review submitted.", "success")
    return redirect('/dashboard')

@app.route('/class_summary/<int:class_id>')
def class_summary(class_id):
    user = User.query.get(session.get('user_id'))
    if not user or user.role != 'professor':
        return redirect('/login')

    teams = Team.query.filter_by(class_id=class_id).all()
    team_results = {}
    for team in teams:
        members = TeamMembership.query.filter_by(team_id=team.id).all()
        users = [User.query.get(m.user_id) for m in members]
        result_list = []
        for u in users:
            avg = db.session.query(db.func.avg(ReviewAnswer.score)).filter_by(class_id=class_id, reviewee_id=u.id).scalar()
            avg = round(avg or 0, 2)
            result_list.append({
                "id": u.id,
                "name": f"{u.first_name} {u.last_name}",
                "email": u.email,
                "average_score": avg
            })
        team_results[team.id] = result_list

    return render_template("class_summary.html", results_by_team=team_results, class_id=class_id)

@app.route('/review_detail/<int:class_id>/<int:student_id>')
def review_detail(class_id, student_id):
    user = User.query.get(session.get('user_id'))
    if not user or user.role != 'professor':
        flash("Access denied.", "danger")
        return redirect('/login')

    # Get reviewer
    student = User.query.get_or_404(student_id)

    # All answers that the student gave to others
    answers = ReviewAnswer.query.filter_by(class_id=class_id, reviewer_id=student_id).all()

    # Reviewees and questions mapping
    reviewees = {a.reviewee_id: User.query.get(a.reviewee_id) for a in answers}
    questions = {q.id: q.question_text for q in ReviewQuestion.query.filter_by(class_id=class_id).all()}

    # Get any comments submitted by the student for others
    comments = ReviewAssignment.query.filter_by(class_id=class_id, reviewer_id=student_id).all()
    comment_map = {c.reviewee_id: c.comment for c in comments}

    return render_template(
        "review_detail.html",
        student=student,
        class_id=class_id,
        answers=answers,
        questions=questions,
        reviewees=reviewees,
        comments_map=comment_map
    )

@app.route('/approve_join/<int:request_id>', methods=['POST'])
def approve_join(request_id):
    req = JoinRequest.query.get_or_404(request_id)
    if req.status != 'pending':
        flash("Already processed.", "warning")
        return redirect('/dashboard')

    first_team = Team.query.filter_by(class_id=req.class_id).first()
    if first_team:
        db.session.add(TeamMembership(user_id=req.student_id, team_id=first_team.id))
        req.status = 'approved'
        db.session.commit()
        flash("Student approved and added.", "success")
    else:
        flash("No team exists for this class.", "danger")
    return redirect('/dashboard')


@app.route('/reject_join/<int:request_id>', methods=['POST'])
def reject_join(request_id):
    req = JoinRequest.query.get_or_404(request_id)
    req.status = 'rejected'
    db.session.commit()
    flash("Request rejected.", "info")
    return redirect('/dashboard')

@app.route('/choose_class', methods=['POST'])
def choose_class():
    session['class_id'] = request.form['class_id']
    return redirect('/dashboard')

@app.route('/join_class', methods=['GET', 'POST'])
def join_class():
    user = User.query.get(session.get('user_id'))
    if not user or user.role != 'student':
        return redirect('/login')

    classes = Class.query.all()
    if request.method == 'POST':
        class_id = int(request.form['class_id'])

        # Check if already requested
        existing = JoinRequest.query.filter_by(student_id=user.id, class_id=class_id).first()
        if existing:
            flash("You already submitted a request for this class.", "info")
            return redirect('/dashboard')

        req = JoinRequest(student_id=user.id, class_id=class_id, status='pending')
        db.session.add(req)
        db.session.commit()
        flash("Join request submitted.", "success")
        return redirect('/dashboard')

    return render_template('join_class.html', classes=classes)

@app.route('/class_reviews/<int:class_id>')
def get_class_reviews(class_id):
    user = User.query.get(session.get('user_id'))
    if not user or user.role != 'professor':
        flash("Access denied.", "danger")
        return redirect('/login')

    # Get all ReviewAnswers for the class
    answers = ReviewAnswer.query.filter_by(class_id=class_id).all()

    # Calculate total score and count per student
    scores = {}
    counts = {}
    for a in answers:
        if a.reviewee_id not in scores:
            scores[a.reviewee_id] = 0
            counts[a.reviewee_id] = 0
        scores[a.reviewee_id] += a.score
        counts[a.reviewee_id] += 1

    # Format the results
    results = []
    for student_id, total_score in scores.items():
        student = User.query.get(student_id)
        avg_score = round(total_score / counts[student_id], 2)
        results.append({
            "student": f"{student.first_name} {student.last_name}",
            "email": student.email,
            "average_score": avg_score
        })

    return render_template("class_scores.html", scores=results, class_id=class_id)

@app.route('/class/<int:class_id>')
def class_dashboard(class_id):
    user = User.query.get(session.get('user_id'))
    if not user or user.role != 'professor':
        flash("Access denied.", "danger")
        return redirect('/login')

    cls = Class.query.get_or_404(class_id)
    teams = Team.query.filter_by(class_id=class_id).all()

    # Get only students registered for this class (via TeamMembership → Team → Class)
    enrolled_students = (
        db.session.query(User)
        .join(TeamMembership, User.id == TeamMembership.user_id)
        .join(Team, TeamMembership.team_id == Team.id)
        .filter(Team.class_id == class_id)
        .distinct()
        .all()
    )

    # Build a dictionary: team_id → [students]
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

# Final run setup for Render
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    port = int(os.environ.get("PORT", 5000))
    app.run(debug=False, host='0.0.0.0', port=port)

