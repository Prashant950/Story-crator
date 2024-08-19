from flask import Flask, render_template, request, redirect, url_for, flash,send_from_directory
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from datetime import datetime
from werkzeug.utils import secure_filename
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = 'singh'
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:@localhost/story_creator'
app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), nullable=False, unique=True)
    email = db.Column(db.String(150), nullable=False, unique=True)
    password = db.Column(db.String(150), nullable=False)

class Story(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(150), nullable=False)
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    image_filename = db.Column(db.String(150), nullable=True)
    contributions = db.relationship('Contribution', backref='story', lazy=True)

class Contribution(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    story_id = db.Column(db.Integer, db.ForeignKey('story.id'), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def allowed_file(filename):
    allowed_extensions = {'png', 'jpg', 'jpeg', 'gif','pdf'}
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in allowed_extensions

# Routes
@app.route('/')
def login_1():
    return render_template('login.html')

@app.route('/home')
@login_required
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()

        if user and check_password_hash(user.password, password):
            login_user(user)
            flash('Logged in successfully!', 'success')
            return redirect(url_for('index'))

        flash('Invalid credentials', 'danger')
        return redirect(url_for('login'))

    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['fullname']
        email = request.form['email']
        password = request.form['password']

        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        new_user = User(username=username, email=email, password=hashed_password)

        try:
            db.session.add(new_user)
            db.session.commit()
            flash('User registered successfully', 'success')
            return redirect(url_for('login_1'))
        except Exception as e:
            db.session.rollback()
            flash(f'An error occurred: {e}', 'danger')

    return render_template('register.html')

@app.route('/create-stories', methods=['GET'])
@login_required
def create_story_form():
    return render_template('create_story.html')

@app.route('/stories', methods=['POST'])
@login_required
def create_story():
    title = request.form['title']
    content = request.form['content']

    # Handle file upload
    image = request.files.get('image')
    filename = None
    if image and allowed_file(image.filename):
        filename = secure_filename(image.filename)
        image.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
    else:
        filename = None  # No image uploaded or invalid file type

    # Create the story and store the image filename
    new_story = Story(title=title, created_by=current_user.id, image_filename=filename)
    db.session.add(new_story)
    db.session.commit()

    # Create the first contribution
    new_contribution = Contribution(content=content, user_id=current_user.id, story_id=new_story.id)
    db.session.add(new_contribution)
    db.session.commit()

    flash('Story created successfully!', 'success')
    return redirect(url_for('get_story', id=new_story.id))

@app.route('/stories', methods=['GET'])
@login_required
def all_stories():
    stories = Story.query.all()  # Retrieve all stories from the database
    return render_template('all_stories.html', stories=stories)


@app.route('/stories/<int:id>', methods=['GET'])
@login_required
def get_story(id):
    story = Story.query.get_or_404(id)
    contributions = Contribution.query.filter_by(story_id=story.id).all()

    return render_template('story_detail.html', story=story, contributions=contributions)

@app.route('/stories/<int:id>/contribute', methods=['POST'])
@login_required
def contribute(id):
    content = request.form['content']
    story = Story.query.get_or_404(id)

    # Check if the story already has 4 contributions
    if len(story.contributions) >= 4:
        flash('This story has already been completed!', 'warning')
        return redirect(url_for('get_story', id=id))

    new_contribution = Contribution(content=content, user_id=current_user.id, story_id=story.id)

    db.session.add(new_contribution)
    db.session.commit()

    flash('Contribution added successfully', 'success')
    return redirect(url_for('get_story', id=id))

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))


# Initialize the database
if __name__ == '__main__':
    with app.app_context():
        db.create_all()

    app.run(debug=True)
