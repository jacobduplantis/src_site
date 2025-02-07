from flask import Flask, render_template, redirect, url_for, flash, request
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager, login_user, login_required, logout_user,
    current_user, UserMixin
)
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField, TextAreaField, SelectField
from wtforms.validators import DataRequired, Length, Email, EqualTo
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key'  # Replace with a secure key
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///community_resources.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Make Python's getattr available in Jinja templates (used in print view)
app.jinja_env.globals['getattr'] = getattr

# ---------------------------
# New Join Table for Shared Lists
# ---------------------------
shared_lists = db.Table('shared_lists',
    db.Column('list_id', db.Integer, db.ForeignKey('resource_list.id'), primary_key=True),
    db.Column('user_id', db.Integer, db.ForeignKey('user.id'), primary_key=True)
)

# ---------------------------
# Models
# ---------------------------
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    lists = db.relationship('ResourceList', backref='owner', lazy=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
        
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

# Association table between ResourceList and Resource
list_resources = db.Table('list_resources',
    db.Column('list_id', db.Integer, db.ForeignKey('resource_list.id'), primary_key=True),
    db.Column('resource_id', db.Integer, db.ForeignKey('resource.id'), primary_key=True)
)

class ResourceList(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    is_favorite = db.Column(db.Boolean, default=False)
    # Relationship for sharing a list with specific users
    shared_with = db.relationship('User', secondary=shared_lists, backref=db.backref('shared_lists', lazy='dynamic'))
    resources = db.relationship('Resource', secondary=list_resources, lazy='subquery',
                                backref=db.backref('lists', lazy=True))

class Resource(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), nullable=False)
    category = db.Column(db.String(150))
    population_served = db.Column(db.String(150))
    location = db.Column(db.Text)
    hours = db.Column(db.Text)
    contact_information = db.Column(db.Text)
    eligibility = db.Column(db.Text)
    details = db.Column(db.Text)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# ---------------------------
# Forms
# ---------------------------
class SignupForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(1,64)])
    email = StringField('Email', validators=[DataRequired(), Email(), Length(1,120)])
    password = PasswordField('Password', validators=[DataRequired(), Length(6,128)])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Sign Up')

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(1,64)])
    password = PasswordField('Password', validators=[DataRequired(), Length(6,128)])
    remember = BooleanField('Remember Me')
    submit = SubmitField('Log In')

class CreateListForm(FlaskForm):
    name = StringField('List Name', validators=[DataRequired(), Length(1,100)])
    submit = SubmitField('Create List')

class AddResourceToListForm(FlaskForm):
    resource_id = SelectField('Select Resource', coerce=int, validators=[DataRequired()])
    submit = SubmitField('Add Resource')

class AddMasterResourceForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired(), Length(1,150)])
    category = StringField('Category', validators=[DataRequired(), Length(1,150)])
    population_served = StringField('Population Served', validators=[DataRequired(), Length(1,150)])
    location = TextAreaField('Location', validators=[DataRequired()])
    hours = TextAreaField('Hours')
    contact_information = TextAreaField('Contact Information')
    eligibility = TextAreaField('Eligibility')
    details = TextAreaField('Details')
    submit = SubmitField('Add Resource')

class ResourceFilterForm(FlaskForm):
    name = StringField('Name')
    category = StringField('Category')
    population_served = StringField('Population Served')
    location = StringField('Location')
    submit = SubmitField('Filter')

# ---------------------------
# Routes and Views
# ---------------------------
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    form = SignupForm()
    if form.validate_on_submit():
        if User.query.filter((User.username == form.username.data) | (User.email == form.email.data)).first():
            flash('Username or email already exists.')
            return redirect(url_for('signup'))
        user = User(username=form.username.data, email=form.email.data)
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        flash('Account created successfully. Please log in.')
        return redirect(url_for('login'))
    return render_template('signup.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and user.check_password(form.password.data):
            login_user(user, remember=form.remember.data)
            flash('Logged in successfully.')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password.')
    return render_template('login.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out successfully.')
    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def dashboard():
    # Sort lists so that favorites appear first
    lists = sorted(current_user.lists, key=lambda l: not l.is_favorite)
    return render_template('dashboard.html', lists=lists)

@app.route('/create_list', methods=['GET', 'POST'])
@login_required
def create_list():
    form = CreateListForm()
    if form.validate_on_submit():
        new_list = ResourceList(name=form.name.data, owner=current_user)
        db.session.add(new_list)
        db.session.commit()
        flash('New list created successfully.')
        return redirect(url_for('dashboard'))
    return render_template('create_list.html', form=form)

@app.route('/list/<int:list_id>')
@login_required
def view_list(list_id):
    resource_list = ResourceList.query.get_or_404(list_id)
    if resource_list.owner != current_user:
        flash('You do not have permission to view this list.')
        return redirect(url_for('dashboard'))
    return render_template('view_list.html', resource_list=resource_list)

@app.route('/list/<int:list_id>/add_resource', methods=['GET', 'POST'])
@login_required
def add_resource_to_list(list_id):
    resource_list = ResourceList.query.get_or_404(list_id)
    if resource_list.owner != current_user:
        flash('You do not have permission to modify this list.')
        return redirect(url_for('dashboard'))
    
    filter_form = ResourceFilterForm(request.args)
    query = Resource.query
    if filter_form.name.data:
        query = query.filter(Resource.name.ilike(f"%{filter_form.name.data}%"))
    if filter_form.category.data:
        query = query.filter(Resource.category.ilike(f"%{filter_form.category.data}%"))
    if filter_form.population_served.data:
        query = query.filter(Resource.population_served.ilike(f"%{filter_form.population_served.data}%"))
    if filter_form.location.data:
        query = query.filter(Resource.location.ilike(f"%{filter_form.location.data}%"))
    master_resources = query.all()
    
    add_form = AddResourceToListForm()
    add_form.resource_id.choices = [(r.id, r.name) for r in master_resources]
    
    if add_form.validate_on_submit():
        resource = Resource.query.get(add_form.resource_id.data)
        if resource:
            if resource not in resource_list.resources:
                resource_list.resources.append(resource)
                db.session.commit()
                flash('Resource added to your list.')
            else:
                flash('Resource is already in your list.')
        else:
            flash('Resource not found.')
        return redirect(url_for('view_list', list_id=list_id))
    
    return render_template('add_resource_to_list.html', filter_form=filter_form, add_form=add_form, resource_list=resource_list)

@app.route('/resource/<int:resource_id>')
def resource_detail(resource_id):
    resource = Resource.query.get_or_404(resource_id)
    return render_template('resource_detail.html', resource=resource)

@app.route('/admin/add_resource', methods=['GET', 'POST'])
@login_required
def admin_add_resource():
    if not current_user.is_admin:
        flash('Access denied.')
        return redirect(url_for('dashboard'))
    form = AddMasterResourceForm()
    if form.validate_on_submit():
        new_resource = Resource(
            name=form.name.data,
            category=form.category.data,
            population_served=form.population_served.data,
            location=form.location.data,
            hours=form.hours.data,
            contact_information=form.contact_information.data,
            eligibility=form.eligibility.data,
            details=form.details.data
        )
        db.session.add(new_resource)
        db.session.commit()
        flash('Resource added to the master list.')
        return redirect(url_for('admin_add_resource'))
    return render_template('admin_add_resource.html', form=form)

@app.route('/resources')
def master_resources():
    resources = Resource.query.all()
    return render_template('resources.html', resources=resources)

# ---------------------------
# Admin Routes for Account Management
# ---------------------------
@app.route('/admin/accounts')
@login_required
def admin_accounts():
    if not current_user.is_admin:
        flash('Access denied.')
        return redirect(url_for('dashboard'))
    users = User.query.all()
    return render_template('admin_accounts.html', users=users)

@app.route('/admin/make_admin/<int:user_id>', methods=['POST'])
@login_required
def admin_make_admin(user_id):
    if not current_user.is_admin:
        flash('Access denied.')
        return redirect(url_for('dashboard'))
    user = User.query.get_or_404(user_id)
    user.is_admin = True
    db.session.commit()
    flash(f"User {user.username} is now an admin.")
    return redirect(url_for("admin_accounts"))

@app.route('/admin/delete_user/<int:user_id>', methods=['POST'])
@login_required
def admin_delete_user(user_id):
    if not current_user.is_admin:
        flash('Access denied.')
        return redirect(url_for('dashboard'))
    user = User.query.get_or_404(user_id)
    if user.id == current_user.id:
        flash("You cannot delete yourself.")
        return redirect(url_for("admin_accounts"))
    db.session.delete(user)
    db.session.commit()
    flash("User deleted.")
    return redirect(url_for("admin_accounts"))

# ---------------------------
# Admin Route for Deleting a Resource from the Master List
# ---------------------------
@app.route('/admin/delete_resource/<int:resource_id>', methods=['POST'])
@login_required
def admin_delete_resource(resource_id):
    if not current_user.is_admin:
        flash('Access denied.')
        return redirect(url_for('dashboard'))
    resource = Resource.query.get_or_404(resource_id)
    db.session.delete(resource)
    db.session.commit()
    flash("Resource deleted from master list.")
    return redirect(url_for("master_resources"))

# ---------------------------
# New Feature: Toggle Favorite for a List
# ---------------------------
@app.route('/list/<int:list_id>/favorite', methods=['POST'])
@login_required
def toggle_favorite(list_id):
    resource_list = ResourceList.query.get_or_404(list_id)
    if resource_list.owner != current_user:
        flash("Permission denied.")
        return redirect(url_for('dashboard'))
    resource_list.is_favorite = not resource_list.is_favorite
    db.session.commit()
    flash("List favorite status updated.")
    return redirect(url_for('dashboard'))

# ---------------------------
# New Feature: Share a List with a Specific User
# ---------------------------
@app.route('/list/<int:list_id>/share', methods=['GET', 'POST'])
@login_required
def share_list(list_id):
    resource_list = ResourceList.query.get_or_404(list_id)
    if resource_list.owner != current_user:
        flash("Permission denied.")
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        username = request.form.get('username')
        if username:
            user = User.query.filter_by(username=username).first()
            if user:
                if user not in resource_list.shared_with:
                    resource_list.shared_with.append(user)
                    db.session.commit()
                    flash(f"List shared with {username}.")
                else:
                    flash("List is already shared with that user.")
            else:
                flash("User not found.")
        return redirect(url_for('manage_lists'))
    return render_template('share_list.html', resource_list=resource_list)

# ---------------------------
# New Feature: Admin Share a List with All Users
# ---------------------------
@app.route('/admin/share_list_all/<int:list_id>', methods=['POST'])
@login_required
def admin_share_list_all(list_id):
    if not current_user.is_admin:
        flash("Permission denied.")
        return redirect(url_for('dashboard'))
    resource_list = ResourceList.query.get_or_404(list_id)
    users = User.query.all()
    for user in users:
        if user != resource_list.owner and user not in resource_list.shared_with:
            resource_list.shared_with.append(user)
    db.session.commit()
    flash("List shared with all users.")
    return redirect(url_for('admin_accounts'))

# ---------------------------
# New Feature: Manage Lists (Favorite, Share, Delete)
# ---------------------------
@app.route('/manage_lists', methods=['GET', 'POST'])
@login_required
def manage_lists():
    # Sort user's lists with favorites at the top
    lists = sorted(current_user.lists, key=lambda l: not l.is_favorite)
    if request.method == 'POST':
        selected_ids = request.form.getlist('list_ids')
        for list_id in selected_ids:
            resource_list = ResourceList.query.get(int(list_id))
            if resource_list and resource_list.owner == current_user:
                db.session.delete(resource_list)
        db.session.commit()
        flash("Selected lists deleted.")
        return redirect(url_for('manage_lists'))
    return render_template('manage_lists.html', lists=lists)

# ---------------------------
# New Feature: Print List Route (with Column Selection)
# ---------------------------
@app.route('/list/<int:list_id>/print', methods=['GET', 'POST'])
@login_required
def print_list(list_id):
    resource_list = ResourceList.query.get_or_404(list_id)
    if resource_list.owner != current_user:
        flash('You do not have permission to print this list.')
        return redirect(url_for('dashboard'))
    
    columns = [
        ('name', 'Name'),
        ('category', 'Category'),
        ('population_served', 'Population Served'),
        ('location', 'Location'),
        ('hours', 'Hours'),
        ('contact_information', 'Contact Information'),
        ('eligibility', 'Eligibility'),
        ('details', 'Details')
    ]
    
    if request.method == 'POST':
        selected_columns = request.form.getlist('columns')
        return render_template('print_list.html', resource_list=resource_list, selected_columns=selected_columns)
    
    return render_template('print_list_select.html', resource_list=resource_list, columns=columns)

# ---------------------------
# Main Block: Create DB, Default Admin, and Run App
# ---------------------------
if __name__ == '__main__':
    with app.app_context():
        if not os.path.exists('community_resources.db'):
            db.create_all()
        # Create default admin account if it doesn't exist
        if not User.query.filter_by(username="techadmin").first():
            admin = User(username="techadmin", email="techadmin@example.com")
            admin.set_password("SRCCtechadmin2025")
            admin.is_admin = True
            db.session.add(admin)
            db.session.commit()
    app.run(debug=True)
