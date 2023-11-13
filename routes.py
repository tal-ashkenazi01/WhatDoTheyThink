from flask import Flask
from flask_login import UserMixin
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager
from flask import render_template, redirect, url_for, flash, request
from flask_login import login_user, logout_user, login_required, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import Length, EqualTo, Email, DataRequired, ValidationError
import requests
import json
from datetime import datetime
import plotly.express as px
import plotly.io as pio

app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///user_database.db"
app.config["SECRET_KEY"] = "39919f90eac849c3374896ba"
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = "login_page"
login_manager.login_message_category = 'info'


@login_manager.user_loader
def load_user(user_id):
    return Users.query.get(int(user_id))


class Users(db.Model, UserMixin):
    id = db.Column(db.Integer(), primary_key=True)
    username = db.Column(db.String(length=20), nullable=False, unique=True)
    email = db.Column(db.String(length=40), nullable=False, unique=True)
    password_ = db.Column(db.String(length=60), nullable=False, unique=True)
    queries = db.relationship("Query", backref="user", lazy=True)  # establishes a relationship with another table

    @property
    def password(self):
        return self.password

    @password.setter
    def password(self, plain_text_password):
        self.password_ = bcrypt.generate_password_hash(plain_text_password).decode("utf-8")

    def check_password_correction(self, attempted_password):
        return bcrypt.check_password_hash(self.password_, attempted_password)

    def __repr__(self):
        return f"User: {self.username}"


class Query(db.Model):
    query_id = db.Column(db.Integer(), primary_key=True)
    user_id = db.Column(db.Integer(), db.ForeignKey("users.id"), nullable=False)
    date = db.Column(db.String(length=30), nullable=False, unique=False)
    game = db.Column(db.String(length=30), nullable=False, unique=False)
    app_id = db.Column(db.Integer(), nullable=False, unique=False)
    results = db.Column(db.String(length=1024), nullable=False, unique=False)

    def __repr__(self):
        return f"Query: {self.game}"

    def assign_ownership(self, user):
        self.user_id = user.id
        db.session.commit()


with app.app_context():
    db.create_all()

class RegisterForm(FlaskForm):
    def validate_username(self, username_to_check):  # this works automatically because flask searches for validation
        # functions and uses the function name itself to know what data to send through
        user = Users.query.filter_by(username=username_to_check.data).first()
        if user:
            raise ValidationError('Username taken. Please try a different username')

    def validate_email_address(self, email_to_check):
        email_address = Users.query.filter_by(email_address=email_to_check.data).first()
        if email_address:
            raise ValidationError('An account with this email already exists. Please try a different email')

    username = StringField(label="Username:", validators=[Length(min=2, max=20), DataRequired()])
    email = StringField(label="Email Address:", validators=[Email(), DataRequired()])
    password1 = PasswordField(label="Password:", validators=[Length(min=6), DataRequired()])
    password2 = PasswordField(label="Confirm Password:", validators=[EqualTo("password1"), DataRequired()])
    submit = SubmitField(label="Create Account")


class LoginForm(FlaskForm):
    username = StringField(label="Username:", validators=[DataRequired()])
    password = PasswordField(label="Password:", validators=[DataRequired()])
    submit = SubmitField(label="Sign in")

class SearchForm(FlaskForm):
    game = StringField(label="Game", validators=[DataRequired()])
    submit = SubmitField(label="Search")


@app.route('/', methods=['GET', 'POST'])
@app.route('/home', methods=['GET', 'POST'])
def home_page():
    search_form = SearchForm()
    if request.method == 'POST':
        game_name = search_form.game.data
        app_id = 1091500  # THIS IS WORKING OFF OF JUST THE CYBERPUNK 2077 ID WHICH IS A PROBLEM
        response = requests.get(
            f"https://whatdotheythink.online/services/SteamReviews?appid={app_id}&reviewType=all&reviewNum=5")
        content = json.loads(response.content)

        review_list = []
        game_info = dict()
        for review in content:
            if "totalReviews" in review:
                game_info = review
            else:
                review_list.append(review["reviewText"])

        # CREATE EXAMPLE GRAPH
        fig = px.scatter(x=[0, 1, 2, 3, 4], y=[0, 1, 4, 9, 16])

        if current_user.is_authenticated:
            current_datetime = datetime.now()
            readable_datetime = current_datetime.strftime("%I:%M%p, %B %d, %Y")
            new_query = Query(user_id=current_user.id, date=readable_datetime, game=game_name, app_id=app_id,
                              results=pio.to_json(fig))
            db.session.add(new_query)
            db.session.commit()
            flash(f'Added search to history', category='success')
        else:
            flash(f'Sign in to save your searches', category='danger')

    if search_form.errors != {}:  # if there are no errors from the validation
        for err_msg in search_form.errors.values():
            flash(f"There was an error with your search: {err_msg}", category='danger')

    return render_template("index.html", form=search_form)


@app.route('/history', methods=['GET', 'POST'])
@login_required
def previous_searches():
    if request.method == 'GET':
        ordered_queries = Query.query.filter_by(user_id=current_user.id).order_by(Query.query_id.desc())
        return render_template("previousSearches.html", queries=ordered_queries)


@app.route('/register', methods=['GET', 'POST'])
def register_page():
    form = RegisterForm()
    if form.validate_on_submit():
        user_to_create = Users(username=form.username.data, email=form.email.data, password=form.password1.data)
        db.session.add(user_to_create)
        db.session.commit()
        app.logger.error("committed the user")
        login_user(user_to_create)
        flash(f"Account Created Successfully! You are now logged in as {user_to_create.username}", category='success')
        return redirect(url_for('previous_searches'))
    if form.errors != {}:  # if there are no errors from the validation
        for err_msg in form.errors.values():
            flash(f"there was an error with creating a user: {err_msg}", category='danger')
    return render_template("register.html", form=form)


@app.route('/login', methods=['GET', 'POST'])
def login_page():
    form = LoginForm()
    if form.validate_on_submit():
        attempted_user = Users.query.filter_by(username=form.username.data).first()
        if attempted_user and attempted_user.check_password_correction(attempted_password=form.password.data):
            login_user(attempted_user)
            flash(f"Success! You are logged in as: {attempted_user.username}", category='success')
            return redirect(url_for('previous_searches'))
        else:
            flash("Username and password do not match. Please try again.", category='danger')
    return render_template("login.html", form=form)


@app.route('/logout')
def logout_page():
    logout_user()
    flash("You have been logged out", category='info')
    return redirect(url_for('home_page'))


if __name__ == "__main__":
    from os import environ
    app.run(debug=True, port=environ.get("PORT", 8080))

# BASIC USER AND PASSWORD
# USERNAME: TA
# PASSWORD: Cse44598!
