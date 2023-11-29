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
from plotly.subplots import make_subplots
import plotly.graph_objects as go
import numpy as np
import plotly.io as pio
import nltk
from nltk.tokenize import word_tokenize

nltk.download('punkt')
filler_words = {'a', 'an', 'the', 'and', 'but', 'or', 'so', 'uh', 'um', 'like', 'just', 'really', 'very', 'so',
                'actually', 'basically', 'seriously', 'literally', 'good', 'game', 'play', 'playing', '10', 'best',
                'played', 'nice', 'got', 've'}

# THE REQUIRED IMPORTS TO ENABLE THE DATA SCIENCE DONE TO THE TEXT
from sklearn.decomposition import NMF
from sklearn.feature_extraction.text import TfidfVectorizer

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
    topic_analysis = None
    game_name = "None"
    # try:
    if request.method == 'POST':
        game_name = search_form.game.data
        num_reviews = 300
        # GET THE APP ID FROM THE INPUT GAME NAME :
        game_name_search = requests.get(f"https://whatdotheythink.online/services/getIDs?gameName={game_name}")
        app_id_zipped = json.loads(game_name_search.content)
        app_id = app_id_zipped["steamID"]

        response = requests.get(
            f"https://whatdotheythink.online/services/SteamReviews?appid={app_id}&reviewType=all&reviewNum={num_reviews}")
        content = json.loads(response.content)

        # THIS GETS THE REVIEWS AND THEIR TEXT
        review_text = []
        review_over_year = dict()

        # NUMBER OF POSITIVE REVIEW IN THE FORMAT YEAR: NUM POSITIVE
        positive_time_played = []
        # NUMBER OF NEGATIVE REVIEWS IN THE FORMAT YEAR: NUM NEGATIVE
        negative_time_played = []

        # # DEBUGGING
        # app.logger.error(content[1])

        game_info = dict()
        for review in content:
            # FILTER OUT THE FIRST ENTRY WHICH IS GAME INFO
            if "totalReviews" in review:
                game_info = review
            else:
                dirty_review_text = review["reviewText"]
                words = word_tokenize(dirty_review_text)
                filtered_words = [word for word in words if word.lower() not in filler_words]
                review_text.append(' '.join(filtered_words))

                # APPEND IF THE REVIEWS ARE POSITIVE OR NEGATIVE
                # THIS IS USED TO SEE IF THE MORE TIME PEOPLE SPEND ON THE GAME, THE MORE THEY ENJOY IT
                if review["reviewPositive"]:
                    time_in_game = review["reviewPlaytimeForever"] / 360
                    positive_time_played.append(time_in_game)
                else:
                    time_in_game = review["reviewPlaytimeForever"] / 360
                    negative_time_played.append(time_in_game)

        # NORMALIZE BOTH THE NEGATIVE REVIEWS AND THE POSITIVE ONES TO REDUCE OUTLIERS
        # CONVERT THE LISTS TO NP ARRAYS
        post_processing_positive_reviews = np.array(positive_time_played)
        post_processing_negative_reviews = np.array(negative_time_played)

        positive_reviews_time_played = post_processing_positive_reviews[
            abs(post_processing_positive_reviews - np.mean(post_processing_positive_reviews)) < 2 * np.std(
                post_processing_positive_reviews)]
        negative_reviews_time_played = post_processing_negative_reviews[
            abs(post_processing_negative_reviews - np.mean(post_processing_negative_reviews)) < 2 * np.std(
                post_processing_negative_reviews)]

        # SEPARATE CODE FOR THE NON-NEGATIVE MATRIX FACTORIZATION
        vectorizer = TfidfVectorizer(stop_words='english', max_df=.97, min_df=.025)
        X = vectorizer.fit_transform(review_text)
        nmf = NMF(n_components=10, init='random').fit(X)
        feature_names = vectorizer.get_feature_names_out()

        # FIND THE FIVE MOST IMPORTANT WORDS
        num_words_to_use = 5
        top_words = {}
        for topicID, filter in enumerate(nmf.components_):
            top_features_index = filter.argsort()[: -num_words_to_use - 1: -1]
            top_filter_words = [feature_names[i] for i in top_features_index]
            weights = filter[top_features_index]
            top_words[f"Topic {topicID}"] = [top_filter_words, weights]

        subplot_titles = ["Positive/Negative<br>Review Ratio",
                          "Average Time Played for<br>Positive/Negative Reviews"]
        subplot_titles.extend([k[0][0] for k in top_words.values()])

        # MAKE THE GRID PATTER FOR THE SUBPLOTS
        specs = [
            [{"type": "domain", "rowspan": 2, "colspan": 2}, None, {"type": "xy", "colspan": 3, "rowspan": 2}, None,
             None],  # Row 1
            [None, None, None, None, None],
            [{"type": "xy"}, {"type": "xy"}, {"type": "xy"}, {"type": "xy"}, {"type": "xy"}],  # Row 3
            [{"type": "xy"}, {"type": "xy"}, {"type": "xy"}, {"type": "xy"}, {"type": "xy"}],  # Row 4
        ]

        # MAKE THE BROADER SUBPLOT
        topic_analysis = make_subplots(rows=4, cols=5, subplot_titles=subplot_titles,
                                       shared_yaxes="rows", specs=specs, vertical_spacing=0.1)

        # AVERAGE TIME SPENT IN GAME BY POSITIVE REVIEWS
        positive_review_box_plot = go.Box(x=positive_reviews_time_played, name="Positive", hoverinfo='x')
        topic_analysis.add_trace(positive_review_box_plot, row=1, col=3)

        # AVERAGE TIME SPENT IN GAME BY NEGATIVE REVIEWS
        negative_review_box_plot = go.Box(x=negative_reviews_time_played, name="Negative", hoverinfo='x')
        topic_analysis.add_trace(negative_review_box_plot, row=1, col=3)

        # SHARED ATTRIBUTES
        topic_analysis.update_xaxes(title_text="Time (hours)", row=1, col=3)
        topic_analysis.update_yaxes(dict(tickangle=-90), row=1, col=3)

        # ADD THE PLOT THAT CONTAINS THE PIE CHART
        ratio_pie_chart = go.Pie(values=[len(positive_reviews_time_played), len(negative_reviews_time_played)],
                                 labels=["Positive", "Negative"],
                                 hoverinfo='label+percent',
                                 text=["Positive", "Negative"])  # , textinfo='none'
        topic_analysis.add_trace(ratio_pie_chart, row=1, col=1)

        row = 3
        col = 1
        for key in top_words.keys():
            if col == 6:
                col = 1
                row += 1
            if (5 * (row - 1) + col) > 20:
                topic_analysis.add_trace(go.Bar(name=""), row, col)
            else:
                topic_analysis.add_trace(go.Bar(name=key, x=top_words[key][0], y=top_words[key][1]), row, col)
            col += 1

        topic_analysis.update_layout(showlegend=False)
        topic_analysis.update_traces(dict(marker_coloraxis=None), row=row, col=1)
        topic_analysis.update_layout(height=1500, width=1000)
        topic_analysis.update_layout(template='plotly_dark')

        if current_user.is_authenticated:
            current_datetime = datetime.now()
            readable_datetime = current_datetime.strftime("%I:%M%p, %B %d, %Y")
            new_query = Query(user_id=current_user.id, date=readable_datetime, game=game_name, app_id=app_id,
                              results=pio.to_json(topic_analysis))
            db.session.add(new_query)
            db.session.commit()
            flash(f'Added search to history', category='success')
        else:
            flash(f'Sign in to save your searches', category='danger')

        return render_template("index.html", form=search_form, results=pio.to_json(topic_analysis), game_name=game_name)

    # except:
    #     flash(f"There was an error with retrieving given game data, please try again", category='danger')

    if search_form.errors != {}:  # if there are no errors from the validation
        for err_msg in search_form.errors.values():
            flash(f"There was an error with your search: {err_msg}", category='danger')

    results = None
    if topic_analysis:
        results = pio.to_json(topic_analysis)

    return render_template("index.html", form=search_form, results=results, game_name=game_name)


@app.route('/history', methods=['GET', 'POST'])
@login_required
def previous_searches():
    if request.method == 'GET':

        # CHECK IF ADMIN:
        if current_user.username == "TA":
            flash(f"Logged in as Administrator", category='success')
            # ordered_queries = Query.query.order_by(Query.query_id.desc())
            ordered_queries = Query.query.order_by(Query.query_id.desc()).all()
            app.logger.error(ordered_queries)
            return render_template("previousSearchesAdmin.html", queries=ordered_queries)
        else:
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
    import os

    port = int(os.getenv('PORT'))
    app.run() # debug=True

# BASIC USER AND PASSWORD
# USERNAME: TA
# PASSWORD: Cse44598!
