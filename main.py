# author Alexander Kortenbreer (starting code from Angela Yu)
# created 08/08/2022

from functools import wraps
from flask import Flask, render_template, redirect, url_for, flash, request, abort
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email, Length  # pip install email_validator
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import CreatePostForm
from sqlalchemy import Table, Column, Integer, ForeignKey
from sqlalchemy.orm import relationship
from sqlalchemy.ext.declarative import declarative_base
from flask_gravatar import Gravatar
from flask_ckeditor import CKEditor, CKEditorField

app = Flask(__name__)
app.config['SECRET_KEY'] = '8BYkEfBA6O6donzWlSihBXox7C0sKR6b'
ckeditor = CKEditor(app)
Bootstrap(app)

##CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# create Object login_manager to handle log in/out for the session
login_manager = LoginManager()
login_manager.init_app(app)
Base = declarative_base()

# get a User from the db by ID
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

##CONFIGURE TABLES
# bidirectional one to many databaseconnection


class User(UserMixin, db.Model):  # Parent of BlogPost and Comment
    __tablename__ = "Users"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(250), nullable=False)
    email = db.Column(db.String(250), nullable=False, unique=True)
    password = db.Column(db.String(250), nullable=False)
    posts = relationship("BlogPost", back_populates="author")  # Verbindung zu BlogPost()
    comments = relationship("Comment", back_populates="comment_author")  # Verbindung zu Comment()


class BlogPost(db.Model):  # Child of User/ Parent of Comment
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    author_id = db.Column(db.Integer, db.ForeignKey("Users.id"))  # author_id ist die User ID
    author = relationship("User", back_populates="posts")  # das ist jetzt eine Instanz von User()
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)
    comments = relationship("Comment", back_populates="parent_post")


class Comment(db.Model):  # Child of BlogPost and User
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.String(1000), nullable=False)

    author_id = db.Column(db.Integer, db.ForeignKey("Users.id"))
    comment_author = relationship("User", back_populates="comments")

    post_id = db.Column(db.Integer, db.ForeignKey("blog_posts.id"))
    parent_post = relationship("BlogPost", back_populates="comments")


# db.create_all()


# declarate Form Classes
class LoginForm(FlaskForm):
    email = StringField('Email', [DataRequired(), Email(), Length(max=100)])
    password = PasswordField('Password', [DataRequired(), Length(min=5, max=25)])

    submit = SubmitField('submit')


class RegisterForm(FlaskForm):
    name = StringField('Name', [DataRequired(), Length(max=50)])
    email = StringField('Email', [DataRequired(), Email(), Length(max=100)])
    password = PasswordField('Password', [DataRequired(), Length(min=5, max=25)])

    submit = SubmitField('submit')


class CommentForm(FlaskForm):
    comment = CKEditorField('Blog Content', validators=[DataRequired()])

    submit = SubmitField('submit')


# decorator to check, if admin is logged in
def admin_login_required(func):
    @wraps(func)
    def decorated_function(*args, **kwargs):
        if current_user.get_id() is None:
            return redirect(url_for('login', next=request.url))
        elif current_user.get_id() != "1":
            return abort(403)
        return func(*args, **kwargs)
    return decorated_function


# home route, get all posts
@app.route('/')
def get_all_posts():
    posts = BlogPost.query.all()
    print(posts)
    return render_template("index.html", all_posts=posts)


@app.route('/register', methods=["GET", "POST"])
def register():
    form_r = RegisterForm()
    if form_r.validate_on_submit():
        password_hashed = generate_password_hash(password=form_r.password.data, method='pbkdf2:sha256', salt_length=8)
        new_user = User(name=form_r.name.data,
                        email=form_r.email.data,
                        password=password_hashed)

        user = User.query.filter_by(email=new_user.email).first()
        # print(user)
        if user:
            flash('Email address already exists')
            return render_template("register.html", form=form_r)

        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for("get_all_posts"))

    return render_template("register.html", form=form_r)


@app.route('/login', methods=["GET", "POST"])
def login():
    form_l = LoginForm()
    # if submit-button was pushed
    if form_l.validate_on_submit():

        # get the data
        email = form_l.email.data
        pw_plain = form_l.password.data
        user = User.query.filter_by(email=email).first()

        # if user does not exist, flash message and reload login page
        if not user:
            flash('Email does not exist or wrong password')
            return render_template("login.html", form=form_l)

        # if user exists, hash password
        pw_hashed = user.password

        # check for correct hashed password, if correct -> login user and render secrets.html
        if check_password_hash(pwhash=pw_hashed, password=pw_plain):
            login_user(user)
            # print(current_user.get_id())
            # print(type(current_user.get_id()))
            return redirect(url_for('get_all_posts'))

        # if wrong password, flash message
        else:
            flash('Wrong password')
            return render_template("login.html", form=form_l)

    # if login was loaded without submit-button pushed -> just render login.html
    else:
        return render_template("login.html", form=form_l)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


# show post by id/ add comment, if logged in (see in post.html)
@app.route("/post/<int:post_id>", methods=["GET", "POST"])
def show_post(post_id):
    form = CommentForm()
    requested_post = BlogPost.query.get(post_id)
    if form.validate_on_submit():
        text = form.comment.data
        user_id = current_user.get_id()
        new_comment = Comment(text=text, author_id=user_id, post_id=post_id)
        db.session.add(new_comment)
        db.session.commit()
        form.comment.data = ""
        comments = Comment.query.all()
        print(comments)
        return render_template("post.html", post=requested_post, form=form, comments=comments)
    comments = Comment.query.all()
    # print(comments)
    return render_template("post.html", post=requested_post, form=form, comments=comments)


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact")
def contact():
    return render_template("contact.html")


@app.route("/new-post", methods=["GET", "POST"])
@admin_login_required
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author=current_user,
            date=date.today().strftime("%B %d, %Y")
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form)


@app.route("/edit-post/<int:post_id>")
@admin_login_required
def edit_post(post_id):
    post = BlogPost.query.get(post_id)

    # preset data of Form
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        author=post.author,
        body=post.body
    )
    #if submit button is pushed
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.author = edit_form.author.data
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))

    return render_template("make-post.html", form=edit_form)


# delete route
@app.route("/delete/<int:post_id>")
@admin_login_required
def delete_post(post_id):

    # first delete comments
    comments = Comment.query.all()
    for comment in comments:
        if comment.post_id == post_id:
            db.session.delete(comment)
            db.session.commit()

    # then delete Post (in the other way around, post_id of comment instance gets lost)
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()

    return redirect(url_for('get_all_posts'))


if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000, debug=True)
