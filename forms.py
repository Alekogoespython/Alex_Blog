from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField
from wtforms.validators import DataRequired, URL, Length
from flask_ckeditor import CKEditorField

##WTForm
class CreatePostForm(FlaskForm):
    title = StringField("Blog Post Title", validators=[DataRequired()])
    subtitle = StringField("Subtitle", validators=[DataRequired()])
    img_url = StringField("Blog Image URL", validators=[DataRequired(), URL()])
    body = CKEditorField("Blog Content", validators=[DataRequired()])
    submit = SubmitField("Submit Post")


# declarate Form Classes
class LoginForm(FlaskForm):
    email = StringField('Email', [DataRequired(), Length(max=100)])
    password = PasswordField('Password', [DataRequired(), Length(min=5, max=25)])

    submit = SubmitField('submit')


class RegisterForm(FlaskForm):
    name = StringField('Name', [DataRequired(), Length(max=50)])
    email = StringField('Email', [DataRequired(), Length(max=100)])
    password = PasswordField('Password', [DataRequired(), Length(min=5, max=25)])

    submit = SubmitField('submit')


class CommentForm(FlaskForm):
    comment = CKEditorField('Blog Content', validators=[DataRequired()])

    submit = SubmitField('submit')
