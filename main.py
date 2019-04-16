from flask import Flask, render_template, redirect, url_for, flash
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField, TextAreaField
from wtforms.validators import DataRequired, EqualTo
import os
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin, LoginManager, login_user, logout_user, login_required, current_user
import hashlib
from datetime import datetime


basedir = os.path.abspath(os.path.dirname(__file__))

app = Flask(__name__)
app.config['SECRET_KEY'] = 'moy-MEGA-klyu4'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'data.sqlite')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

bootstrap = Bootstrap(app)
db = SQLAlchemy(app)
login_manager = LoginManager(app)


class LoginForm(FlaskForm):
    login = StringField('Логин', validators=[DataRequired()])
    password = PasswordField('Пароль', validators=[DataRequired()])
    submit = SubmitField('Войти')


class RegistrationForm(FlaskForm):
    login = StringField('Логин', validators=[DataRequired()])
    password = PasswordField(
        'Пароль', 
        validators=[
            DataRequired(), 
            EqualTo('password2', message='Пароли не совпадают.')
        ]
    )
    password2 = PasswordField('Подтвердите пароль ещё раз', validators=[DataRequired()])
    submit = SubmitField('Зарегистрироваться')

    # @staticmethod
    # def validate_login(self, field):
    #     if User.query.filter_by(username=field.data).first():
    #         raise ValidationError('Такой пользователь уже существует.')


class PostForm(FlaskForm):
    body = TextAreaField("Есть новая заметка?", validators=[DataRequired()])
    submit = SubmitField('Запостить')


class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, index=True)
    password_hash = db.Column(db.String(128))
    posts = db.relationship('Post', backref='author', lazy='dynamic')

    def __repr__(self):
        return '<User {}>'.format(self.username)
        
    @property
    def password(self):
        raise AttributeError('пароль прочесть нельзя.')
    
    @password.setter
    def password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def verify_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    def gravatar(self, size=100, default='identicon', rating='g'):
        # COPY PAST MODULE
        url = 'https://secure.gravatar.com/avatar'
        email = '{}@bookmarks.ru'.format(self.username.lower()).encode('utf-8')
        hashs = hashlib.md5(email).hexdigest()
        return '{url}/{hash}?s={size}&d={default}&r={rating}'.format(
            url=url, hash=hashs, size=size, default=default, rating=rating)
    
    def robohash(self, size=200):
        url = 'https://robohash.org/'
        return url + self.username + '?size={}x{}'.format(size, size)


class Post(db.Model):
    __tablename__ = 'posts'
    id = db.Column(db.Integer, primary_key=True)
    body = db.Column(db.Text)
    timestamp = db.Column(db.DateTime, index=True, default=datetime.utcnow)
    author_id = db.Column(db.Integer, db.ForeignKey('users.id'))


@app.context_processor
def inject_app_name():
    return dict(app_name="Заметки")


@app.route('/', methods=['GET', 'POST'])
def index():
    postss = Post.query.filter_by(author_id=1).order_by(Post.timestamp.desc()).all()
    return render_template('index.html', posts=postss)


@app.route('/posts', methods=['GET', 'POST'])
@login_required
def posts():
    form = PostForm()
    
    if form.validate_on_submit():
        post = Post(body=form.body.data, author=current_user._get_current_object())
        db.session.add(post)
        db.session.commit()
        return redirect(url_for('posts'))

    posts = Post.query.filter_by(author_id=current_user.get_id()).order_by(Post.timestamp.desc()).all()
    return render_template('posts.html', form=form, posts=posts)


@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404


@app.errorhandler(500)
def internal_server_error(e):
    return render_template('500.html'), 500


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.login.data).first()
        if user is not None and user.verify_password(form.password.data):
            login_user(user, False)
            return redirect(url_for('index'))
        flash('Неправильный логин или пароль.')
    return render_template('login.html', form=form)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Вы вышли.')
    return redirect(url_for('index'))


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(username=form.login.data, password=form.password.data)
        db.session.add(user)
        db.session.commit()
        flash('Теперь вы можете войти.')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)


@app.route('/delete_post/<int:post_id>')
@login_required
def delete_post(post_id):
    post = Post.query.get(post_id)
    db.session.delete(post)
    db.session.commit()
    return redirect(url_for('posts'))


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@login_manager.unauthorized_handler
def unauthorized():
    return render_template('401.html'), 401


if __name__ == "__main__":
    app.run()
