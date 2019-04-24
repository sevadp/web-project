import os
import hashlib
from datetime import datetime
from flask import Flask, render_template, redirect, url_for, flash, abort
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, LoginManager, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from wtforms import StringField, SubmitField, PasswordField, TextAreaField, ValidationError
from wtforms.validators import DataRequired, EqualTo
from flask_ckeditor import CKEditor, CKEditorField


basedir = os.path.abspath(os.path.dirname(__file__))

app = Flask(__name__)
# Настройка приложения и подключение бд от фласка sqlite
app.config['SECRET_KEY'] = 'moy-MEGA-klyu4'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'data.sqlite')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Бут страп тоже от фласка. + обозначение регистрация объектов по классам ниже
bootstrap = Bootstrap(app)
db = SQLAlchemy(app)
login_manager = LoginManager(app)
ckeditor = CKEditor(app)


class LoginForm(FlaskForm):
    # Форма ввода. Лог + пароль. Проверка на правильность лог пароля от приложений фласка))))
    login = StringField('Логин', validators=[DataRequired()])
    password = PasswordField('Пароль', validators=[DataRequired()])
    submit = SubmitField('Войти')


class RegistrationForm(FlaskForm):
    # Регистрация + валид от фласка. И подтверждение пароля.
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

    # Проверка валидности логика. валид = правильност
    def validate_login(self, field):
        if User.query.filter_by(username=field.data).first():
            raise ValidationError('Такой пользователь уже существует.')


class PostForm(FlaskForm):
    # Посты + валидность от фласка.
    body = TextAreaField("Есть новая заметка?", validators=[DataRequired()])
    submit = SubmitField('Запостить')


class User(UserMixin, db.Model):
    # Подключение бд. типы данных для них и колонка users для всех юзеров.
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, index=True)
    password_hash = db.Column(db.String(128))
    posts = db.relationship('Post', backref='author', lazy='dynamic')

    def __repr__(self):
        return '<User {}>'.format(self.username)

    # тест от ошибок, чтобы не крашило серв.
    @property
    def password(self):
        raise AttributeError('пароль прочесть нельзя.')
    
    @password.setter
    def password(self, password):
        # Собственно установка пароля.  При регистрации
        # Фласковый генератор хеша для пароля.
        self.password_hash = generate_password_hash(password)
    
    def verify_password(self, password):
        # Подтверждение проверки тот ли пароль когда авторизуешься
        return check_password_hash(self.password_hash, password)
    
    def gravatar(self, size=100, default='identicon', rating='g'):
        url = 'https://secure.gravatar.com/avatar'
        email = '{}@bookmarks.ru'.format(self.username.lower()).encode('utf-8')
        email_hash = hashlib.md5(email).hexdigest()
        return '{url}/{hash}?s={size}&d={default}&r={rating}'.format(
            url=url, hash=email_hash, size=size, default=default, rating=rating)
    
    def robohash(self, size=200):
        # нужны картинки( робохеш крч ты каждому юзеру свою рандомную аву генеришь, у него там свои
        # методы. но она сохраняется навсегда тк есть индификатор постоянный для юзеров
        # . главное чтобы инет был - а то все падет!
        url = 'https://robohash.org/'
        return url + self.username + '?size={}x{}'.format(size, size)


class Post(db.Model):
    __tablename__ = 'posts'
    id = db.Column(db.Integer, primary_key=True)
    body = db.Column(db.Text)
    # время UTC ну лондонское
    timestamp = db.Column(db.DateTime, index=True, default=datetime.utcnow)
    author_id = db.Column(db.Integer, db.ForeignKey('users.id'))


@app.context_processor
def inject_app_name():
    return dict(app_name="Заметки")


@app.route('/', methods=['GET', 'POST'])
def index():
    # Тема такая. У каждого обычного есть свои посты и главная. А у админа только свои посты
    # Он публикует и их все видят на главной. Первый человек сайта становится админом.
    admin_posts = Post.query.filter_by(author_id=1).order_by(Post.timestamp.desc()).all()
    return render_template('index.html', posts=admin_posts)


@app.route('/posts', methods=['GET', 'POST'])
@login_required
def posts():
    # Сразу проверка на авторизацию. Если авторизован - то показывает.
    # У каждого свой личный кабинет. Только он видит свою инфу.
    form = PostForm()
    
    if form.validate_on_submit():
        post = Post(body=form.body.data, author_id=current_user.get_id())
        db.session.add(post)
        db.session.commit()
        return redirect(url_for('posts'))

    user_posts = Post.query.filter_by(author_id=current_user.get_id()).order_by(Post.timestamp.desc()).all()
    return render_template('posts.html', form=form, posts=user_posts)


@app.errorhandler(404)
def page_not_found(e):
    # Если нет страницы, дропает 404 ошибку.
    # Нужен аргумент, но я его не юзаю. А без него краши
    return render_template('404.html'), 404


@app.errorhandler(403)
def forbidden(e):
    return render_template('403.html'), 403


@app.errorhandler(500)
def internal_server_error(e):
    # Ошибка сервера - 500 ошибка.
    # Нужен аргумент, но я его не юзаю. А без него краши
    return render_template('500.html'), 500


@app.route('/login', methods=['GET', 'POST'])
def login():
    # Авторизация. Форма - класс, который выше.
    form = LoginForm()
    # Проверка на правильность ввода форм. тож халявная функция
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.login.data).first()
        # если юзер реален ну не пуст и верификация пароля пройдена( хеш от этого пароля совпадает с
        # хешом в бд, который фласк генерит. То авторизируем
        if user is not None and user.verify_password(form.password.data):
            login_user(user, False)
            return redirect(url_for('index'))
        # ну если сюда доходит то ошибка
        flash('Неправильный логин или пароль.')
    # функция есть загенерили страницу и работает
    return render_template('login.html', form=form)


@app.route('/logout')
@login_required
def logout():
    # чтобы выйти нужна авторизация. фласк тупа все дает это на изи сделать. Выходим и все.
    logout_user()
    flash('Вы вышли.')
    return redirect(url_for('index'))


@app.route('/register', methods=['GET', 'POST'])
def register():
    # Форма регистрации - класс, который выше
    form = RegistrationForm()
    if form.validate_on_submit():
        # проверка фласком на правильность полей и указание если все ок то пароль логин создаем юзера
        user = User(username=form.login.data, password=form.password.data)
        # добавляем бд и коммитим, ну запоминаем типо сохранение.
        db.session.add(user)
        db.session.commit()
        flash('Теперь вы можете войти.')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)


@app.route('/delete_post/<int:post_id>')
@login_required
def delete_post(post_id):
    # авторизация нужна. Человек видит только свои посты, поэтому удалить по ид может свои.
    # удаление ну  и бд сохранение
    post = Post.query.get(post_id)
    db.session.delete(post)
    db.session.commit()
    return redirect(url_for('posts'))


@app.route('/edit_post/<int:post_id>', methods=['GET', 'POST'])
@login_required
def edit_post(post_id):
    post = Post.query.get_or_404(post_id)

    if int(current_user.get_id()) != int(post.author_id):
        abort(403)
        
    form = PostForm()
    
    if form.validate_on_submit():
        post.body = form.body.data
        db.session.add(post)
        db.session.commit()
        flash('Запись успешно изменена.')
        return redirect(url_for('edit_post', post_id=post.id))
    
    form.body.data = post.body
    return render_template('edit_post.html', form=form)


@login_manager.user_loader
def load_user(user_id):
    # подгрузка юзера
    return User.query.get(int(user_id))


@login_manager.unauthorized_handler
def unauthorized():
    # запрос не был применен так как ему не хватает данных для действия лишнего. щас ок с этим. только
    # если самому не пробовать
    return render_template('401.html'), 401


if __name__ == "__main__":
    app.run()
