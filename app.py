from flask import Flask, render_template, request, redirect,url_for,current_app ,flash
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
import os
import secrets
from flask_login import LoginManager, login_user, login_required, current_user, logout_user, UserMixin
from flask_bcrypt import Bcrypt
import requests


app = Flask(__name__)
app.secret_key = b'_5#y2L"F4Q8z\n\xec]/'
bcrypt = Bcrypt(app)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog.db'


db = SQLAlchemy(app)
migrate = Migrate(app, db)

login_manager = LoginManager(app)
login_manager.login_view = "users.login"

login_manager.login_message_category = "info"

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


def save_img(photo):
    hash_photo = secrets.token_urlsafe(10)
    _,file_extension = os.path.splitext(photo.filename)
    photo_name = hash_photo + file_extension
    file_path = os.path.join(current_app.root_path,'static/images',photo_name)
    photo.save(file_path)
    return photo_name

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(20))
    password = db.Column(db.Text)


class Blogspot(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(50))
    subtitle = db.Column(db.String(50))
    content = db.Column(db.Text)
    imgs = db.Column(db.String(12))
def subscribe_user(email, user_group_email, api_key):
    resp = requests.post(f"https://api.mailgun.net/v3/lists/{user_group_email}/members",
                         auth = ("api", api_key),
                         data ={"subscribed": True,
                                "address": email}
                         )
    return resp
@app.route('/', methods=["GET", "POST"])
def index():
    posts = Blogspot.query.all()
    if request.method == "POST":
        email = request.form.get('email')
        subscribe_user(email=email,
                       user_group_email="newsletters@sandboxbf77a69e88d44d21bd111d5ca842653d.mailgun.org",
                       api_key="bad4342a6e862513d68011000b7511e8-7cd1ac2b-f81c5e19")
    return render_template('index.html', posts=posts )
r = requests.post(
    "https://api.mailgun.net/v3/sandboxbf77a69e88d44d21bd111d5ca842653d.mailgun.org/messages",

    auth = ("api", "bad4342a6e862513d68011000b7511e8-7cd1ac2b-f81c5e19"),

    data = { "from":"Robot <sandboxbf77a69e88d44d21bd111d5ca842653d.mailgun.org>",
             "to":"newsletters@sandboxbf77a69e88d44d21bd111d5ca842653d.mailgun.org",
             "subject":"Thanks for subscribe our website.",
             "text":"Subscription is successfully completed!"})
print(r.status_code)
@app.route('/post/<int:post_id>')
def post(post_id):
    post = Blogspot.query.filter_by(id=post_id).one()
    return render_template('post.html',post=post)

@app.route('/page')
def page():
    return render_template('page.html')

@app.route('/category')
def category():
    return render_template('category.html')

@app.route('/404')
def f404():
    return render_template('404.html')

@app.route('/default')
def default():
    return render_template('default.html')

@app.route('/search')
def search():
    return render_template('search.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    # Here we use a class of some kind to represent and validate our
    # client-side form data. For example, WTForms is a library that will
    # handle this for us, and we use a custom LoginForm to validate.

    if request.method=='POST':
        user = User.query.filter_by(name = request.form.get('username')).first()
        password = request.form.get('userpassword')
        password_db = user.password
        hashed = bcrypt.generate_password_hash(password)
        if user and bcrypt.check_password_hash(hashed, password_db):
            login_user(user)
            flash('Logged in successfully.','success')

            next =  request.args.get('next')
            return redirect(next or url_for('add'))
        flash("Wrong password try again later" ,'danger')
    return render_template('signin.html')



@app.route('/signup')
def signup():
    return render_template('signup.html')

@app.route('/add', methods =['POST','GET'])
def add():
    return render_template('add.html')


@app.route('/addpost', methods =['POST','GET'])
def addpost():
    title = request.form['title']
    subtitle = request.form['subtitle']
    content = request.form['content']
    photo = save_img(request.files.get('photo'))

    post = Blogspot(title=title, subtitle=subtitle, content=content, imgs=photo)
    db.session.add(post)
    db.session.commit()

    return redirect(url_for('index'))
@app.route('/adduser', methods =['POST','GET'])
def adduser():
    name = request.form['name']
    password = request.form['password']

    user = User(name=name, password=password)
    db.session.add(user)
    db.session.commit()

    return redirect(url_for('signup'))

if __name__ == '__main__':
    app.run(debug=True)