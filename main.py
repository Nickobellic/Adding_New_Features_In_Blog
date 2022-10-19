from flask import Flask, render_template, redirect, url_for, flash, request, abort
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from functools import wraps
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import CreatePostForm, RegisterForm, LoginForm, CommentForm
from flask_gravatar import Gravatar

app = Flask(__name__)
app.config['SECRET_KEY'] = '8BYkEfBA6O6donzWlSihBXox7C0sKR6b'
ckeditor = CKEditor(app)
Bootstrap(app)
login_manager = LoginManager()
login_manager.init_app(app)
ckeditor = CKEditor()

##CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
db.init_app(app)


##CONFIGURE TABLES
def admin_only(f):
    @wraps(f)
    @login_required
    def decorated_function(*args, **kwargs):
        #If id is not 1 then return abort with 403 error
        if current_user.id != 1:
            return abort(403)
        #Otherwise continue with the route function
        return f(*args, **kwargs)
    return decorated_function


class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    author = db.Column(db.String(250), nullable=False)
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)
    children = relationship('Users')

class Users(db.Model, UserMixin):
    __tablename__ = "Users"
    id = db.Column(db.Integer, primary_key=True)
    parent_id = db.Column(db.Integer, db.ForeignKey('blog_posts.id'))
    name = db.Column(db.String(200), nullable=False)
    email = db.Column(db.String(250), unique=True, nullable=False)
    password = db.Column(db.String(200), unique=False, nullable=False)
    parent = relationship('BlogPost')

class Comment(db.Model, UserMixin):
    __tablename__ = "Comment"
    author = db.Column(db.String(100), nullable=False, primary_key=True)
    comment = db.Column(db.String(1000), nullable=False)



@login_manager.user_loader
def load_user(user_id):
    return Users.query.get(user_id)

@app.route('/')
def get_all_posts():
    posts = BlogPost.query.all()
    if Users.is_authenticated and Users.is_active:
        return render_template("index.html", all_posts=posts, log=False)
    else:
        return render_template("index.html", all_posts=posts, log=True)



@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if request.method == "POST":
        count = 0
        users = Users.query.all()
        for i in users:
            if form.email.data == i.email and check_password_hash(pwhash=i.password, password=form.password.data):
                count += 1
                break

        if count == 0:
            new_user = Users(id=len(users) + 1, name=form.name.data, email=form.email.data,
                             password=generate_password_hash(password=form.password.data, method="pbkdf2:sha256",
                                                             salt_length=8))
            db.session.add(new_user)
            db.session.commit()
            return redirect(url_for('get_all_posts'))
        else:
            flash('You\'ve already Registered. Log In Instead! ')
            return redirect(url_for('login'))


    if Users.is_authenticated:
        logged = True
    else:
        logged = False

    return render_template("register.html", form=form, log =logged)


@app.route('/login', methods=['GET', 'POST'])
def login():
    logged = True
    adm = False
    login = LoginForm()
    correct = True
    if request.method == "POST":
        users = Users.query.all()
        for i in users:
            if i.email == login.email.data:
                if check_password_hash(pwhash=i.password ,password=login.password.data):
                    correct = True
                    posts = BlogPost.query.all()
                    login_user(Users.query.filter_by(email=i.email).first())
                    if Users.query.filter_by(email=i.email).first().id == 1:
                        adm = True
                    else:
                        adm = False
                    return render_template("index.html", all_posts=posts, log=True, admin=adm)
                else:
                    correct = False
                    break
            else:
                correct = False
                break
        if correct:
            flash('Logged In successfully')
        else:
            flash('Please Try Again. Email ID not found')
    if Users.is_authenticated:
        logged = True
    else:
        logged = False
    return render_template("login.html", form=login, log=logged, admin=adm)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:post_id>", methods=['GET','POST'])
@login_required
def show_post(post_id):
    comms = Comment.query.all()
    if Users.is_authenticated:
        logged = True
    else:
        logged = False
    if current_user.id == 1:
        adm = True
    else:
        adm = False
    requested_post = BlogPost.query.get(post_id)
    com_box = CommentForm()
    if request.method == 'POST':
        commented = Comment(author=Users.query.filter_by(id=current_user.id).first().name,comment=request.form.get('content')[3:-6])

        db.session.add(commented)
        db.session.commit()
        return redirect(url_for('get_all_posts'))
    return render_template("post.html", post=requested_post, form=com_box, log=logged, admin=adm, comments=comms)


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact")
def contact():
    return render_template("contact.html")


@app.route("/new-post", methods=['GET', 'POST'])
@admin_only
def add_new_post():
    adm = False
    if Users.is_authenticated:
        logged = True
    else:
        logged = False
    form = CreatePostForm()
    if request.method == 'POST':
        if form.validate_on_submit():
            new_post = BlogPost(
                id = len(BlogPost.query.all())+1,
                title=form.title.data,
                subtitle=form.subtitle.data,
                body=form.body.data,
                img_url=form.img_url.data,
                author=current_user.name,
                date=date.today().strftime("%B %d, %Y")
            )
            db.session.add(new_post)
            db.session.commit()
            return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form, log=logged, admin=adm)


@app.route("/edit-post/<int:post_id>", methods=['GET','POST'])
@admin_only
def edit_post(post_id):
    post = BlogPost.query.get(post_id)
    if request.method == 'POST':
        edit_form = CreatePostForm(
            title=post.title,
            subtitle=post.subtitle,
            img_url=post.img_url,
            body=post.body
        )
        if edit_form.validate_on_submit():
            post.title = edit_form.title.data
            post.subtitle = edit_form.subtitle.data
            post.img_url = edit_form.img_url.data
            post.body = edit_form.body.data
            db.session.commit()
            return redirect(url_for("show_post", post_id=post.id))

    return render_template("make-post.html", form=edit_form)


@app.route("/delete/<int:post_id>")
@admin_only
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


if __name__ == "__main__":
    app.run(debug=True)
