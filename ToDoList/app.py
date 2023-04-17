from flask import Flask, request, render_template, url_for, redirect, make_response
from datetime import datetime, timedelta
import bcrypt, jwt, datetime
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

engine = create_engine("sqlite:///:memory:", echo=True)

Session = sessionmaker(bind=engine)
Session.configure(bind=engine)  # once engine is available
session = Session()

app = Flask(__name__)
app.config['SECRET_KEY'] = 'mysecretkey'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:////tmp/ToDoList.db'
db = SQLAlchemy(app)



class Users(db.Model):
    __tablename__ = 'users'
    
    name = db.Column(db.String)
    email = db.Column(db.String, unique=True, primary_key=True)
    password = db.Column(db.String)
    # tasks = relationship('Tasks', back_populates='user')

    def __init__(self, name, email, password):
        self.name = name
        self.email = email
        self.password = password

    def __repr__(self):
        # return "{'name': {}, 'email': {}, 'password': {}}".format(self.name,self.password, self.email)
        return f'<Users {self.name}>'
    
    
class Tasks(db.Model):
    __tablename__ = 'tasks'
    
    # id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    task = db.Column(db.String, primary_key=True)
    description = db.Column(db.String)
    date = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    # email = db.Column(db.String, unique=True)
    # user_email = db.Column(db.String, db.ForeignKey('users.email'))
    # user = relationship('Users', back_populates='tasks')
    
    def __init__(self, task, description):
        self.task = task
        self.description = description
    def __repr__(self):
        return '<Task %r>' % self.task

# @app.before_first_request
# def create_tables():
#     db.create_all() 
# app.app_context().push()
# db.create_all()

with app.app_context():
    db.create_all()


@app.route("/", methods = ['GET', 'POST'])
def index():
    return redirect(url_for("login"))


@app.route('/register', methods=['POST', 'GET'])
def register():
    if request.method == 'POST':
        new_name = request.form['name']
        new_email = request.form['email']
        
        new_password = request.form['password']
        repeat_password = request.form['repeat_password']
        
        if new_password == repeat_password:
            new_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())
            user = Users(name = new_name, email = new_email, password= new_password)
            db.session.add(user)
            db.session.commit()
            return redirect(url_for('login'))
        return "Password did not match"
    return render_template('register.html')


@app.route('/login', methods=['POST', 'GET'])
def login():
    if request.method == 'POST':
        new_email = request.form['email']
        new_password = request.form['password']
        print('new_email', new_email)
        print(new_password)
        new_password = new_password.encode('utf-8')
        
        user_objs = Users.query.all()
        print(user_objs)

        for user_obj in user_objs:
            print(user_obj, user_obj.password )

            if bcrypt.checkpw(new_password, user_obj.password):
                print(user_obj.email)
                token_expiry = datetime.datetime.utcnow() + timedelta(minutes=1) # set token expiration time to 1 minute from now
                token = jwt.encode({'email': new_email, 'exp': token_expiry}, app.config['SECRET_KEY'], algorithm='HS256')
                resp = make_response(redirect(url_for('dashboard')))
                resp.set_cookie('token', token)
                return resp
    return render_template('login.html')


@app.route('/show_tasks', methods=['GET'])
def show_tasks():
    if request.method == "GET":
        all_tasks = Tasks.query.all()
        for task in all_tasks:
            print(task, task.description, task.date)
        return render_template('dashboard.html', tasks = all_tasks)
    


@app.route('/dashboard', methods=['POST', 'GET'])
def dashboard():
    token = request.cookies.get('token')
    email = request.cookies.get("email")
    print(token)
    if not token:
        return redirect(url_for('login'))

    try:
        data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        # check if token is expired
        if datetime.datetime.utcnow() > datetime.datetime.fromtimestamp(data['exp']):
            return redirect(url_for('login'))
    except jwt.exceptions.ExpiredSignatureError:
        return redirect(url_for('login'))
    except jwt.exceptions.InvalidTokenError:
        return redirect(url_for('login'))

    # Only allow access to the dashboard for authenticated users
    return render_template('dashboard.html', email = email)


@app.route('/add_task', methods=['POST', 'GET'])
def add_task():
    if request.method == "POST": 
        new_title = request.form['title']
        new_description = request.form['description']
        # new_email = request.cookies.get("email")

        task = Tasks(task = new_title, description = new_description)
        db.session.add(task)
        db.session.commit()
        return redirect(url_for('show_tasks'))
    return render_template("add_task.html")

@app.route('/delete_task/<string:task>', methods = ["POST"])
def delete_task(task):
    if request.method == "POST":
        taskk = task
        taske = Tasks.query.filter_by(task=taskk).first_or_404()
        db.session.delete(taske)
        db.session.commit()
        # db.flash(f'Task {taskk} deleted successfully!', 'success')
    return render_template('dashboard.html', tasks = Tasks.query.all())


    
if __name__ == '__main__':
    app.run(debug=True)
