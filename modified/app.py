from flask import Flask, render_template, request,redirect, url_for,flash , session
from dbConnector import UseDatabase
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user,current_user
from flask_bcrypt import Bcrypt
from flask_session import Session
import secrets
from datetime import timedelta 


dbconfig = {'host': '127.0.0.1', 'user': 'root', 'password': '97082', 'database': 'oop_auth'}

app = Flask(__name__)


#auth config
app.config['SECRET_KEY'] = '7!1:2^64e3u/ghdr?83lawe;#;;./' #it will kill session if server goes down, may is hould give a hard coded random key
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://lol:lol@localhost/oop_auth'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

#session config
app.config['SESSION_TYPE'] = 'filesystem'
app.config['SESSION_PERMANENET'] = True
app.permanent_session_lifetime = timedelta(days=2) #expire after 30 days
Session(app)

# Initialize Flask extensions
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# table creation for auth
class User(UserMixin, db.Model):
    __tablename__ = 'auth'
    id = db.Column(db.Integer, primary_key=True)
    fname = db.Column(db.String(50), nullable=False)
    lname = db.Column(db.String(50))
    email = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    def set_password(self, password):
        self.password_hash = bcrypt.generate_password_hash(password).decode('utf-8')

    def check_password(self, password):
        return bcrypt.check_password_hash(self.password_hash, password)

# User Loader
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))



@app.route('/logout' , methods=['GET','POST'])
#@login_required
def logout():
    if request.method == 'POST' :
        response = request.form['response']
        if response == 'yes' :
            logout_user()
            return redirect(url_for('homepage'))
        else:
            return redirect(url_for('homepage'))
    
    return render_template('logout.html', activelogout='active')


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        fname = request.form['fname']
        lname = request.form['lname']
        email = request.form['email']
        password = request.form['password']

        #only unique email
        existing_email = User.query.filter_by(email=email).first()
        if existing_email:
            flash('already an user with that email , enter different email or login', 'danger')
        else:
            hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
            new_user = User(fname=fname, lname=lname , email=email)
            new_user.set_password(password)

            db.session.add(new_user)
            db.session.commit()
            flash('Sign UP successful. Please login.', 'success')
            return redirect(url_for('login'))

    return render_template('signup.html',activesignup='active', css='/static/signup.css')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()
        if user and user.check_password(password):
            login_user(user)
            #app.config['SESSION_PERMANENET'] = True   #should i do it here ?
            session['email'] = email                   #session will be saved with respect to email
            return redirect(url_for('homepage'))
        else:
            flash('Login failed. Check your credentials', 'danger')
    return render_template('login.html', activelogin='active',css='static/login.css')



#------------------------------------------------------------------------------------------------------------------------------------------------->


@app.route('/') #Done
def homepage() :
    return render_template('homepage.html', activehome='active',css='static/homepagecss.css')

@app.route('/product')  #Done
def product() :
    return render_template('product.html', activeproduct='active',css='static/productcss.css')

@app.route('/about_us') #Sourish Will Do It
def about_us() :

    return render_template('about_us.html', activeabout='active',css='static/about_uscss.css')



@app.route('/result1', methods=['GET', 'POST']) #Anybody Can Try This Best One Will Be Done
def tool() :

    symptom1 = request.form['symptom1']
    symptom2 = request.form['symptom2']
    symptom3 = request.form['symptom3']
    symptom4 = request.form['symptom4']
    symptom5 = request.form['symptom5']

    with UseDatabase(dbconfig) as cursor:
        cmd = "SELECT sympkey FROM symptoms WHERE sympname IN (%s,%s,%s,%s,%s)"
        cursor.execute(cmd,(symptom1, symptom2, symptom3, symptom4, symptom5))
        sympkeys = cursor.fetchall()
        sympkey_tuple = tuple([i[0] for i in sympkeys])


        cmd = "SELECT diskey, sympkey FROM symptodis WHERE sympkey IN {}".format(sympkey_tuple)
        cursor.execute(cmd)
        distosymp = cursor.fetchall()


        distosymp_dict = {}
        for i in distosymp:
            cmd = "SELECT disname FROM disease WHERE diskey=%s"
            cursor.execute(cmd,(i[0],))
            disname = cursor.fetchone()
            if disname[0] not in distosymp_dict:
                distosymp_dict[disname[0]] = [i[1]]
            else:
                distosymp_dict[disname[0]].append(i[1])

        key_length_pairs = [(key, len(value)) for key, value in distosymp_dict.items()]
        key_length_pairs.sort(key=lambda x: x[1], reverse=True)

        distosymp_ordered = {}
        for key, value in key_length_pairs:
            distosymp_ordered[key] = distosymp_dict[key]

    return render_template('result1.html', activeproduct='active', css='static/result1css.css', distosymp=distosymp_ordered)

@app.route('/result2/<sympkeys>/<disname>')
def result2(sympkeys, disname) -> None:
    return str([sympkeys, disname])

if __name__ == '__main__':
    app.run(debug=True)
