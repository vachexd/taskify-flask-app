import smtplib
from email.mime.text import MIMEText

from flask import Flask , redirect, url_for, request , session,render_template
from flask_bcrypt import Bcrypt
from flask_sqlalchemy import SQLAlchemy
from authlib.integrations.flask_client import OAuth
from datetime import datetime
import re ,os , requests
from random import randint
from vars import key , forecasturl , apppass , googleclientid , googleclientsecret , googlediscoveryurl

app =Flask(__name__)
app.app_context().push()
app.config['SECRET_KEY'] = '338338'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] ='sqlite:///' + os.path.join(basedir+"/instance", 'taskmanagerdb.sqlite')
db = SQLAlchemy(app)
app.config['GOOGLE_CLIENT_ID'] = googleclientid
app.config['GOOGLE_CLIENT_SECRET'] = googleclientsecret
app.config['GOOGLE_DISCOVERY_URL'] =googlediscoveryurl



class Task(db.Model):
    id=db.Column(db.Integer , primary_key=True , unique=False)

    weather=db.Column(db.Float , nullable=True)
    holiday=db.Column(db.String, nullable=True)
    userid=db.Column(db.Integer , nullable=False)
    date=db.Column(db.String , nullable=False)
    hour=db.Column(db.String,nullable=True)
    task=db.Column(db.String, nullable=True)

class User(db.Model):
    id=db.Column(db.Integer , primary_key=True)
    mail=db.Column(db.String,unique=True, nullable=False)
    password=db.Column(db.String, nullable=False)

    def __repr__(self):
        return f'<user {self.mail}>'

def is_valid_email(email):

    regex = r'^[a-z0-9]+[\._]?[a-z0-9]+[@]\w+[.]\w+$'

    if re.match(regex, email):

        return True
    else:
        return False

def checkcreds(mail,password):
    if(mail=='' or password=='' or mail==None or password==None or is_valid_email(mail)==False):
        return 'invalid mail or password'
    else:


        return True

def sendmail2(recipient):
    code = randint(100, 1000)
    msg = MIMEText(f'Code - {code}')
    msg['Subject'] = 'Verification Code'
    msg['From'] = "taskify999@gmail.com"
    msg['To'] = ', '.join(recipient)

    with smtplib.SMTP_SSL('smtp.gmail.com', 465) as smtp_server:
        smtp_server.login('taskify999@gmail.com', apppass)
        smtp_server.sendmail('taskify999@gmail.com', recipient, msg.as_string())

    return code
    print("Message sent!")


def registeruser(mail,password):
    bcrypt=Bcrypt(app)

    user=User(mail=mail,password=bcrypt.generate_password_hash(password).decode('utf-8'))
    db.session.add(user)
    db.session.commit()


@app.route('/forgotpassword' , methods=['GET' , 'POST'])
def forgotpasswordpage():


    if(request.method=='POST'):
        if('pw1' in request.form.keys()):
            if(request.form.get('pw1')==request.form.get('pw2')):
                bcrypt=Bcrypt(app)
                User.query.filter_by(mail=session['recovermail']).first().password=bcrypt.generate_password_hash(request.form.get('pw1'))
                db.session.commit()
                session.pop('recovermail',None)
                return redirect(url_for('loginpage'))

            else:
                return render_template('forgotpasswordfinal.html' , status='invalid passwords')


        if('inputcode' in request.form.keys()):

            if(str(request.form.get('inputcode'))==str(session['sentcode'])):
                session.pop('sentcode',None)
                return render_template('forgotpasswordfinal.html')
            else:
                return render_template('forgotpasswordverify.html' , mail=session['recovermail'])
        mail=request.form.get('mail')
        if is_valid_email(mail)!=1:
            return render_template('forgotpassword.html' , status='not valid mail')
            print('not valid mail')
        elif User.query.filter_by(mail=mail).first() is None:
            return render_template('forgotpassword.html'  ,status='mail not found')
            print('mail not found')
        else:

            session['sentcode']=sendmail2(mail)
            session['recovermail']=mail

            return render_template('forgotpasswordverify.html' , mail=mail)
    return render_template('forgotpassword.html')


@app.route('/registration' , methods=['GET','POST'])
def registrationpage():

    if(request.method=='GET'):

        return render_template('registration.html')
    elif(request.method=='POST'):
        if('code' in request.form.keys()):


            if(int(request.form.get('code'))==int(session['sentcode'])):

                registeruser(request.form.get('mail'), session['registerpassword'])
                session.pop('registerpassword' , None)

                session.pop('sentcode' , None)
                session['username'] = request.form.get('mail')
                return redirect(url_for('loggedinpage'))
            else:

                return render_template('verification.html' , wrongmessage='wrong code , try again',mail=request.form.get('mail') )

        else:


            mail = request.form.get('mail')
            result=User.query.filter_by(mail=mail).first()

            if (result != None):

                return render_template('registration.html', status='already registered')

            elif (request.form.get('pw1') != request.form.get('pw2')):


                return render_template('registration.html', status='passwords dont match')
            else:
                credstatus = checkcreds(request.form.get('mail'), request.form.get('pw1'))

                if (credstatus == True):
                    code = sendmail2(mail)
                    print('sent code , redirecting to verification.html')

                    session['registerpassword']=request.form.get('pw1')
                    session['sentcode']=code
                    print(session['registerpassword'])
                    print(session['sentcode'])
                    return render_template('verification.html', mail=request.form.get('mail') )


                else:
                    return render_template('registration.html')

@app.route('/' , methods=['GET' , 'POST'] )
@app.route('/login' , methods=['GET' , 'POST'] )
def loginpage():

    if(request.method=='POST'):
        response=User.query.filter_by(mail=request.form.get('nm')).first()

        bcrypt=Bcrypt(app)
        if(response==None):
            return render_template('login.html', status='incorrect creds')
        elif(bcrypt.check_password_hash(response.password,request.form.get('pw'))!=1):
            return render_template('login.html' , status='incorrect creds')
        else:
            session['username']=request.form.get('nm')
            return redirect(url_for('loggedinpage'))

    else:
        return render_template('login.html')
@app.route('/googlelogin' )
def googleloginpage():
    oauth = OAuth(app)
    google = oauth.register(
        name='google',
        client_id=app.config['GOOGLE_CLIENT_ID'],
        client_secret=app.config['GOOGLE_CLIENT_SECRET'],
        server_metadata_url=app.config['GOOGLE_DISCOVERY_URL'],
        client_kwargs={
            'scope': 'openid https://www.googleapis.com/auth/userinfo.profile https://www.googleapis.com/auth/userinfo.email'
        }
    )
    redirect_uri = url_for('authorize', _external=True)
    return google.authorize_redirect(redirect_uri)

@app.route('/auth/callback')
def authorize():
    oauth = OAuth(app)
    google = oauth.register(
        name='google',
        client_id=app.config['GOOGLE_CLIENT_ID'],
        client_secret=app.config['GOOGLE_CLIENT_SECRET'],
        server_metadata_url=app.config['GOOGLE_DISCOVERY_URL'],
        client_kwargs={
            'scope': 'openid https://www.googleapis.com/auth/userinfo.profile https://www.googleapis.com/auth/userinfo.email'
        }
    )
    token = google.authorize_access_token()
    user_info = google.parse_id_token(token , None)


    if(User.query.filter_by(mail=user_info['email']).first()!=None):
        session['username'] = user_info['email']
        return redirect(url_for('loggedinpage'))

    else:


        return redirect('/login')


@app.route('/logout')
def logoutfunc():
    if('username' in session.keys()):
        session.pop('username' , None)
    return redirect(url_for('loginpage'))

@app.route('/loggedin' , methods=['GET' , 'POST'])
def loggedinpage():
    if(request.method=='POST'):

        deletetask(request.form.get('taskid'))
        return render_template('loggedin.html', user=session['username'],
                               tasks=Task.query.filter_by(
                                   userid=User.query.filter_by(mail=session['username']).first().id).all())

    if('username' not in session.keys()):

        return redirect(url_for('loginpage'))
    elif(session['username']==None):
        return redirect(url_for('loginpage'))
    else:
        checktasks()
        return render_template('loggedin.html' , user=session['username'] ,
                               tasks = Task.query.filter_by(userid=User.query.filter_by(mail=session['username']).first().id).all())


@app.route('/addtask' , methods=['GET' , 'POST'])
def addtaskpage():
    if(request.method=='GET'):
        return render_template('addtask.html')

    if(request.method=='POST'):
        print(request.form.get('date'))
        if(request.form.get('date')==''):
            return render_template('addtask.html' , error='invalid date')
        date = checkdate(request.form.get('date'))

        if(date==None):
            return render_template('addtask.html' , error='invalid date')

        weather=getweather(date)

        task=Task(task=request.form.get('task') , date=str(date), hour = request.form.get('hour') , userid=User.query.filter_by(mail=session['username']).first().id , weather=weather , holiday=checkholidays(str(date)) )

        db.session.add(task)
        db.session.commit()
        return redirect(url_for('loggedinpage'))

def checkdate(date):
    today = datetime.today().date()
    datesplit = date.split('-')
    inputdate = datetime(int(datesplit[0]), int(datesplit[1]), int(datesplit[2])).date()
    if(inputdate<today):
        return None
    else:
        return inputdate

def deletetask(taskid):

    db.session.delete(Task.query.filter_by(id=taskid).first())
    db.session.commit()

def getweather(date):

    forecastparameters={
        'key':key,
        'q':'Tbilisi',
        'days':14
    }

    resp=requests.get(forecasturl,params=forecastparameters)

    if(resp.status_code!=200):
        return None

    for forecastday in resp.json()['forecast']['forecastday']:

        if (forecastday['date'] == str(date)):
            return forecastday['day']['avgtemp_c']


def checktasks():
    today=datetime.today().date()
    tasks=Task.query.all()
    for task in tasks:
        print(type(task.date))

        tasksplit=task.date.split('-')
        print(tasksplit)
        taskdate=datetime(int(tasksplit[0]) , int(tasksplit[1]) , int(tasksplit[2])).date()
        if (taskdate < today):
            deletetask(task.id)


def checkholidays(date):
    newdate = datetime(datetime.today().year, int(date.split('-')[1]), int(date.split('-')[2])).date()

    resp = requests.get(f'https://date.nager.at/api/v3/PublicHolidays/{datetime.today().year}/GE')
    for day in resp.json():

        if (day['date'] == str(newdate)):
            return day['name']

if __name__ == '__main__':
    # db.drop_all()
    db.create_all()
    app.run(debug=True)
