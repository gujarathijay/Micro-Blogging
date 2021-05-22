from datetime import datetime, timedelta
# import json
import re
import jwt
from flask import Flask, jsonify, request, make_response
from flask.wrappers import Request
from flaskext.mysql import MySQL
import uuid
from functools import wraps



app = Flask(__name__)
# mysql = MySQL()
#Comment
# app.config['MYSQL_DATABASE_USER'] = 'root'
# app.config['MYSQL_DATABASE_PASSWORD'] = 'root'
# app.config['MYSQL_DATABASE_DB'] = 'blogs'
# app.config['MYSQL_DATABASE_HOST'] = 'localhost'
# # mysql.init_app(app)


# conn = mysql.connect()
# cursor =conn.cursor()
app.config['SECRET_KEY'] = 'CODINGBUDIES123'
user = ""


def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        # jwt is passed in the request header
        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']
        # return 401 if token is not passed
        if not token:
            return jsonify({'message' : 'Token is missing !!'}), 401

        try:
            # decoding the payload to fetch the stored details
            data = jwt.decode(token, app.config['SECRET_KEY'])
        except:
            return jsonify({
                'message' : 'Token is invalid !!'
            }), 401
        # returns the current logged in users contex to the routes
        return  f(*args, **kwargs)

    return decorated

@app.route('/')
def hello_world():
    return 'Welcome to MicroBlogging'



@app.route("/api/create", methods=["POST"])
def createUser():
    userName = request.json["username"]
    email    = request.json["email"]
    password = request.json["password"]
    pattern = "^.*(?=.{8,})(?=.*\d)(?=.*[a-z])(?=.*[A-Z])(?=.*[@#$%^&+=]).*$"
    result = re.findall(pattern, password)
    if userExist(userName):
        return "This username is already in use!"

    queryItemCount = "SELECT * FROM users;"
    cursor.execute(queryItemCount)
    data = cursor.fetchall()
    id = len(data) + 1

    print(id)

    if (not result):
        return "password is not strong enough!"
    else:
        insert_stmt = (
                        "INSERT INTO users (id , username, email, password) "
                        "VALUES (%s, %s, %s, %s)"
        )
        data = (id ,userName, email, password)
        cursor.execute(insert_stmt, data)
        response = {
            "id"  : id,
            "username" : userName,
            "email" : email
        }
        conn.commit()
        conn.close()
        return response


@app.route("/api/login", methods=["POST"])
def checkPassword():
    userName = request.json["username"]
    password = request.json["password"]

    queryAuthenticate = "select password from users where username=%s"
    data = (userName)
    cursor.execute(queryAuthenticate, data)
    response = cursor.fetchone()

    if not response:
        return "Please create your account first"

    if response[0] == password:
        user = userName
        token = jwt.encode({
            'exp' : datetime.utcnow() + timedelta(minutes = 30)
        }, app.config['SECRET_KEY'])

        return make_response(jsonify({'token' : token.decode('UTF_8')}), 201)

    return make_response(
            'Could not verify',
            403,
            {'WWW-Authenticate' : 'Basic realm ="Wrong Password !!"'}
        )


@app.route("/api/follow", methods=["POST"])
@token_required
def addFollower():
    currentUser  = request.json["username"]
    userToFollow = request.json["usernameToFollow"]

    queryid1 = "select id from users where username=%s"
    data = (currentUser)
    cursor.execute(queryid1, data)
    id1= cursor.fetchone()[0]

    queryid2 = "select id from users where username=%s"
    data = (userToFollow)
    cursor.execute(queryid2, data)
    id2 = cursor.fetchone()[0]

    fetchFollowers = "select follower_id, following_id from followers where follower_id=%s AND following_id=%s"
    data = (id1, id2)
    cursor.execute(fetchFollowers, data)
    response = cursor.fetchone()

    if not response:
        # insert
        insert_stmt = (
                        "INSERT INTO followers (follower_id, following_id) "
                        "VALUES (%s, %s)"
        )
        data = (id1, id2)
        cursor.execute(insert_stmt, data)
        conn.commit()
        return "Successfully added to your friend list"

    else:
        return "You are already friends!"


@app.route("/api/removeFollower", methods=["DELETE"])
@token_required
def removeFollower():
    currentUser  = request.json["username"]
    userToRemove = request.json["usernameToRemove"]

    queryid1 = "select id from users where username=%s"
    data = (currentUser)
    cursor.execute(queryid1, data)
    id1= cursor.fetchone()[0]

    queryid2 = "select id from users where username=%s"
    data = (userToRemove)
    cursor.execute(queryid2, data)
    id2 = cursor.fetchone()[0]

    # delete row
    delete_stmt = ("DELETE FROM followers WHERE follower_id=%s AND following_id=%s"
        )

    values = (id1, id2)
    cursor.execute(delete_stmt, values)
    conn.commit()
    return "Successfully removed from your friend list"




def userExist(username):
    queryAuthenticate = "select username from users where username=%s"
    data = (username)
    cursor.execute(queryAuthenticate, data)
    response = cursor.fetchone()

    if not response:
        return False
    return True



#TimeLine Service is remaining
@app.route("/api/userTimeline/<user>", methods=["GET"])
@token_required
def getUserTimeline(user):
    currentUser  = user
    stmt='''SELECT text FROM posts WHERE user_id in(
    SELECT id from users where username=%s
    )'''
    data=currentUser
    cursor.execute(stmt,data)
    rv = cursor.fetchall()
    payload = []
    content = {}
    for result in rv:
        content = {'username':currentUser, 'post': result[0]}
        payload.append(content)
        content = {}
    return jsonify(payload)

@app.route("/api/publicTimeline/", methods=["GET"])
@token_required
def getPublicTimeline():
    stmt='''SELECT username,text from users inner join posts on users.id=posts.user_id'''
    cursor.execute(stmt)
    rv = cursor.fetchall()
    payload = []
    content = {}
    for result in rv:
        content = {'username':result[0], 'post': result[1]}
        payload.append(content)
        content = {}
    return jsonify(payload)

@app.route("/api/homeTimeline/<user>", methods=["GET"])
@token_required
def getHomeTimeline(user):
    currentUser  = user
    stmt='''select friendname, text from home where username = %s'''
    data=currentUser
    cursor.execute(stmt,data)
    rv = cursor.fetchall()
    payload = []
    content = {}
    for result in rv:
        content = {'username':result[0], 'post': result[1]}
        payload.append(content)
        content = {}
    return jsonify(payload)
#    Returns recent posts from all users that this user follows.

@app.route("/api/postTweet", methods=["POST"])
@token_required
def postTweet():
    currentUser  = request.json["username"]
    text         = request.json["tweet"]

    stmt='''INSERT INTO posts (user_id,text) VALUES
    ((SELECT id from users WHERE username=%s),%s)'''
    data=(currentUser,text)
    cursor.execute(stmt,data)
    conn.commit()
    return {"text":"Tweet Successful"}

#ADDED ALL
if __name__ == '__main__':
    app.run(debug=True)
