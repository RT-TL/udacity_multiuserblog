import os
import re
import random
import hashlib
import hmac
from string import letters

import webapp2
import jinja2

from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                               autoescape = True)

secret = 'LASER'


### GLOBAL FUNCTIONS###


## RENDER VIEWS

# Render function
def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)

# Function to render a post (REMOVE)
def render_post(response, post):
    response.out.write('<b>' + post.subject + '</b><br>')
    response.out.write(post.content)


## User Security

# Return security salt
def make_salt(length = 5):
    return ''.join(random.choice(letters) for x in xrange(length))

# Return secure string for cookie with hash and salt
def make_pw_hash(name, pw, salt = None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (salt, h)

# Return if provided paramters are valid password
def valid_pw(name, password, h):
    salt = h.split(',')[0]
    return h == make_pw_hash(name, password, salt)

# Return user key
def users_key(group = 'default'):
    return db.Key.from_path('users', group)

# Create secure value
def make_secure_val(val):
    return '%s|%s' % (val, hmac.new(secret, val).hexdigest())

# Return if secure value is valid
def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val

def blog_key(name='default'):
    return db.Key.from_path('blogs', name)


### CLASSES

## BLOG CLASS
class BlogHandler(webapp2.RequestHandler):
    # Render functions
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        params['user'] = self.user
        return render_str(template, **params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    # Authorization & authenciation
    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val))

    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    def login(self, user):
        self.set_secure_cookie('user_id', str(user.key().id()))

    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

    # Request handlers
    def get(self, id):
        if not id:
            self.render('message.html', message="Gibts nicht")
        self.handleGet(id)

    def put(self, *id):
        self.render('message.html', message="put request")

    def post(self, *id):
        # validate data
        # id available
        # for edit/delete: owner true
        # success: redirect
        # error: render edit form via self.renderForm();
        self.render('message.html', message="post request")

    def delete(self, *id):
        self.render('message.html', message="delete request")

    def handleGet(self, id):
        return True

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))


class MainPage(BlogHandler):
  def get(self):
      self.write('Hello, Udacity!')



### MODELS


## USER MODEL

class User(db.Model):
    name = db.StringProperty(required = True)
    pw_hash = db.StringProperty(required = True)
    email = db.StringProperty()

    @classmethod
    def by_id(cls, uid):
        return User.get_by_id(uid, parent = users_key())

    @classmethod
    def by_name(cls, name):
        u = User.all().filter('name =', name).get()
        return u

    @classmethod
    def register(cls, name, pw, email = None):
        pw_hash = make_pw_hash(name, pw)
        return User(parent = users_key(),
                    name = name,
                    pw_hash = pw_hash,
                    email = email)

    @classmethod
    def login(cls, name, pw):
        u = cls.by_name(name)

        if u and valid_pw(name, pw, u.pw_hash):
            return u


## POST MODEL
class Post(db.Model):
    subject = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now=True)
    author = db.ReferenceProperty(User)

    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        return render_str("post.html", p=self)

## COMMENT MODEL
class Comment(db.Model):
    title = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now=True)
    author = db.ReferenceProperty(User)

    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        return render_str("post.html", p=self)

## LIKE MODEL
class Like(db.Model):
    author = db.ReferenceProperty(User)
    post = db.ReferenceProperty(Post)

### ENDPOINT-CLASSES

## BLOG OVERVIEW
class BlogFront(BlogHandler):
    def get(self):
        posts = greetings = Post.all().order('-created')
        self.render('front.html', posts = posts)

## POSTS

class PostsController(BlogHandler):
    # define model variable that determines which forms to render/where to find them and which data to load
    def handleGet(self, id):
        self.render('message.html', message=str(id) + " gibts!")

class PostsIndex(BlogHandler):
    def get(self):
        self.render('message.html', message="Ich bin der geile index")

## COMMENTS
class CommentsController(BlogHandler):
    def handleGet(self, id):

        self.render('message.html', message=str(id) + " gibts!")


## SIGNUP AND LOGIN FUNCTIONS

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
    return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
    return password and PASS_RE.match(password)

EMAIL_RE  = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
def valid_email(email):
    return not email or EMAIL_RE.match(email)

class Signup(BlogHandler):
    def get(self):
        self.render("signup-form.html")

    def post(self):
        have_error = False
        self.username = self.request.get('username')
        self.password = self.request.get('password')
        self.verify = self.request.get('verify')
        self.email = self.request.get('email')

        params = dict(username = self.username,
                      email = self.email)

        if not valid_username(self.username):
            params['error_username'] = "That's not a valid username."
            have_error = True

        if not valid_password(self.password):
            params['error_password'] = "That wasn't a valid password."
            have_error = True
        elif self.password != self.verify:
            params['error_verify'] = "Your passwords didn't match."
            have_error = True

        if not valid_email(self.email):
            params['error_email'] = "That's not a valid email."
            have_error = True

        if have_error:
            self.render('signup-form.html', **params)
        else:
            self.done()

    def done(self, *a, **kw):
        raise NotImplementedError

class Register(Signup):
    def done(self):
        u = User.by_name(self.username)
        if u:
            msg = 'That user already exists.'
            self.render('signup-form.html', error_username = msg)
        else:
            u = User.register(self.username, self.password, self.email)
            u.put()

            self.login(u)
            self.redirect('/blog')

class Login(BlogHandler):
    def get(self):
        self.render('login-form.html')

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')

        u = User.login(username, password)
        if u:
            self.login(u)
            self.redirect('/posts/')
        else:
            msg = 'Invalid login'
            self.render('login-form.html', error = msg)

class Logout(BlogHandler):
    def get(self):
        self.logout()
        self.redirect('/blog')

class Welcome(BlogHandler):
    def get(self):
        username = self.request.get('username')
        if valid_username(username):
            self.render('welcome.html', username = username)
        else:
            self.redirect('/unit2/signup')

app = webapp2.WSGIApplication([('/', MainPage),
                                webapp2.Route('/posts/<id>', PostsController),
                               #webapp2.Route('/posts/<id>/add/edit', EditPost),#receives optional submit data and errors
                               ('/posts/', PostsIndex),
                               webapp2.Route('/comments/<id>', CommentsController),
                               ('/blog/?', BlogFront),
                               ('/signup', Register),
                               ('/login', Login),
                               ('/logout', Logout),
                               ],
                              debug=True)