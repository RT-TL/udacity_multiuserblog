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

### User as global var
user = False

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
        params['user'] = user
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

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        user = uid and User.by_id(int(uid))

        if user:
            global user
            user = user

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
    subject = db.StringProperty()
    content = db.TextProperty()
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now=True)
    author = db.ReferenceProperty(User)
    likes = db.ListProperty(db.Key)

    def render(self, *user):
        self._render_text = self.content.replace('\n', '<br>')

        admin = False

        # Turn off admin mode if user is not owner
        if user:
            if self.is_owner(user[0].id()):
                admin = True

        return render_str("posts_view.html", p=self ,admin=admin, user = user)

    # Receives a user object as parameter. Checks if user is owner
    def is_owner(self, user_id):
        if not self.author.key().id() == user_id:
            return False
        return True

    # Get a certain post data by its ID
    @classmethod
    def by_id(cls, id):
        key = db.Key.from_path('Post', int(id), parent=blog_key())
        post = db.get(key)

        if post:
            return post

    # Validate data set to the model
    def validates(self):
        if not self.content:
            return False
        if not self.subject:
            return False
        if not self.author:
            return False
        return True

    # Return number of likes (integer)
    def number_of_likes(self):
        like_amount = len(self.likes)
        return like_amount

    # Return boolean true when user is added to like
    def like(self):
        if user.key() not in self.likes:
            self.likes.append(user.key())
            self.put()
            return True
        return False

    # Return boolean true if user is removed to like
    def dislike(self):
        if user.key() in self.likes:
            self.likes.remove(user.key())
            self.put()
            return True
        return False

    # Return boolean true if requested user is in the like list
    def liked_by(self):
        # Check if user is in like-keys
        if user.key() in self.likes:
            return True
        return False

## COMMENT MODEL
class Comment(db.Model):
    title = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now=True)
    author = db.ReferenceProperty(User)

    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        #return render_str("post.html", p=self)

### ENDPOINT-CLASSES


## POSTS

# View post handler
class PostsController(BlogHandler):
    # define model variable that determines which forms to render/where to find them and which data to load
    def get(self, id):
        post = Post.by_id(id)

        if not post:
            self.error(404)
            return

        self.render("permalink.html", p = post)

class DeletePost(BlogHandler):
    def post (self, id):
        post = Post.by_id(id)

        # Exception if not found
        if not post:
            self.error(404)
            return

        # Validate user is allowed to delete
        if not post.is_owner(self.user.key().id()):
            return self.render('error.html', message="Sorry, you can not delete this post.")

        # Delete current post
        post.delete()

        # Redirect to index page
        self.render('message.html', message="The post " + id + ' has been deleted.')

class LikePost(BlogHandler):
    def post(self, id):
        post = Post.by_id(id)

        # Allow only logged in useres
        if not user:
            self.redirect('/login')

        # Exception if not found
        if not post:
            self.error(404)
            return

        # Like current post
        post.like()

        # Redirect to previous page
        #TODO: Replace later by ajax call
        self.redirect(self.request.referer)

class DislikePost(BlogHandler):
    def post(self, id):
        post = Post.by_id(id)

        # Allow only logged in useres
        if not user:
            self.redirect('/login')

        # Exception if not found
        if not post:
            self.error(404)
            return

        # Like current post
        post.dislike()

        # Redirect to previous page
        # TODO: Replace later by ajax call
        self.redirect(self.request.referer)


# Add post handler
class AddPost(BlogHandler):

    def get(self):
        # Check if user is logged in
        if not self.user:
            self.redirect("/login")

        post = Post
        self.render('posts_form_new.html', post=post)

    def post(self):

        # only logged in users have access to post
        if not self.user:
            self.redirect('/login')

        # set post data
        subject = self.request.get('subject')
        content = self.request.get('content')
        author = self.user
        post = Post(parent = blog_key(), subject = subject, content=content, author=author)

        # Show validation errors
        if not post.validates():
            return self.render('posts_form_new.html', post=post, content=content, subject=subject, error="Invalid data for new post")
        else:
            # Save new data
            post.put()

        # Render permalink view
        self.redirect('/posts/%s' % str(post.key().id()))


# Edit post handler
class EditPost(BlogHandler):

    def get(self, id):
        # Check if user is logged in
        if not self.user:
            self.redirect("/login")

        # Get post data
        post = Post.by_id(id)

        # Refer to previous page if not allowed
        if not post.is_owner(self.user.key().id()):
            return self.render('error.html', message="Sorry, you can not edit this post.")

        self.render('posts_form.html', post=post)

    def post(self, id):

        # only logged in users have access to post
        if not self.user:
            self.redirect('/login')

        # get previous post data
        post = Post.by_id(id)

        # read post data
        post.subject = self.request.get('subject')
        post.content = self.request.get('content')

        # Check ownership rights
        if not post.is_owner(self.user.key().id()):
            return self.render('error.html', message="Sorry, you can not edit this post.")

        # Show validation errors
        if not post.validates():
            return self.render('posts_form.html', post=post, error="Invalid data for new post")

        post.put()

        # Render permalink view
        self.render("permalink.html", p=post, message="Data stored")

# Show list of all posts
class PostsIndex(BlogHandler):
    def get(self):
        # Get all post data
        posts = Post.all().order('-created')
        self.render('/posts_index.html', posts=posts)

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
            self.redirect('/posts/')

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
        self.redirect('/posts/')

class Welcome(BlogHandler):
    def get(self):
        username = self.request.get('username')
        if valid_username(username):
            self.render('welcome.html', username = username)
        else:
            self.redirect('/unit2/signup')

### ROUTER
app = webapp2.WSGIApplication([('/', MainPage),
                               webapp2.Route('/posts/add', AddPost),
                               webapp2.Route('/posts/<id>', PostsController),
                               webapp2.Route('/posts/<id>/edit', EditPost),
                               webapp2.Route('/posts/<id>/delete', DeletePost),
                               webapp2.Route('/posts/<id>/like', LikePost),
                               webapp2.Route('/posts/<id>/dislike', DislikePost),
                               ('/posts/', PostsIndex),
                               webapp2.Route('/comments/<id>', CommentsController),
                               ('/signup', Register),
                               ('/login', Login),
                               ('/logout', Logout),
                               ],
                              debug=True)
