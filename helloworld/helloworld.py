import os
import re
#from string import letters

import webapp2
import jinja2
import hmac

SECRET = 'secretsalt'

from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
                               autoescape=True)

# SECURITY FUNCTIONS
def hash_str(s):
    return hmac.new(SECRET, s).hexdigest()

def make_secure_val(s):
    s = str(s)
    return "%s|%s" % (s, hash_str(s))

def check_secure_val(h):
    if not h:
        return False

    val = h.split('|')[0]
    if h == make_secure_val(val):
        return val
    else:
        return False

# GENERIC RENDER FUNCTIONS
def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)


# BLOG CLASS
class BlogHandler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        return render_str(template, **params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

def render_post(response, post):
    response.out.write('<b>' + post.subject + '</b><br>')
    response.out.write(post.content)

class MainPage(BlogHandler):
  def get(self):
      self.response.headers['Content-Type'] = 'text/plain'
      visits = self.request.cookies.get('visits', 0)

##### blog stuff

def blog_key(name = 'default'):
    return db.Key.from_path('blogs', name)

class Post(db.Model):
    subject = db.StringProperty(required = True)
    content = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    last_modified = db.DateTimeProperty(auto_now = True)

    def render(self):
        self._render_text = self.content.replace('\n', '<br>')

class BlogFront(BlogHandler):
    def get(self):
        posts = db.GqlQuery("select * from Post order by created desc limit 10")
        self.render('front.html', posts = posts)

class PostPage(BlogHandler):
    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)

        if not post:
            self.error(404)
            return

        self.render("permalink.html", post = post)

class NewPost(BlogHandler):
    def get(self):
        self.render("newpost.html")

    def post(self):
        subject = self.request.get('subject')
        content = self.request.get('content')

        if subject and content:
            p = Post(parent = blog_key(), subject = subject, content = content)
            p.put()
            self.redirect('/blog/%s' % str(p.key().id()))
        else:
            error = "subject and content, please!"
            self.render("newpost.html", subject=subject, content=content, error=error)

###### Unit 2 HW's
class Rot13(BlogHandler):
    def get(self):
        self.render('rot13-form.html')

    def post(self):
        rot13 = ''
        text = self.request.get('text')
        if text:
            rot13 = text.encode('rot13')

        self.render('rot13-form.html', text = rot13)

### USER REGISTRATION FUNCTIONS
USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
    return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
    return password and PASS_RE.match(password)

EMAIL_RE  = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
def valid_email(email):
    return not email or EMAIL_RE.match(email)

def username_available(username):
    u = User.all().filter('Username =', username).get()
    return not u

class User(db.Model):
    Username = db.StringProperty(required=True)
    Password = db.StringProperty(required=True)
    Email = db.StringProperty(required=False)

class Signup(BlogHandler):

    def get(self):
        self.render("signup-form.html")

    def post(self):
        have_error = False
        username = self.request.get('username')
        password = self.request.get('password')
        verify = self.request.get('verify')
        email = self.request.get('email')

        params = dict(username=username,
                      email=email)

        if not username_available(username):
            params['error_username'] = "This username is already taken"
            have_error = True

        if not valid_username(username):
            params['error_username'] = "That's not a valid username."
            have_error = True

        if not valid_password(password):
            params['error_password'] = "That wasn't a valid password."
            have_error = True
        elif password != verify:
            params['error_verify'] = "Your passwords didn't match."
            have_error = True

        if not valid_email(email):
            params['error_email'] = "That's not a valid email."
            have_error = True

        if have_error:
            self.render('signup-form.html', **params)
        else:
            # Hash password
            password = hash_str(password)

            # Save User
            u = User(Username=username, Password=password, Email=email)
            u.put()

            # Get new user ID
            user_id = u.key().id()

            hashed_user = make_secure_val(user_id)

            # Set cookie
            self.response.headers.add_header('Set-Cookie', 'user_id='+hashed_user+'; Path=/')
            self.redirect('/blog/welcome')

class Welcome(BlogHandler):
    def get(self):
        # read cookie
        user_hash = self.request.cookies.get('user_id')

        # validate cookie
        if check_secure_val(user_hash):
            # set username or redirect
            user_id = int(user_hash.split('|')[0]);
            user = User.get_by_id(user_id)
            self.render('welcome.html', username=user.Username)
        else:
            self.render("signup-form.html")

#check if user has a valid id. If not send him to signup page

application = webapp2.WSGIApplication([
    ('/', MainPage),
    ('/unit2/rot13', Rot13),
    ('/blog/signup', Signup),
    ('/blog/welcome', Welcome),
    ('/blog/?', BlogFront),
    ('/blog/([0-9]+)', PostPage),
    ('/blog/newpost', NewPost)
],debug=True)