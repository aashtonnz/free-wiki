import os
import webapp2
import jinja2
import random
import string
import re
import hmac
import time
import logging

from google.appengine.ext import db
from google.appengine.api import memcache

DEBUG = True
SECRET = "*Ec]Y;spV(}FGu2-neZax~r@6NP9,j"
ROOT_KEY = db.Key.from_path('dummy_key', 'dummy_identifier')

WIKI_RE = '(?:[a-z0-9-]+/?)+'
USER_RE = '[a-zA-Z0-9_-]{3,20}'
PASS_RE = '.{3,20}'
EMAIL_RE = '[\S]+@[\S]+.[\S]+'

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
                               autoescape=True)

class User(db.Model):
    username = db.StringProperty(required=True)
    hashed_password = db.StringProperty(required=True)
    email = db.StringProperty(required=False)
    salt = db.StringProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)

class Edit(db.Model):
    wiki = db.StringProperty(required=False)
    content = db.TextProperty(required=False)
    author = db.StringProperty(required=True)
    version = db.IntegerProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)

class Wiki(db.Model):
    name = db.StringProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)

def get_errors(username, password, verify, email):
    errors = {'username_error': '', 'password_error': '', 'verify_error': '',
              'email_error': ''}
    if not re.compile('^' + USER_RE + '$').match(username):
        errors['username_error'] = "Invalid username."
    if db.GqlQuery("SELECT * FROM User WHERE username=:1", username).get():
        errors['username_error'] = "Username taken."
    if not re.compile('^' + PASS_RE +'$').match(password):
        errors['password_error'] = "Invalid password."
    if email and not re.compile('^' + EMAIL_RE +'$').match(email):
        errors['email_error'] = "Invalid email address."
    if not verify == password:
        errors['verify_error'] = "Passwords do not match."
    return errors

def get_index(update=False):
    key = 'index'
    result = memcache.get(key)
    if result is None or update:
        logging.error("DB UPDATE INDEX")
        result = db.GqlQuery("SELECT * FROM Wiki "
                             "WHERE ancestor IS :1 "
                             "ORDER BY name ASC ",
                             ROOT_KEY)
        result = (list(result), time.time())
        memcache.set(key, result)
    return result

def get_edits(wiki, update=False):
    key = 'edit: ' + wiki
    result = memcache.get(key)
    if result is None or update:
        logging.error("DB UPDATE EDITS")
        result = db.GqlQuery("SELECT * FROM Edit "
                             "WHERE ancestor IS :1 "
                             "AND wiki = :2 "
                             "ORDER BY created DESC ",
                             ROOT_KEY, wiki)
        result = (list(result), time.time())
        memcache.set(key, result)
    return result

def get_users(update=False):
    key = 'users'
    result = memcache.get(key)
    if result is None or update:
        logging.error("DB UPDATE USERS")
        result = db.GqlQuery("SELECT * FROM User "
                             "WHERE ancestor IS :1 "
                             "ORDER BY username ASC ",
                             ROOT_KEY)
        result = (list(result), time.time())
        memcache.set(key, result)
    return result

def get_user_edits(user, update=False):
    key = 'user: ' + user
    result = memcache.get(key)
    if result is None or update:
        logging.error("DB UPDATE USER EDITS")
        result = db.GqlQuery("SELECT * FROM Edit "
                             "WHERE ancestor IS :1 "
                             "AND author = :2 "
                             "ORDER BY created DESC ",
                             ROOT_KEY, user)
        result = (list(result), time.time())
        memcache.set(key, result)
    return result

def make_hash(s):
    return hmac.new(SECRET, s).hexdigest()

def make_secure(s):
    return '%s|%s' % (s, make_hash(s))

def is_secure(h):
    s = h.split('|')[0]
    return make_secure(s) == h

class Handler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def is_logged_in(self):
        username_cookie = self.request.cookies.get('username')
        return username_cookie and is_secure(username_cookie)

class MainPage(Handler):
    def get(self):
        self.render("main.html", logged=self.is_logged_in())

class SignupPage(Handler):
    def get(self, username_error="", password_error="",
                    verify_error="", email_error=""):
        self.render("signup.html", username_error=username_error,
                    password_error=password_error, verify_error=verify_error,
                    email_error=email_error, logged=self.is_logged_in())

    def post(self):
        errors = get_errors(self.request.get('username'),
                            self.request.get('password'),
                            self.request.get('verify'),
                            self.request.get('email'))
        
        if any(errors.values()):
            self.get(**errors)
        else:
            username = self.request.get('username')
            email = self.request.get('email')
            salt = ''.join(random.choice(string.letters) for i in range(5))
            hashed_password = make_hash(self.request.get('password') + salt)

            user = User(username=username, hashed_password=hashed_password,
                        email=email, salt=salt, parent=ROOT_KEY)
            user.put()
            get_users(True)

            secure_username = make_secure(username)
            username_cookie = 'username=%s; Path=/' % secure_username
            self.response.headers.add_header('Set-Cookie',
                                             str(username_cookie))
            self.redirect('/')

class LoginPage(Handler):
    def get(self, username="", password="", login_error=""):
        self.render("login.html", username=username, password=password,
                    login_error=login_error, logged=self.is_logged_in())

    def post(self):
        username = self.request.get("username")
        password = self.request.get("password")
        
        result = db.GqlQuery("SELECT * FROM User WHERE username=:1",
                             username).get()

        if result and result.hashed_password == \
           make_hash(password + result.salt):
            
            secure_username = make_secure(username)
            username_cookie = 'username=%s; Path=/' % secure_username
            self.response.headers.add_header('Set-Cookie',
                                             str(username_cookie))
            self.redirect('/')
        else:
            self.get(username, password, "Invalid login")

class LogoutPage(Handler):
    def get(self):
        self.response.headers.add_header('Set-Cookie', 'username=; Path=/')
        self.redirect('/')

class IndexPage(Handler):
    def get(self):
        index, _ = get_index()
        self.render("index.html", index=index, logged=self.is_logged_in())

class UserIndexPage(Handler):
    def get(self):
        users, _ = get_users()
        self.render("user-index.html", users=users,
                    logged=self.is_logged_in())

class FlushPage(Handler):
    def get(self):
        memcache.flush_all()
        self.redirect('/')

class EditPage(Handler):
    def get(self, wiki):
        version = self.request.get('v')

        if self.is_logged_in():
            edits, _ = get_edits(wiki)
            
            i = 0
            if version and version.isdigit() and int(version) < len(edits):
                i = -int(version)
            if edits:
                self.render("edit.html", wiki=edits[i].wiki,
                            content=edits[i].content,
                            logged=self.is_logged_in())
            else:
                self.render("edit.html", wiki=wiki, content="",
                            logged=self.is_logged_in)
        else:
            self.error(302)
            self.redirect("/login")

    def post(self, wiki):
        content = self.request.get('content')
        edits, _ = get_edits(wiki)
        
        if not edits or content != edits[0].content:
            if not edits:
                wiki_en = Wiki(name=wiki, parent=ROOT_KEY)
                wiki_en.put()
                get_index(True)

            username_cookie = self.request.cookies.get('username')
            author = username_cookie.split('|')[0]
            edit = Edit(wiki=wiki, content=content, author=author,
                            version=len(edits)+1, parent=ROOT_KEY)
            edit.put()
            get_edits(wiki, True)
            get_user_edits(author, True)

        self.redirect('/w/%s' % wiki)

class HistoryPage(Handler):
    def get(self, wiki):
        edits, _ = get_edits(wiki)
        self.render("history.html", wiki=wiki, edits=edits,
                    logged=self.is_logged_in())

class WikiPage(Handler):
    def get(self, wiki):
        edits, _ = get_edits(wiki)
        version = self.request.get('v')
        
        i = 0
        if version and version.isdigit() and int(version) <= len(edits):
            i = -int(version)
        if edits:
            self.render("wiki.html", edit=edits[i],
                        logged=self.is_logged_in())
        else:
            self.error(302)
            self.redirect('/edit/%s' % wiki)

class UserPage(Handler):
    def get(self, user):
        users = [u.username for u in get_users()[0]]
        if user in users:
            edits, _ = get_user_edits(user)
            self.render("user.html", user=user, edits=edits,
                        logged=self.is_logged_in())
        else:
            self.error(404)
            self.render("not-found.html", instance='user')
        
class NotFoundPage(Handler):
    def get(self):
        self.error(404)
        self.render("not-found.html", instance='page')

app = webapp2.WSGIApplication([('/', MainPage),
                               ('/signup', SignupPage),
                               ('/login', LoginPage),
                               ('/logout', LogoutPage),
                               ('/index', IndexPage),
                               ('/users', UserIndexPage),
                               ('/flush', FlushPage),
                               (r'/edit/(%s)' % WIKI_RE, EditPage),
                               (r'/history/(%s)' % WIKI_RE, HistoryPage),
                               (r'/w/(%s)' % WIKI_RE, WikiPage),
                               (r'/u/(%s)' % USER_RE, UserPage), # USER_RE!
                               (r'/.*', NotFoundPage)],
                              debug=DEBUG)        
