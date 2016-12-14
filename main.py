#!/usr/bin/env python
#
# Copyright 2007 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
import webapp2
import jinja2
import os
import hashlib
import hmac
import random
import string
from valid_credentials import valid_username, valid_password, valid_email
from google.appengine.ext import db

SECRET = 'du.uyX9fE~Tb6.pp&U3D-OsmYO,Gqi$^S34tzu9'

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
								autoescape = True)

def make_pw_secure_val(name,pw,salt = None):
	if not salt:
		salt = make_salt(5)
	hash_val = hashlib.sha256(name + pw + salt).hexdigest()
	return "%s|%s" % (salt,hash_val)

# returns boolean values
def check_pw_secure_val(name,pw,pw_secure_val):
	salt = pw_secure_val.split('|')[0]
	return pw_secure_val == make_pw_secure_val(name,pw,salt)

def make_salt(length):
	salt = ''.join(random.choice(string.letters) for x in xrange(length))
	return salt

def hash_str(val):
	return hmac.new(SECRET, val).hexdigest()

def make_secure_val(val):
	return "%s|%s" % (val,hash_str(val))

# returns the un-encrypted value
def check_secure_val(secure_val):
	val = secure_val.split('|')[0]
	if secure_val == make_secure_val(val):
		return val

def render_str(template, **params):
	t = jinja_env.get_template(template)
	return t.render(params)

class Post(db.Model):
	subject = db.StringProperty(required = True)
	content = db.TextProperty(required = True)
	created = db.DateTimeProperty(auto_now_add = True)
	user_id = db.StringProperty(required = True)

	def render(self):
		self._render_text = self.content.replace('\n','<br>')
		self.username = User.by_id(int(self.user_id)).name
		return render_str('post.html',post = self)

	@classmethod
	def by_id(cls,pid):
		return cls.get_by_id(pid)


class User(db.Model):
	name = db.StringProperty(required = True)
	pw_secure_val = db.StringProperty(required = True)
	email = db.StringProperty()

	@classmethod
	def by_id(cls,uid):
		return cls.get_by_id(uid)

	@classmethod
	def by_name(cls,name):
		return cls.all().filter('name = ',name).get()

	@classmethod
	def register(cls,name, pw, email):
		pw_secure_val = make_pw_secure_val(name,pw)
		return User(name = name,
					pw_secure_val = pw_secure_val,
					email = email)

	@classmethod
	def login(cls,name,pw):
		u = cls.by_name(name)
		if u and check_pw_secure_val(name,pw,u.pw_secure_val):
			return u

class Feedback(db.Model):
	user_id = db.StringProperty(required = True)
	content = db.TextProperty(required = True)
	created = db.DateTimeProperty(auto_now_add = True)

	def render(self):
		self._render_text = self.content.replace('\n','<br>')
		self.username = User.by_id(int(self.user_id)).name
		return render_str('feedback.html',feedback = self)


class PostByUser(db.Model):
	user_id = db.StringProperty(required = True)
	post_id = db.TextProperty(required = True)
	created = db.DateTimeProperty(auto_now_add = True)

	def render(self):
		post = Post.by_id(int(self.post_id))
		return post.render()

class Comment(db.Model):
	user_id = db.StringProperty(required = True)
	post_id = db.StringProperty(required = True)
	content = db.TextProperty(required = True)
	created = db.DateTimeProperty(auto_now_add = True)

	def render(self):
		self._render_text = self.content.replace('\n','<br>')
		self.username = User.by_id(int(self.user_id)).name
		return render_str('comment.html',comment = self)


class BaseHandler(webapp2.RequestHandler):
	def write(self, *args, **kwargs):
		self.response.out.write(*args, **kwargs)

	def render(self, template, **kwargs):
		self.write(render_str(template, **kwargs))

	def set_secure_cookie(self,name,val):
		cookie_val = make_secure_val(val)
		self.response.headers.add_header('Set-Cookie','%s=%s ; Path=/' % (name,cookie_val))

	# returns the un-encrypted value
	def read_secure_cookie(self,name):
		cookie_val = self.request.cookies.get(name)
		return cookie_val and check_secure_val(cookie_val)

	# sets the user_id cookie to point to a user
	def login(self,user):
		self.set_secure_cookie('user_id', str(user.key().id()))

	def logout(self):
		self.set_secure_cookie('user_id','')

	# runs before each request and stores the current logged in
	# user in self.user which is inherited to other functions
	def initialize(self, *args, **kwargs):
		webapp2.RequestHandler.initialize(self, *args, **kwargs)
		uid = self.read_secure_cookie('user_id')
		self.user = None
		if uid and User.by_id(int(uid)):
			self.user = User.by_id(int(uid))

class MainHandler(BaseHandler):
    def get(self):
    	if self.user:
    		self.redirect('/blog')
    	else:
        	self.render('index.html')

class Signup(BaseHandler):
	def get(self):
		self.render('signup-form.html')

	def post(self):
		has_error = False

		self.username = self.request.get('username')
		self.password = self.request.get('password')
		self.verify = self.request.get('verify')
		self.password = self.request.get('password')
		self.email = self.request.get('email')

		msg = 'Enter a valid %s'

		params = dict(username = self.username,
						email = self.email)

		if not valid_username(self.username):
			has_error = True
			params['error_username'] = msg % 'username'

		if valid_password(self.password):
			if self.password.lower() == 'password':
				has_error = True
				params['error_password'] = "Password can't be equal to 'password'"

			elif self.password.lower() == self.username.lower():
				has_error = True
				params['error_password'] = "password can't be equal to username"
		
			elif not self.verify == self.password:
				has_error = True
				params['error_verify'] = "passwords don't match"

		else:
			has_error = True
			params['error_password'] = msg % 'password'

		if self.email and (not valid_email(self.email)):
			has_error = True
			params['error_email'] = msg % 'email'

		if has_error:
			self.render('signup-form.html', **params)

		else:
			self.done()

class RegisterHandler(Signup):
	def done(self):
		u = User.by_name(self.username)
		if u:
			msg = 'user already exists'
			self.render('signup-form.html',error_username = msg)
		else:
			u = User.register(self.username,self.password,self.email)
			u.put()
			self.login(u)
			self.redirect('/welcome')

class LoginHandler(BaseHandler):
	def get(self):
		self.logout()
		self.render('login-form.html')

	def post(self):
		username = self.request.get('username')
		password = self.request.get('password')

		u = User.login(username,password)

		if u:
			self.login(u)
			self.redirect('/blog')
		else:
			msg = 'invalid login'
			self.render('login-form.html',error = msg)

class LogoutHandler(BaseHandler):
	def get(self):
		if self.user:
			self.logout()
			self.render('logout.html')
		else:
			self.write('No user logged in')

class WelcomeHandler(BaseHandler):
	def get(self):
		if self.user:
			self.render('welcome.html',username = self.user.name)

		else:
			self.redirect('/')


class BlogHandler(BaseHandler):
	def get(self):
		if self.user:
			posts = db.GqlQuery("select * from Post order by created desc")
			self.render('front.html',posts = posts)

		else:
			self.redirect('/')


class NewPost(BaseHandler):
	def get(self):
		if self.user:
			self.render('newpost.html')

		else:
			self.redirect('/')

	def post(self):
		subject = self.request.get('subject')
		content =  self.request.get('content')
		user_id = str(self.user.key().id())

		if subject and content:
			p = Post(subject = subject,content = content,user_id = user_id)
			p.put()
			post_id = str(p.key().id())
			element = PostByUser(user_id = user_id,post_id = post_id)
			element.put()
			self.redirect('/blog/%s' % post_id)
		else:
			error = "Enter both subject and content!!!"
			self.render('newpost.html',error = error)

class UserPage(BaseHandler):
	def get(self,user_id):
		if self.user:
			elements = db.GqlQuery("select * from PostByUser WHERE user_id='%s' order by created desc" % user_id)

			self.render('postbyuser.html',elements = elements, username = User.by_id(int(user_id)).name)

		else:
			self.redirect('/')


class PostPage(BaseHandler):
	def get(self,post_id):
		if self.user:
			key = db.Key.from_path('Post',int(post_id))
			post = db.get(key)

			if not post:
				self.error(404)
				return

			comments = db.GqlQuery("select * from Comment WHERE post_id='%s' order by created desc" % post_id)
			self.render('permalink.html', post = post, comments = comments)
		
		else:
			self.redirect('/')

	def post(self,post_id):
		user_id = str(self.user.key().id())
		content =  self.request.get('content')

		if content:
			c = Comment(user_id = user_id,post_id = post_id,content = content)
			c.put()
			self.redirect('/blog/%s' % post_id)
		else:
			self.redirect('/blog/%s' % post_id)

class FeedbackPost(BaseHandler):
	def get(self):
		if self.user:
			self.render('newfeedback.html')

		else:
			self.redirect('/')

	def post(self):
		content =  self.request.get('content')
		user_id = str(self.user.key().id())

		if content:
			f = Feedback(user_id = user_id,content = content)
			f.put()
			self.redirect('/exit')
		else:
			error = "Enter some content!!!"
			self.render('newfeedback.html',error = error)

class SeeFeedbackHandler(BaseHandler):
	def get(self):
		if self.user.name == 'asutosh':
			feedbacks = db.GqlQuery("select * from Feedback order by created desc")
			self.render('feedback-front.html',feedbacks = feedbacks)

		else:
			self.redirect('/')

app = webapp2.WSGIApplication([
    ('/', MainHandler),
    ('/login', LoginHandler),
    ('/blog', BlogHandler),
    ('/logout', FeedbackPost),
    ('/feedbacks',SeeFeedbackHandler),
    ('/exit',LogoutHandler),
    ('/signup', RegisterHandler),
    ('/blog/newpost', NewPost),
    ('/blog/([0-9]+)', PostPage),
    ('/user/([0-9]+)', UserPage),
    ('/welcome',WelcomeHandler)
], debug=True)
