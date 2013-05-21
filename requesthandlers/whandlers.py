#!/usr/bin/env python

import webapp2
import jinja2
import re
import os

import logging

from models import model
from security import crypt

import calendar
from datetime import datetime, timedelta

def utc_to_local(utc_dt):
    # get integer timestamp to avoid precision lost
    timestamp = calendar.timegm(utc_dt.timetuple())
    local_dt = datetime.fromtimestamp(timestamp)
    assert utc_dt.resolution >= timedelta(microseconds=1)
    return local_dt.replace(microsecond=utc_dt.microsecond)




template_dir = os.path.join(os.path.dirname(__file__), '../templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                               autoescape = True)

def format_datetime(value, format='medium'):
    if format == 'full':
        format="EEEE, d. MMMM y 'at' HH:mm"
    elif format == 'medium':
        format="EE dd.MM.y HH:mm"
    return babel.format_datetime(value, format)

jinja_env.filters['datetime'] = format_datetime

#form validation methods
USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
    return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
    return password and PASS_RE.match(password)

EMAIL_RE  = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
def valid_email(email):
    return not email or EMAIL_RE.match(email)




#Base Handler 
class Handler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))
    
    def render_str(self, template, **params):
        params['user'] = self.user
        t = jinja_env.get_template(template)
        return t.render(params)
    
    def set_secure_cookie(self, name, val):
        cookie_val = crypt.make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val))

    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and crypt.check_secure_val(cookie_val)

    def login(self, user):
        self.set_secure_cookie('user_id', str(user.key().id()))

    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and model.User.by_id(int(uid))

    
    

class Signup(Handler):
        def get(self):
            logging.info("SIGNUP--GET")
            next_url = self.request.headers.get('referer', '/')
            self.render("signup.html", next_url=next_url)

        def post(self):
            logging.info("SIGNUP--POST")
            have_error = False
            next_url = str(self.request.get('next_url'))
            if not next_url or next_url.startswith("/login"):
                next_url = '/'
                
            self.username = self.request.get('username')
            self.password = self.request.get('password')
            self.verify = self.request.get('verify')
            self.email = self.request.get('email')
            params = dict(username = self.username, email = self.email)

            if not valid_username(self.username):
                params['error_username'] = "That's not a valid username."
                have_error = True
            elif model.User.by_name(self.username):
                params['error_username'] = "That's name is already taken."
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
                self.render('signup.html', **params)
            else:
                u = model.User.register(self.username, self.password, self.email)
                u.put()
                self.login(u)
                if not next_url or next_url.startswith("/login"):
                    next_url = '/'
                self.redirect(next_url)
                
class Login(Handler):
        def get(self):
            logging.info("LOGIN--GET")
            next_url = self.request.headers.get('referer', '/')
            ipAddress = self.request.headers.get("Remote_Addr");
            l = model.Log(ip=ipAddress, note="opened login form")
            l.put()
            self.render("login.html", next_url=next_url)
           
        def post(self):
            logging.info("LOGIN--POST")
            
            username = self.request.get('username')
            password = self.request.get('password')
            ipAddress = self.request.headers.get("Remote_Addr");
            

            
            
            next_url = str(self.request.get("next_url"))
            if not next_url or next_url.startswith("/login"):
                next_url = '/'
                
            u = model.User.login(username, password)
            if u:
                self.login(u)
                l = model.Log(ip=ipAddress, note="login in -- " + username)
                l.put()
                self.redirect(next_url)
            else:
                msg = "Invalid Login"
                self.render('login.html', error = msg)
            
            
            
                
class Logout(Handler):
    def get(self):
        logging.info("LOGOUT")
        next_url = self.request.headers.get('referer', '/')
        self.response.headers.add_header('Set-Cookie', "user_id=; Path=/" )
        self.redirect(next_url)


                
class WikiPage(Handler):
    def get(self, path):
        logging.info("WIKIPAGE-- " + path)
        next_url = str(self.request.headers.get('referer', '/'))
        
        v = self.request.get('v')
        p = None
        if v:
            if v.isdigit():
                p  = model.Page.by_id(int(v), path)
                
                if not p:
                    self.notfound()
        else:
            p = model.Page.by_path(path).get()
            
        if p:
            self.render("wiki.html", page = p, path = path)
        else:
            if next_url.find('_edit/') < 0:
                self.redirect("/_edit" + path)
            else:
                self.redirect("/")
        
        
        
class EditPage(Handler):
    def get(self, path):
        logging.info("EDIT-PAGE--GET-- " + path)
        if not self.user:
            self.redirect('/login')
        
        v = self.request.get('v')
        p = None
        if v:
            if v.isdigit():
                p  = model.Page.by_id(int(v), path)
                
                if not p:
                    self.redirect("/_history" + path)
        else:
            p = model.Page.by_path(path).get()
            
        self.render('wikiedit.html', path = path, page = p)

            
            
             
    def post(self, path):
        logging.info("EDIT-PAGE--POST-- " + path)
        if not self.user:
            self.error(400)
            return
        
        content = self.request.get("content")
        old_page = model.Page.by_path(path).get()
        
        if not(old_page or content):
            content = ""
            
        if not old_page or old_page.content != content:
            p = model.Page(parent = model.Page.p_key(path),
                           pagepath = path,
                           content = content,
                           author=self.user)
            p.put()
            
        self.redirect(path)
        
class HistoryPage(Handler):
    def get(self, path):
        logging.info("GET HISTORY PAGE")
        pages = model.Page.by_path(path)
        pages = list(pages)
        if pages:
            self.render('history.html', pages=pages, path=path)
        else:
            self.redirect("/_edit" + path)
            
class ListPages(Handler):
    def get(self):
        logging.info("GET LIST OF ALL PAGES")
        pages = model.Page.all()
        pages = list(pages)
        fpages = {}
        for p in pages:
            np = model.Page.by_path(p.pagepath).get()
            
            fpages[str(p.pagepath)] = np
        fpages = fpages.values()
        fpages.sort(key=lambda x: x.pagepath)
        
            
            
        
        self.render("listpages.html", pages = fpages)

    

        
        
        
        
                
        
    
         
        
    

        
    

    

    

    


        



