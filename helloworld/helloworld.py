import os

import webapp2

import jinja2
form = """
    <form method="post">
        <input name="q" type="text"></input>
        <input type="submit">
    </form>
    """

class MainPage(webapp2.RequestHandler):

    def get(self):
        #self.response.headers['Content­Type'] = 'text/plain'
        self.response.write(form)

class TestHandler(webapp2.RequestHandler):

    def post(self):
        #q = self.request.get()
        #self.response.out.write(q)
        self.response.headers['Content-Type'] = 'text/plain'
        self.response.out.write(self.request)

application = webapp2.WSGIApplication([
    ('/', MainPage),
    ('/testform', TestHandler)
], debug=True)