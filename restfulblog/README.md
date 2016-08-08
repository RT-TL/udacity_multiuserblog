# Udacity Multiuser Blog Project

This project represents basic web usage aspects: Creation of accounts, simple rights management, submitting forms 

## Table of contents

* [Quick start](#quick-start)
* [Requirements](#requirements)
* [Project Structure](#project-structure)
* [License](#license)


## Quick start

Clone repository:
```
git clone https://github.com/Roomtailors/udacity_multiuserblog.git
```

To begin you need to install all required modules, especially webapp2: Find it here: [https://pypi.python.org/pypi/webapp2]

## Requirements

1. Install Python 2.x
2. Clone git repository 
3. Modules for import os, re, random, hashlib, hmac, letters, webapp2, jinja2 [http://jinja.pocoo.org/docs/dev/]

## Project Structure

The blog is organized in a rest-like manner. Available endpoints are:

/posts/
/likes/
/comments/
/signup
/login
/logout

Resources can be modified through there add/edit/delete actions. URLs are build either by directly adressing resourdces (/posts/add/ or /posts/<id>/edit) or via their parent resource, for example:
 
```
/posts/<id#1>/like/<id#2>/delete    = removes a like with <id#2> from post with <id#1>
/posts/add                          = creates a new resource (add) in posts
/posts/<id>/edit                    = edits the resource post with <id>
```

To get the edit form, call the endpoint with GET method. To change it POST the data to the same endpoint.

## License

This project is licensed under the MIT License - see the [LICENSE.md](LICENSE.md) file for details
