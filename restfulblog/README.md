# Udacity Multiuser Blog Project

This project represents basic web usage aspects: Creation of accounts, simple rights management, submitting forms 

## Table of contents

* [Quick start](#quick-start)
* [Requirements](#requirements)
* [Project Structure](#project-structure)
* [Frontende Development](#frontend-development)
* [License](#license)


## Quick start

Clone repository:
```
git clone https://github.com/Roomtailors/udacity_portfolio.git
```

To begin install dependencies by running from root:

```
npm-install
```

## Requirements

1. Clone git repository with 
2. Node-js and npm for dependecy installation

All other dependencies are installed through nmp install

## Project Structure

    |-- .gitignore
    |-- Gruntfile.js
    |-- index.html
    |-- package.json
    |-- README.md
    |-- img-source // save your images here
    |-- less // edit these to create new style sheets
    |   |-- custom.less
    |   |-- layout.less
    |   |-- variables.less
    |-- resources // production only
        |-- css
        |-- img
        |-- js

## Frontend Development

To change any frontend aspects consider the following hints.

- Do not modify css files. Modify less-files instead and compile them.
- Store images in img-source and use grunt to create different resolutions and minimized versions.
- In order to create minified css and optimized responsive images run from root:
´´´
grunt
´´´
- consider using lazyload for responsive images

## License

This project is licensed under the MIT License - see the [LICENSE.md](LICENSE.md) file for details
