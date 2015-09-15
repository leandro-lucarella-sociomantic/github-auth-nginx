# Reasoning
While authing against our Google Apps domain has worked pretty well up until now, we really needed a way to auth against out Github organization. Not everyone who is accessing some of our protected development content has an email account in our Google Apps domain. They do, however, have access to our github org.

Sadly it seems that apache and nginx modules for doing oauth are lacking.

I was hoping to avoid the whole lua approach (and `mod_authnz_external` was a no go from the start). However I realized that Brian Akins (@bakins) had done some fancy omnibus work that got me 90% of the way there.

From there it was a matter of patching up the omnibus repo to bring it to current versions as well as adding in a few additional components.


# Requirements

## OAuth Plugin dependency

- https://github.com/openresty/lua-resty-core
- https://github.com/brunoos/luasec 0.4.1+ (for ssl.https), 0.4.0 - untested.
- https://github.com/diegonehab/luasocket 3.0-rc1
- luajit 2.1 (2.0 - untested, because 2.1 is recomended by nginx-lua plugin and openresty)

## GitHub application
Go to your github account and add a new application under your github org. (https://github.com/organizations/ORGNAME/settings/applications/)

- Application Name is arbitrary.
- Homepage URL is the url to the site you're protecting
- Callback URL is `http[s]://mysite.com/_callback`

Make note of the ID and Secret you're given. You'll need those.

# Configuration

## OAuth Config

Before you push the nginx server you need to set the following nginx vars:

- ``$oauth_id`` Github client id
- ``$oauth_secret`` Github client secret
- ``$oauth_orgs_whitelist`` Github org to allow to access the app
- ``$oauth_scope`` Github scope access for oauth token

You set these values on your instance by as such.

    set $oauth_id             'MY_GITHUB_APP_ID';
    set $oauth_secret         'MY_GITHUB_APP_SECRET';
    set $oauth_orgs_whitelist '{"MY_GITHUB_ORG": true}';
    set $oauth_scope          'repo,user,user:email';


If you just want a simple test, it's pretty straightforward.

- install the package
- edit `/opt/nginx/etc/nginx.conf` with the attached conf file


Note that org names are case-sensitive.

# References
I got most of the inspiration (okay all of it) from a shitload of other people. Here are the big ones in no specific order

- https://github.com/bakins/omnibus-nginx
- http://seatgeek.com/blog/dev/oauth-support-for-nginx-with-lua
- https://github.com/NorthIsUp/nginx-oauth-on-dotcloud

I'm actually pretty excited about the openresty stuff but really the ability to extend nginx generically with lua is pretty awesome too.
