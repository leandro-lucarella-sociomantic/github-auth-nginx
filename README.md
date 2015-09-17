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

```nginx
set $oauth_id             'MY_GITHUB_APP_ID';
set $oauth_secret         'MY_GITHUB_APP_SECRET';
set $oauth_orgs_whitelist '{"MY_GITHUB_ORG": true}';
set $oauth_scope          'repo,user,user:email';
```

If you just want a simple test, it's pretty straightforward.

- install the package
- edit `/opt/nginx/etc/nginx.conf` with the attached conf file


Note that org names are case-sensitive.

## OAuth exported variables

OAuth sets variable ``auth_user`` with user's login (if available, otherwise it is set to "unknown"). You can use this variables inside your application:

```nginx
location / {
    set $auth_user 'unknown';

    lua_need_request_body on;
    access_by_lua_file "/etc/nginx/access.lua";

    fastcgi_pass 127.0.0.1:9000;
    fastcgi_param AUTH_USER $auth_user;
    fastcgi_param REMOTE_USER $auth_user;
}
```

## Session Configuration Variables

You can set default configuration parameters directly from Nginx configuration. It's **IMPORTANT** to understand
that these are read only once (not on every request), for performance reasons. This is especially important if
you run multiple sites (with different configurations) on the same Nginx server. You can of course set the common
parameters on Nginx configuration even on that case.

Here is a list of `lua-resty-session` related Nginx configuration variables that you can use to control
`lua-resty-session`:

```nginx
set $session_name              session;
set $session_cookie_lifetime   3600;
```
