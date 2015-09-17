require("resty.core")

-- handles all the authentication, don't touch me
-- skip favicon
local block = ""


if ngx.var.uri == "/favicon.ico" then return ngx.location.capture(ngx.var.uri) end
ngx.log(ngx.INFO, block, "################################################################################")

-- import requirements
local cjson = require("cjson.safe")
local https = require("ssl.https")
local url = require("socket.url")
local ltn12 = require("ltn12")

local github_uri = "https://github.com"
local github_api_uri = "https://api.github.com"

ngx.log(ngx.INFO, block, "Using github_uri="..github_uri)
ngx.log(ngx.INFO, block, "Using github_api_uri="..github_api_uri)

-- TODO: make this an oauth lib
-- note that org names are case-sensitive
local oauth = {
    app_id = ngx.var.oauth_id,
    app_secret = ngx.var.oauth_secret,
    orgs_whitelist = cjson.decode(ngx.var.oauth_orgs_whitelist),

    scope = ngx.var.oauth_scope,
    authorize_base_url = github_uri.."/login/oauth/authorize",
    access_token_url = github_uri.."/login/oauth/access_token",
    user_orgs_url = github_api_uri.."/user/orgs",
    user_url = github_api_uri.."/user",
}

oauth.authorize_url = oauth.authorize_base_url.."?client_id="..oauth.app_id.."&scope="..oauth.scope

function oauth.request(url_string, method)
    local result_table = {}

    local url_table = {
      url = url.build(url.parse(url_string, {port = 443})),
      method = method,
      sink = ltn12.sink.table(result_table),
      headers = {
        ["accept"] = "application/json"
      }
    }

    local body, code, headers, status_line = https.request(url_table)

    local json_body = ""
    for i, value in ipairs(result_table) do json_body = json_body .. value end

    ngx.log(ngx.INFO, block, "body::", json_body)

    return {body=cjson.decode(json_body), status=code, headers=headers}
end

function oauth.get(url_string)
    return oauth.request(url_string, "GET")
end

function oauth.get_access_token(code)

    local params = {
        access_token_url=oauth.access_token_url,
        client_id=oauth.app_id,
        client_secret=oauth.app_secret,
        code=code,
        redirect_uri=oauth.redirect_uri,
    }

    local url_string = oauth.access_token_url.."?"..ngx.encode_args(params)

    return oauth.get(url_string)
end

function oauth.get_user_info(access_token)
    local params = {access_token=access_token}
    local url_string = oauth.user_url.."?"..ngx.encode_args(params)
    local response = oauth.get(url_string)
    local body = response.body

    if body.error then
        return {status=401, message=body.error}
    end

    return {status=200, body={access_token=access_token, login=body.login}}
end

function oauth.verify_user(access_token)
    local params = {access_token=access_token}
    local url_string = oauth.user_orgs_url.."?"..ngx.encode_args(params)
    local response = oauth.get(url_string)
    local body = response.body

    if body.error then
        return {status=401, message=body.error}
    end

    for i, org in ipairs(body) do
        ngx.log(ngx.INFO, block, "testing: ", org.login)

        if oauth.orgs_whitelist[org.login] then
            ngx.log(ngx.INFO, block, org.login, " is in orgs_whitelist")
            return {status=200, body={access_token=access_token, org=org, access_level=9001}}
        end
    end

    return {status=403, message='not authorized for any orgs'}
end

--- end oauth lib

--- start session lib

local session = {
    encode_chars = {["+"] = "-", ["/"] = "_", ["="] = "."},
    decode_chars = {["-"] = "+", ["_"] = "/", ["."] = "="},

    name = ngx.var.session_name or "session",
    lifetime = tonumber(ngx.var.session_cookie_lifetime) or 3600,
    data = {
        access_token = nil,
        authorized = nil,
        auth_user = nil,
    },
}

function session:start()
    local data = ngx.var["cookie_" .. self.name]
    if data then
        data = ngx.decode_base64((data:gsub("[-_.]", self.decode_chars)))
        if data then
            data = cjson.decode(data)
            self.data = data or {}
        end
    end
end

function session:save()
    local data = cjson.encode(self.data)
    data = (ngx.encode_base64(data):gsub("[+/=]", self.encode_chars))
    local cookie = { self.name, "=", data, "; path=/; Max-Age=", self.lifetime }
    ngx.header["Set-Cookie"] = table.concat(cookie)
end

session:start()

--- end session lib


local args = ngx.req.get_uri_args()

-- extract previous token from cookie if it is there
local access_token = session.data.access_token or nil
local authorized = session.data.authorized or nil

if access_token == "" then access_token = nil end
if authorized ~= "true" then authorized = nil end

if access_token or authorized then session:save() end

-- We have nothing, do it all
if authorized ~= "true" or not access_token then
    block = "[A]"
    ngx.log(ngx.INFO, block, 'authorized=', authorized)
    ngx.log(ngx.INFO, block, 'access_token=', access_token)

    -- first lets check for a code where we retrieve
    -- credentials from the api
    if not access_token or args.code then
        if args.code then
            response = oauth.get_access_token(args.code)

            -- kill all invalid responses immediately
            if response.status ~= 200 or response.body.error then
                ngx.status = response.status
                ngx.header["Content-Type"] = "application/json"
                response.body.auth_wall = "something went wrong with the OAuth process"
                ngx.say(cjson.encode(response.body))
                ngx.exit(ngx.HTTP_OK)
            end

            -- decode the token
            access_token = response.body.access_token
        end

        -- both the cookie and proxy_pass token retrieval failed
        if not access_token then
            local redirect_back = session.data.redirect_back or ngx.var.uri
            redirect_back = (string.match(redirect_back, "/_callback%??.*")) and "/" or redirect_back
            ngx.log(ngx.INFO, block, "redirect_back1=", redirect_back)

            if redirect_back then session.data.redirect_back = redirect_back end

            -- Redirect to the /oauth endpoint, request access to ALL scopes
            session:save()
            return ngx.redirect(oauth.authorize_url)
        end
    end
end


if authorized ~= "true" then
    block = "[B]"
    ngx.log(ngx.INFO, block, 'authorized=', authorized)
    ngx.log(ngx.INFO, block, 'access_token=', access_token)
    -- check is we have capability to get user login
    local user_info = oauth.get_user_info(access_token)
    if user_info.status ~= 200 then
        session.data.login = "unknown"
    else
        session.data.login = user_info.body.login
    end

    -- ensure we have a user with the proper access app-level
    local verify_user_response = oauth.verify_user(access_token)
    if verify_user_response.status ~= 200 then
        -- delete their bad token
        session.data.access_token = nil

        -- Redirect 403 forbidden back to the oauth endpoint, as their stored token was somehow bad
        if verify_user_response.status == 403 then
            session:save()
            return ngx.redirect(oauth.authorize_url)
        end

        -- Disallow access
        ngx.status = verify_user_response.status
        ngx.say('{"status": 503, "message": "Error accessing oauth.api for credentials"}')

        session:save()
        return ngx.exit(ngx.HTTP_OK)
    end

    -- Ensure we have the minimum for access_level to this resource
    if verify_user_response.body.access_level < 255 then
        -- Expire their stored token
        session.data.access_token = nil
        session.data.authorized = nil

        -- Disallow access
        ngx.log(ngx.ERR, "Unauthorized access: ", token)
        ngx.status = ngx.HTTP_UNAUTHORIZED
        ngx.say('{"status": 403, "message": "USER_ID "'..access_token..'" has no access to this resource"}')

        session:save()
        return ngx.exit(ngx.HTTP_OK)
    end

    -- Store the access_token within a cookie
    session.data.access_token = access_token
    session.data.authorized = "true"
    session:save()
end

-- should be authorized by now

-- Support redirection back to your request if necessary
local redirect_back = session.data.redirect_back
ngx.log(ngx.INFO, block, "redirect_back2=", redirect_back)

if redirect_back then
    ngx.log(ngx.INFO, block, "redirect_back3=", redirect_back)
    session.data.redirect_back = nil
    session:save()
    return ngx.redirect(redirect_back)
end
ngx.var.auth_user = session.data.login or "unknown"
ngx.log(ngx.INFO, block, "--------------------------------------------------------------------------------")

-- Set some headers for use within the protected endpoint
-- ngx.req.set_header("X-USER-ACCESS-LEVEL", json.access_level)
-- ngx.req.set_header("X-USER-EMAIL", json.email)
