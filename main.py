from google.cloud import datastore
from flask import Flask, request, jsonify, _request_ctx_stack, redirect, url_for, render_template, session, make_response
import requests
from functools import wraps
import json
from six.moves.urllib.request import urlopen
from flask_cors import cross_origin
from jose import jwt
from os import environ as env
from werkzeug.exceptions import HTTPException
from dotenv import load_dotenv, find_dotenv
from authlib.integrations.flask_client import OAuth
from six.moves.urllib.parse import urlencode

app = Flask(__name__)
app.secret_key = 'SECRET_KEY'

client = datastore.Client()

BOATS = "boats"
LOADS = "loads"
OWNERS = "owners"

CLIENT_ID = 'jswPNCQfXGZVZv6GdeLBxyJIVoRzSTWz'
CLIENT_SECRET = 'PHr7jPlS5HH-asp3ThgLDRl-R44kWEKB6jtII1EZ-jmTOkWhCdW3mPBnNCRLtQpE'
DOMAIN = 'nelsona9-assignment7.us.auth0.com'
#APP_URL = 'http://localhost:8080'
APP_URL = 'https://nelsona9-portfolio.uk.r.appspot.com'
#CALLBACK_URL = 'http://localhost:8080/callback'
CALLBACK_URL = 'https://nelsona9-portfolio.uk.r.appspot.com/callback'

ALGORITHMS = ["RS256"]

oauth = OAuth(app)

auth0 = oauth.register(
    'auth0',
    client_id=CLIENT_ID,
    client_secret=CLIENT_SECRET,
    api_base_url="https://" + DOMAIN,
    access_token_url="https://" + DOMAIN + "/oauth/token",
    authorize_url="https://" + DOMAIN + "/authorize",
    client_kwargs={
        'scope': 'openid profile email',
    },
    server_metadata_url=f'https://{DOMAIN}/.well-known/openid-configuration'
)

# This code is adapted from https://auth0.com/docs/quickstart/backend/python/01-authorization?_ga=2.46956069.349333901.1589042886-466012638.1589042885#create-the-jwt-validation-decorator

class AuthError(Exception):
    def __init__(self, error, status_code):
        self.error = error
        self.status_code = status_code


@app.errorhandler(AuthError)
def handle_auth_error(ex):
    response = jsonify(ex.error)
    response.status_code = ex.status_code
    return response

# Verify the JWT in the request's Authorization header
def verify_jwt(request):
    if 'Authorization' in request.headers:
        auth_header = request.headers['Authorization'].split()
        token = auth_header[1]
    else:
        raise AuthError({"code": "no auth header",
                            "description":
                                "Authorization header is missing"}, 401)
    
    jsonurl = urlopen("https://" + DOMAIN + "/.well-known/jwks.json")
    jwks = json.loads(jsonurl.read())
    try:
        unverified_header = jwt.get_unverified_header(token)
    except jwt.JWTError:
        raise AuthError({"code": "invalid_header",
                        "description":
                            "Invalid header. "
                            "Use an RS256 signed JWT Access Token"}, 401)
    if unverified_header["alg"] == "HS256":
        raise AuthError({"code": "invalid_header",
                        "description":
                            "Invalid header. "
                            "Use an RS256 signed JWT Access Token"}, 401)
    rsa_key = {}
    for key in jwks["keys"]:
        if key["kid"] == unverified_header["kid"]:
            rsa_key = {
                "kty": key["kty"],
                "kid": key["kid"],
                "use": key["use"],
                "n": key["n"],
                "e": key["e"]
            }
    if rsa_key:
        try:
            payload = jwt.decode(
                token,
                rsa_key,
                algorithms=ALGORITHMS,
                audience=CLIENT_ID,
                issuer="https://"+ DOMAIN+"/"
            )
        except jwt.ExpiredSignatureError:
            raise AuthError({"code": "token_expired",
                            "description": "token is expired"}, 401)
        except jwt.JWTClaimsError:
            raise AuthError({"code": "invalid_claims",
                            "description":
                                "incorrect claims,"
                                " please check the audience and issuer"}, 401)
        except Exception:
            raise AuthError({"code": "invalid_header",
                            "description":
                                "Unable to parse authentication"
                                " token."}, 401)

        return payload
    else:
        raise AuthError({"code": "no_rsa_key",
                            "description":
                                "No RSA key in JWKS"}, 401)

def requires_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'profile' not in session:
            # Redirect to Login page here
            return redirect('/login')
        return f(*args, **kwargs)

    return decorated

@app.route('/')
def index():
    # return render_template('home.html')
    # return "Please navigate to /boats to use this API"
    return render_template('index.html')

# Decode the JWT supplied in the Authorization header
@app.route('/decode', methods=['GET'])
def decode_jwt():
    # return a 406 response code if the request content-type is not 'applicaiton/json'
    if not request.accept_mimetypes.accept_json:
        # return a 406 response code if the request accept-type is not 'applicaiton/json'
        err_msg = {"406 Not Acceptable": "The 'Accept' content-type cannot be handled by the server. Must include 'application/json'"}
        return (jsonify(err_msg), 406)

    payload = verify_jwt(request)
    # payload["jwt"] = request.headers.get('Authorization')[7:]
    return payload

# Generate a JWT from the Auth0 domain and return it
# Request: JSON body with 2 properties with "username" and "password"
#       of a user registered with this Auth0 domain
# Response: JSON with the JWT as the value of the property id_token
@app.route('/login', methods=['GET', 'POST'])
def login_user():
    # return a 406 response code if the request content-type is not 'applicaiton/json'
    if not request.accept_mimetypes.accept_json:
        # return a 406 response code if the request accept-type is not 'applicaiton/json'
        err_msg = {"406 Not Acceptable": "The 'Accept' content-type cannot be handled by the server. Must include 'application/json'"}
        return (jsonify(err_msg), 406)    
        
    content = request.get_json()
    username = content["username"]
    password = content["password"]
    body = {'grant_type':'password','username':username,
            'password':password,
            'client_id':CLIENT_ID,
            'client_secret':CLIENT_SECRET
           }
    headers = { 'content-type': 'application/json' }
    url = 'https://' + DOMAIN + '/oauth/token'
    r = requests.post(url, json=body, headers=headers)
    return r.text, 200, {'Content-Type':'application/json'}

# this function was adapted from the link provided in the assignment page (https://auth0.com/docs/quickstart/webapp/python)
@app.route('/callback')
def callback_handling():
    # Handles response from token endpoint
    auth0.authorize_access_token()
    resp = auth0.get('userinfo')
    userinfo = resp.json()
    # token = oauth.auth0.authorize_access_token()
    # session["user"] = token

    # Store the user information in flask session.
    session['jwt_payload'] = userinfo
    session['profile'] = {
        'user_id': userinfo['sub'],
        'name': userinfo['name'],
        'picture': userinfo['picture']
    }
    return redirect('/user_info')

# this function was adapted from the link provided in the assignment page (https://auth0.com/docs/quickstart/webapp/python)
@app.route('/logout')
def logout():
    # Clear session stored data
    session.clear()
    # Redirect user to logout endpoint
    params = {'returnTo': url_for('index', _external=True), 'client_id': CLIENT_ID}
    return redirect(auth0.api_base_url + '/v2/logout?' + urlencode(params))

# this function was adapted from the link provided in the assignment page (https://auth0.com/docs/quickstart/webapp/python)
@app.route('/user_info')
@requires_auth
def user_info():
    return render_template('user_info.html',
                           userinfo=session['profile'],
                           userinfo_pretty=json.dumps(session, indent=4))

@app.route('/users', methods=['GET'])
def get_users():
    # return a 406 response code if the request content-type is not 'applicaiton/json'
    if not request.accept_mimetypes.accept_json:
        # return a 406 response code if the request accept-type is not 'applicaiton/json'
        err_msg = {"406 Not Acceptable": "The 'Accept' content-type cannot be handled by the server. Must include 'application/json'"}
        return (jsonify(err_msg), 406)

    query = client.query(kind=OWNERS)
    results = list(query.fetch())

    owners_list = []
    for o in results:
        owners_list.append(o["user_id"])

    return (jsonify(owners_list), 200)

@app.route('/boats', methods=['POST','GET'])
def boats_get_post():
    try:
        # must have a valid JWT to proceed
        payload = verify_jwt(request)
        
        # return a 406 response code if the request content-type is not 'applicaiton/json'
        if not request.accept_mimetypes.accept_json:
            # return a 406 response code if the request accept-type is not 'applicaiton/json'
            err_msg = {"406 Not Acceptable": "The 'Accept' content-type cannot be handled by the server. Must include 'application/json'"}
            return (jsonify(err_msg), 406)
        
        if request.method == 'POST':
            content = request.get_json()

            # raise a 400 error if the three required attributes are not included in the request
            if "name" not in content or "type" not in content or "length" not in content:
                err_msg = {"400 Bad Request": "The request object is missing at least one of the required attributes"}
                return (jsonify(err_msg), 400)

            # return a 403 error if the name attribute is not unique
            if not is_unique_and_valid_boat(content["name"]):
                err_msg = {"403 Forbidden": "'name' is not unique or is invalid"}
                return (jsonify(err_msg), 403)

            # create a new boat entity
            new_boat = datastore.entity.Entity(key=client.key(BOATS))
            if "loads" not in content:
                loads_content = None
            else:
                loads_content = content["loads"]
            new_boat.update({"name": content["name"], "type": content["type"], "length": content["length"],
                "owner": payload["sub"], "loads": loads_content})
            client.put(new_boat)

            # add the "id" and "self" attributes to the boat entity that is displayed
            new_boat["id"] = new_boat.key.id
            new_boat["self"] = request.url + "/" + str(new_boat.key.id)

            return jsonify(new_boat), 201

        elif request.method == 'GET':
            # query and make a list of the boat entities
            query = client.query(kind=BOATS)
            # boats_list = list(query.fetch())

            owner_boats = []

            # adds the boat entity to the list of owner boats if the boat belongs to the owner associated with payload's JWT
            # for boat in boats_list:
            #     if boat["owner"] == payload["sub"]:
            #         boat["id"] = boat.key.id
            #         boat["self"] = request.url + "/" + str(boat.key.id)
            #         owner_boats.append(boat)

            q_limit = int(request.args.get('limit', '5'))
            q_offset = int(request.args.get('offset', '0'))
            l_iterator = query.fetch(limit=q_limit, offset=q_offset)
            pages = l_iterator.pages
            boats_list = list(next(pages))

            if l_iterator.next_page_token:
                next_offset = q_offset + q_limit
                next_url = request.base_url + "?limit=" + str(q_limit) + "&offset=" + str(next_offset)
            else:
                next_url = None

            count = 0
            for b in boats_list:
                if b["owner"] == payload["sub"]:
                    owner_boats.append(b)
                    b["id"] = b.key.id
                    b["self"] = request.url + "/" + str(b.key.id)
                    count += 1
                
            output = {"boat_count": count, "boats": owner_boats}

            if next_url:
                output["next"] = next_url
            return json.dumps(output)

            # return jsonify(owner_boats), 200
        
        else:
            # return a 405 error code if the request method is not POST or GET
            res = make_response('')
            res.headers.set('Content-Type', 'application/json')
            res.headers.set('Allow', 'POST, GET')
            res.status_code = 405
            return res
    
    except:
        # missing or invalid JWT 
        return ("", 401)

@app.route('/boats/<boat_id>', methods=['PATCH', 'PUT', 'DELETE', 'GET'])
def boats_crud(boat_id):
    try:
        # must have a valid JWT to proceed
        payload = verify_jwt(request)
        
        if request.method == 'PATCH':
            # return a 406 response code if the request content-type is not 'applicaiton/json'
            if not request.accept_mimetypes.accept_json:
                # return a 406 response code if the request accept-type is not 'applicaiton/json'
                err_msg = {"406 Not Acceptable": "The 'Accept' content-type cannot be handled by the server. Must include 'application/json'"}
                return (jsonify(err_msg), 406)

            try:
                # update the boat entity 
                boat_key = client.key(BOATS, int(boat_id))
                boat = client.get(key=boat_key)
                
                if payload["sub"] != boat["owner"]:
                    err_msg = {"404 Not Found": "No boat with this boat_id exists for this user"}
                    return (jsonify(err_msg), 404)

                content = request.get_json()
                count = 0
                for key in content:
                    if key in ["name", "type", "length"]:
                        # return a 403 error if the name attribute is not unique
                        if key == "name" and content["name"] != boat["name"] and not is_unique_and_valid_boat(content["name"]):
                            err_msg = {"403 Forbidden": "'name' is not unique or is invalid"}
                            return (jsonify(err_msg), 403)

                        boat.update({str(key): content[str(key)]})
                        count += 1
                if count > 0:
                    client.put(boat)

                # add the "id" and "self" attributes to the displayed boat
                boat["id"] = boat.key.id
                boat["self"] = request.url
            except:
                err_msg = {"404 Not Found": "No boat with this boat_id exists for this user"}
                return (jsonify(err_msg), 404)

            return jsonify(boat)

        elif request.method == 'PUT':
            # raise a 400 error if the three required attributes are not included in the request
            content = request.get_json()
            if "name" not in content or "type" not in content or "length" not in content:
                err_msg = {"400 Bad Request": "The request object is missing at least one of the required attributes"}
                return (jsonify(err_msg), 400)
            
            try:
                # update the boat entity
                boat_key = client.key(BOATS, int(boat_id))
                boat = client.get(key=boat_key)

                if payload["sub"] != boat["owner"]:
                    err_msg = {"404 Not Found": "No boat with this boat_id exists for this user"}
                    return (jsonify(err_msg), 404)

                for key in content:
                    if content[key] != boat[key]:
                        boat.update({key: content[key]})
                # boat.update({"name": content["name"], "type": content["type"], "length": content["length"], "loads": boat["loads"], "owner": boat["owner"], "id": boat["id"]})
                client.put(boat)
            except:
                err_msg = {"404 Not Found": "No boat with this boat_id exists for this user"}
                return (jsonify(err_msg), 404)

        elif request.method == 'DELETE':
            try:
                # store the information of the boat with the provided id
                boat_key = client.key(BOATS, int(boat_id))
                boat = client.get(key=boat_key)
                
                if payload["sub"] != boat["owner"]:
                    err_msg = {"404 Not Found": "No boat with this boat_id exists for this user"}
                    return (jsonify(err_msg), 404)
                    
                query = client.query(kind=LOADS)
                loads_list = list(query.fetch())

                # delete the boat entity
                if boat["owner"] == payload["sub"]:
                    for load in loads_list:
                        if load["carrier"] == {"id": boat.id, "self": APP_URL + "/boats/" + str(boat.id)}:
                            load["carrier"] = None
                            client.put(load)
                    client.delete(boat_key)
                    return ("", 204)
            except:
                # no boat with boat_id exists
                err_msg = {"404 Not Found": "No boat with this boat_id exists for this user"}
                return jsonify(err_msg), 404

            return ("", 204)

        elif request.method == 'GET':
            # return a 406 response code if the request content-type is not 'applicaiton/json'
            if not request.accept_mimetypes.accept_json:
                # return a 406 response code if the request accept-type is not 'applicaiton/json'
                err_msg = {"406 Not Acceptable": "The 'Accept' content-type cannot be handled by the server. Must include 'application/json'"}
                return (jsonify(err_msg), 406)

            try:
                # get the information for the boat with the provided id
                boat_key = client.key(BOATS, int(boat_id))
                boat = client.get(key=boat_key)

                if payload["sub"] != boat["owner"]:
                    err_msg = {"404 Not Found": "No boat with this boat_id exists for this user"}
                    return (jsonify(err_msg), 404)

                # add the "id" and "self" attributes to the displayed boat
                boat["id"] = boat.key.id
                boat["self"] = request.url

            except:
                err_msg = {"404 Not Found": "No boat with this boat_id exists for this user"}
                return (jsonify(err_msg), 404)

        else:
            # return a 405 error code if the request method is not PATCH, PUT, DELETE, or GET
            res = make_response('')
            res.headers.set('Content-Type', 'application/json')
            res.headers.set('Allow', 'PATCH, PUT, DELETE, GET')
            res.status_code = 405
            return res
    except:
        # missing or invalid JWT 
        return ("", 401)

@app.route('/loads', methods=['POST','GET'])
def loads_get_post():
    # return a 406 response code if the request content-type is not 'applicaiton/json'
    if not request.accept_mimetypes.accept_json:
        # return a 406 response code if the request accept-type is not 'applicaiton/json'
        err_msg = {"406 Not Acceptable": "The 'Accept' content-type cannot be handled by the server. Must include 'application/json'"}
        return (jsonify(err_msg), 406)

    if request.method == 'POST':
        # raise a 400 error if the required attributes are not included in the request
        content = request.get_json()
        if "volume" not in content or "item" not in content or "creation_date" not in content:
            err_msg = {"400 Bad Request": "The request object is missing at least one of the required attributes"}
            return (jsonify(err_msg), 400)

        # create and put the new_load entity
        new_load = datastore.entity.Entity(key=client.key(LOADS))
        new_load.update({"volume": content["volume"], "item": content["item"], "creation_date": content["creation_date"], "carrier": None})
        client.put(new_load)

        # add the "id" and "self" attributes to the new load entity that is displayed
        new_load["id"] = new_load.key.id
        new_load["self"] = request.url + "/" + str(new_load.key.id)

        return (jsonify(new_load), 201)

    elif request.method == 'GET':
        # query for and store the list of load entities
        query = client.query(kind=LOADS)
        loads_list = list(query.fetch())

        q_limit = int(request.args.get('limit', '5'))
        q_offset = int(request.args.get('offset', '0'))
        l_iterator = query.fetch(limit=q_limit, offset=q_offset)
        pages = l_iterator.pages
        loads_list = list(next(pages))

        if l_iterator.next_page_token:
            next_offset = q_offset + q_limit
            next_url = request.base_url + "?limit=" + str(q_limit) + "&offset=" + str(next_offset)
        else:
            next_url = None

        count = 0
        for load in loads_list:
            load["id"] = load.key.id
            load["self"] = request.url + "/" + str(load.key.id)
            count += 1

        output = {"load_count": count, "loads": loads_list}
        
        if next_url:
            output["next"] = next_url

        return json.dumps(output)

        # add the "id" and "self" attributes to the load entities that are displayed
        # for load in loads_list:
        #     load["id"] = load.key.id
        #     load["self"] = request.url + "/" + str(load.key.id)

        # return jsonify(loads_list)
    
    else:
        # return a 405 error code if the request method is not POST or GET
        res = make_response('')
        res.headers.set('Content-Type', 'application/json')
        res.headers.set('Allow', 'POST, GET')
        res.status_code = 405
        return res

@app.route('/loads/<load_id>', methods=['PATCH','PUT','DELETE','GET'])
def loads_crud(load_id):
    if request.method == 'PATCH':
        # return a 406 response code if the request content-type is not 'applicaiton/json'
        if not request.accept_mimetypes.accept_json:
            # return a 406 response code if the request accept-type is not 'applicaiton/json'
            err_msg = {"406 Not Acceptable": "The 'Accept' content-type cannot be handled by the server. Must include 'application/json'"}
            return (jsonify(err_msg), 406)

        try:
            # update and put the new information for the load with the provied id
            content = request.get_json()
            load_key = client.key(LOADS, int(load_id))
            load = client.get(key=load_key)
            for key in content:
                load.update({key: content[key]})
            client.put(load)

            # add the "id" and "self" attributes to the load entity that is displayed
            load["id"] = load.key.id
            load["self"] = request.url

        except:
            err_msg = {"404 Not Found": "No load with this load_id exists"}
            print(err_msg)
            return (jsonify(err_msg), 404)

        return jsonify(load)

    elif request.method == 'PUT':
        # raise a 400 error if the required attributes are not included in the request
        content = request.get_json()
        if "volume" not in content or "item" not in content or "creation_date" not in content:
            err_msg = {"Error": "The request object is missing at least one of the required attributes"}
            return (jsonify(err_msg), 400)

        try:
            load_key = client.key(LOADS, int(load_id))
            load = client.get(key=load_key)

            for key in content:
                if content[key] != load[key]:
                    load.update({key: content[key]})
            # load.update({"volume": content["volume"], "item": content["item"], "creation_date": content["creation_date"], "carrier": load["carrier"], "id": load["id"]})
            client.put(load)
        except:
            err_msg = {"404 Not Found": "No load with this load_id exists"}
            return (jsonify(err_msg), 404)

    elif request.method == 'DELETE':
        # get the load with the provided id
        load_key = client.key(LOADS, int(load_id))
        load = client.get(key=load_key)

        # query for and store the list of load entities
        query = client.query(kind=LOADS)
        loads_list = list(query.fetch())

        query = client.query(kind=BOATS)
        boats_list = list(query.fetch())

        # raise a 404 error if the load id does not exist in the loads entities
        if load not in loads_list:
            err_msg = {"404 Not Found": "No load with this load_id exists"}
            return (jsonify(err_msg), 404)

        # delete the load
        else:
            for boat in boats_list:
                for l in boat["loads"]:
                    if l == {"id": load.id, "self": APP_URL + "/loads/" + str(load.id)}:
                        boat["loads"].remove(l)
                        client.put(boat)
            client.delete(load_key)
            return ("", 204)

    elif request.method == 'GET':
        # return a 406 response code if the request content-type is not 'applicaiton/json'
        if not request.accept_mimetypes.accept_json:
            # return a 406 response code if the request accept-type is not 'applicaiton/json'
            err_msg = {"406 Not Acceptable": "The 'Accept' content-type cannot be handled by the server. Must include 'application/json'"}
            return (jsonify(err_msg), 406)

        try:
            # get the information for the load with the provided id
            load_key = client.key(LOADS, int(load_id))
            load = client.get(key=load_key)

            # add the "id" and "self" attributes to the load entity that is displayed
            load["id"] = load.key.id
            load["self"] = request.url
            
        except:
            err_msg = {"404 Not Found": "No load with this load_id exists"}
            return (jsonify(err_msg), 404)

        return jsonify(load)

    else:
        # return a 405 error code if the request method is not PATCH, PUT, DELETE, or GET
        res = make_response('')
        res.headers.set('Content-Type', 'application/json')
        res.headers.set('Allow', 'PATCH, PUT, DELETE, GET')
        res.status_code = 405
        return res

@app.route('/boats/<boat_id>/loads/<load_id>', methods=['PUT','DELETE'])
def boat_load_put_delete(boat_id, load_id):
    # get the information for the boat with the provided boat_id
    boat_key = client.key(BOATS, int(boat_id))
    boat = client.get(key=boat_key)

    # get the information for the load with the provided load_id
    load_key = client.key(LOADS, int(load_id))
    load = client.get(key=load_key)

    # query for and store the list of boat entities
    query_boats = client.query(kind=BOATS)
    boats_list = list(query_boats.fetch())

    # query for and store the list of load entities
    query_loads = client.query(kind=LOADS)
    loads_list = list(query_loads.fetch())

    if request.method == 'PUT':
        # raise a 404 error if the load or boat with the provided ids do not exist
        if load not in loads_list or boat not in boats_list:
            err_msg = {"404 Not Found": "The specified boat and/or load does not exist"}
            return (jsonify(err_msg), 404)

        # raise a 403 error if the load is already on a boat
        elif load["carrier"] is not None:
            err_msg = {"403 Forbidden": "The load is already on a boat"}
            return (jsonify(err_msg), 403)
        
        # set the load's carrier to the provided boat_id
        else:
            if "loads" in boat.keys() and boat["loads"] is not None:
                boat["loads"].append({"id": load.id, "self": APP_URL + "/loads/" + str(boat.id)})
            else:
                boat["loads"] = [{"id": load.id, "self": APP_URL + "/loads/" + str(load.id)}]
            # boat.update({"loads": boat["loads"].append(load)})
            # boat["self"] = APP_URL + "/boats/" + str(boat.id)
            # load["carrier"] = boat
            # boat["loads"].append(load)
            client.put(boat)

            load.update({"carrier": {"id": boat.id, "self": APP_URL + "/boats/" + str(boat.id)}})
            client.put(load)
            return ("", 204)      

    elif request.method == 'DELETE':
        # raise a 404 error if the load or boat with the provided ids do not exist or the boat is not in the provided load
        if load not in loads_list or boat not in boats_list or load["carrier"] != {"id": boat.id, "self": APP_URL + "/boats/" + str(boat.id)}:
            err_msg = {"404 Not Found": "No boat with this boat_id is loaded with a load with this load_id"}
            return (jsonify(err_msg), 404)
        
        # if the load and boat exist and the boat is in the load, set the load's carrier to None and put it
        elif load.id == int(load_id) and boat.id == int(boat_id) and load["carrier"] == {"id": boat.id, "self": APP_URL + "/boats/" + str(boat.id)}:
            load["carrier"] = None
            client.put(load)

            # for id, boat_load in enumerate(boat["loads"]):
            #     if load.id == boat_load.get("id"):
            #         boat["loads"].
            boat["loads"].remove({"id": load.id, "self": APP_URL + "/loads/" + str(load.id)})
            client.put(boat)
            return ("", 204)

    else:
        # return a 405 error code if the request method is not PUT or DELETE
        res = make_response('')
        res.headers.set('Content-Type', 'application/json')
        res.headers.set('Allow', 'PUT, DELETE')
        res.status_code = 405
        return res

# @app.route('/owners/<owner_id>/boats', methods=['GET'])
# def owner_boats_get(owner_id):
#     # return a 406 response code if the request content-type is not 'applicaiton/json'
#     if not request.accept_mimetypes.accept_json:
#         # return a 406 response code if the request accept-type is not 'applicaiton/json'
#         err_msg = {"406 Not Acceptable": "The 'Accept' content-type cannot be handled by the server. Must include 'application/json'"}
#         return (jsonify(err_msg), 406)
    
#     if request.method == 'GET':
#         # query and make a list of the boat entities
#         query = client.query(kind=BOATS)
#         boats_list = list(query.fetch())

#         owner_boats = []

#         # adds the boat entity to the list of owner boats if the boat belongs to the owner associated with payload's JWT
#         for e in boats_list:
#             if e["owner"] == owner_id:
#                 e["id"] = e.key.id
#                 owner_boats.append(e)

#         return jsonify(owner_boats), 200
    
#     else:
#         # return a 405 error code if the request method is not GET
#         res = make_response('')
#         res.headers.set('Content-Type', 'application/json')
#         res.headers.set('Allow', 'GET')
#         res.status_code = 405
#         return res

def is_unique_and_valid_boat(name):
    # query and list the boat entities
    query = client.query(kind=BOATS)
    results = list(query.fetch())

    # if the desired boat name is invalid, return False
    if len(name) < 1 or len(name) > 75 or type(name) is not str:
        return False

    # if the desired boat name is already taken, return False
    for boat in results:
        if name == boat["name"]:
            return False
    
    return True

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=8080, debug=True)

