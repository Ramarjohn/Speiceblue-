import json
import re
import urllib
from functools import wraps

from bson import ObjectId
from flask import Flask, jsonify, request
from flask_pymongo import PyMongo
from flask_restful import Api, Resource
from passlib.hash import pbkdf2_sha256

from Authentication import encode_auth_token, decode_auth_token

regex = '^[a-z0-9]+[\._]?[a-z0-9]+[@]\w+[.]\w{2,3}$'
app = Flask(__name__)
api = Api(app)



app.config["MONGO_URI"] = "mongodb+srv://ram:" + urllib.parse.quote_plus(
    "123") + "@cluster0.mnbrb.mongodb.net/myFirstDatabase?retryWrites=true&w=majority"
mongodb_client = PyMongo(app)
db = mongodb_client.db
User = db.UserDetails
template_details = db.TemplateDetails


def token_required(f):
    @wraps(f)
    def decorator(*args, **kwargs):
        token = None
        if 'Authorization' in request.headers:
            token = request.headers['Authorization']
        if not token:
            app.logger.info("Valid token is missing")
            return jsonify({'message': 'a valid token is missing'}), 404
        data, statu_code = decode_auth_token(token.split()[1])
        if statu_code != 200:
            return jsonify({'message': 'Invalid user'})
        UserValidation = User.find_one({'_id': ObjectId(data)})
        if UserValidation:
            return f(data)

        else:
            return jsonify({'message': 'Invalid user'}), 404

    return decorator


@app.route("/register", methods=['POST'])
def register():
    data = request.get_json(force=True)

    try:
        if data['email'] == '' or data['first_name'] == '' or data['last_name'] == '' or data['password'] == '':
            return jsonify({"message": "All fields are mandatory"}), 500
        data['password'] = pbkdf2_sha256.hash(str(data['password']))
        if bool(re.search(regex, data['email'])) == False:
            return jsonify({'message': 'Invalid email'}), 404
        if User.find_one({'email': data['email']}):
            return jsonify({'message': 'The user is already registered. try new one!.'}), 404
        User.insert_one(data)
    except KeyError as keyerror:
        return jsonify({"message": "Enter the {}".format(str(keyerror))}), 500
    except Exception as m:
        return jsonify({"message": str(m)}), 500
    result = []
    for u in User.find({}):
        result.append(u)
    return jsonify({"message": "successfully registered."}), 200


@app.route("/login", methods=['POST'])
def login():
    data = request.get_json(force=True)
    try:
        users = User.find_one({'email': data['email']})
        if not users:
            return jsonify({'message': 'Invalid user'}), 404
        if pbkdf2_sha256.verify(str(data['password']), users['password']):
            authentication_data = encode_auth_token(users['_id'])
            return jsonify({"Message": "Succesfully Logged in.", "Token": authentication_data}), 200
        else:
            return jsonify({"message": 'Invalid user'}), 404
    except Exception as e:

        return jsonify({"message": str(e)}), 500


class Templates(Resource):
    method_decorators = [token_required]

    def get(self, user_id):
        template_id = request.args.get('template_id')
        if template_id== None:
            return jsonify({"message": "Need template id"})
        users = list(template_details.find({"$and": [{'user_id': ObjectId(user_id)}, {"_id": ObjectId(template_id)}]}))
        if len(users) == 0:
            return jsonify({"message": "Incorrect template id"})
        return json.loads(json.dumps(users, default=str)), 200

    def post(self, user_id):
        request_data = request.get_json(force=True)
        request_data['user_id'] = ObjectId(user_id)
        template_details.insert_one(request_data)
        template_data = list(template_details.find({'user_id': ObjectId(user_id)}))
        return json.loads(json.dumps(template_data, default=str)), 200

    def put(self, user_id):
        template_id = request.args.get('template_id')
        if template_id == None:
            return jsonify({"message": "Need template id"})
        request_data = request.get_json(force=True)

        users = list(template_details.find({"$and": [{'user_id': ObjectId(user_id)}, {"_id": ObjectId(template_id)}]}))
        if len(users) == 0:
            return jsonify({"message": "Incorrect template id"})
        template_details.update_one({"$and": [{'user_id': ObjectId(user_id)}, {"_id": ObjectId(template_id)}]},
                                    {'$set': request_data})
        template_data = list(template_details.find({'user_id': ObjectId(user_id)}))
        return json.loads(json.dumps(template_data, default=str)), 200

    def delete(self, user_id):
        template_id = request.args.get('template_id')
        if template_id == None:
            return jsonify({"message": "Need template id"})
        users = list(template_details.find({"$and": [{'user_id': ObjectId(user_id)}, {"_id": ObjectId(template_id)}]}))
        if len(users) == 0:
            return jsonify({"message": "Incorrect template id"})
        template_details.delete_one({"$and": [{'user_id': ObjectId(user_id)}, {"_id": ObjectId(template_id)}]})
        return json.loads(
            json.dumps({"message": "Successfully deleted this template {}".format(template_id)}, default=str)), 200


api.add_resource(Templates, '/templates')

if __name__ == "__main__":
    app.run(debug=True)
