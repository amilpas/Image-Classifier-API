from flask import Flask, jsonify, request
from flask_restful import Api, Resource
from pymongo import MongoClient
import bcrypt
# import numpy as np
# import tensorflow as tf
import requests
import subprocess
import json

# create an instance of the API
app = Flask(__name__)
api = Api(app)

# create a connection to MongoDB
client = MongoClient("mongodb://db:27017")

# create a db called `ImageRecognition`
db = client.ImageRecognition

# create a collection called `users`
users = db["users"]


def userExist(username):
    if users.find({"username": username}).count() == 0:
        return False
    else:
        return True


def verifyPassword(username, password):
    if not userExist(username):
        return False

    hashedPWD = users.find({"username": username})[0]["password"]

    if bcrypt.hashpw(password.encode("utf-8"), hashedPWD) == hashedPWD:
        return True
    else:
        return False


def generateReturnDictionary(status, message):
    retJson = {
        "status": status,
        "message": message
    }

    return retJson


def verifyCredentials(username, password):
    if not userExist(username):
        return generateReturnDictionary(301, "Invalid Username"), True

    correctPWD = verifyPassword(username, password)
    if not correctPWD:
        return generateReturnDictionary(302, "Invalid Password"), False
    return None, False


class Register(Resource):
    def post(self):
        postedData = request.get_json()
        username = postedData["username"]
        password = postedData["password"]
        # verify if the username is not already taken
        if userExist(username):
            retJson = {
                "status": 301,
                "message": "Invalid Username"
            }
            return jsonify(retJson)

        # hash the password
        hashedPWD = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())

        # insert the username and hashed password in the collection
        users.insert_one({
            "username": username,
            "password": hashedPWD,
            "tokens": 4
        })
        retJson = {
            "status": 200,
            "message": "You successfully signed up for this API"
        }
        return jsonify(retJson)


class Classify(Resource):
    def post(self):
        postedData = request.get_json()
        username = postedData["username"]
        password = postedData["password"]
        url = postedData["url"]

        retJson, error = verifyCredentials(username, password)

        if error:
            return jsonify(retJson)

        tokens = users.find({
            "username": username
        })[0]["tokens"]

        if tokens <= 0:
            return jsonify(generateReturnDictionary(303, "Not enough tokens!"))

        r = requests.get(url)
        retJson = {}
        with open("temp.jpg", "wb") as f:
            f.write(r.content)
            proc = subprocess.Popen('python classify_image.py --model_dir=. --image_file=./temp.jpg', stdout=subprocess.PIPE, stderr=subprocess.STDOUT, shell=True)
            ret = proc.communicate()[0]
            proc.wait()
            with open("text.txt", "r") as g:
                retJson = json.load(g)

        users.update({
                "username": username
            },
            {
                "$set": {"tokens": tokens - 1}
            }
        )
        return retJson


class Refill(Resource):
    def post(self):
        postedData = request.get_json()

        username = postedData["username"]
        password = postedData["adminPWD"]
        amount = postedData["amount"]

        if not userExist(username):
            return jsonify(generateReturnDictionary(301, "Invalid Username"))

        correctPWD = "abc@123"

        if not password == correctPWD:
            return jsonify(
                generateReturnDictionary(304, "Invalid Admin Password"))

        users.update({
                "username": username
            },
            {
                "$set": {"tokens": amount}
            }
        )

        return jsonify(generateReturnDictionary(200, "Refilled successfully!"))


api.add_resource(Register, '/register')
api.add_resource(Classify, '/classify')
api.add_resource(Refill, '/refill')

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
