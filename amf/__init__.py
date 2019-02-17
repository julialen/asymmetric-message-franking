import os
import functools
import json
import sys
from petlib.bn import Bn
from petlib.ec import EcGroup, EcPt
import binascii
import requests
import time
from flask import Flask
from flask import (
    g, redirect, render_template, request, session, url_for
)

from amf.db import get_db

sys.path.append(sys.path[0] + "/amf-algorithms/")
import dmf
from spok import setup

PERSPECTIVE_KEY = ""
DELIMITER = "$$$"
TOXICITY_THRESHOLD = 0.8
G = EcGroup(714)

# Get the toxicity rating of the message from the Perspective API
def call_perspective_api(text, attributes, key):
    backoff_counter = 1
    while True:
      path = 'https://commentanalyzer.googleapis.com/v1alpha1/comments:analyze?key=%s' % key
      request = {
          'comment' : {'text' : text},
          'requestedAttributes' : { c : {} for c in attributes},
          'doNotStore' : True,
      }
      response = requests.post(path, json=request)
      prob = {}
      if response.status_code == 429:
         time.sleep(10 * backoff_counter)
         backoff_counter += 1
      else:
        break
    if response.status_code == 200:
      data = json.loads(response.text)
      scores_simplified = {}
      attribute_scores = data['attributeScores']
      for attr, data in attribute_scores.items():
          prob[attr] = data['summaryScore']['value']
      return prob
    else:
      print("Status code: {}.".format(response.status_code))
      for attr in attributes:
        prob[attr] = None
      return prob

# Convert the string back into a frank signature
def str_to_frank(l, G):
    elem1 = EcPt.from_binary(binascii.a2b_base64(l[0].encode('ascii')), G)
    elem2 = EcPt.from_binary(binascii.a2b_base64(l[1].encode('ascii')), G)
    elem3 = EcPt.from_binary(binascii.a2b_base64(l[2].encode('ascii')), G)
    elem4 = EcPt.from_binary(binascii.a2b_base64(l[3].encode('ascii')), G)
    elem5 = EcPt.from_binary(binascii.a2b_base64(l[4].encode('ascii')), G)

    elem6 = Bn.from_hex(l[5])
    elem7 = Bn.from_hex(l[6])
    elem8 = Bn.from_hex(l[7])
    elem9 = Bn.from_hex(l[8])
    elem10 = Bn.from_hex(l[9])
    elem11 = Bn.from_hex(l[10])

    elem12 = EcPt.from_binary(binascii.a2b_base64(l[11].encode('ascii')), G)
    elem13 = EcPt.from_binary(binascii.a2b_base64(l[12].encode('ascii')), G)
    elem14 = EcPt.from_binary(binascii.a2b_base64(l[13].encode('ascii')), G)
    elem15 = EcPt.from_binary(binascii.a2b_base64(l[14].encode('ascii')), G)

    return ((((elem1, elem2), ((elem3, elem4), elem5)), ((elem6, elem7, elem8), \
        (elem9, elem10, elem11))), elem12, elem13, elem14, elem15)

def create_app(test_config=None):
    # create and configure the app
    app = Flask(__name__, instance_relative_config=True)
    app.config.from_mapping(
        SECRET_KEY='dev',
        DATABASE=os.path.join(app.instance_path, 'amf.sqlite'),
    )

    if test_config is None:
        # load the instance config, if it exists, when not testing
        app.config.from_pyfile('config.py', silent=True)
    else:
        # load the test config if passed in
        app.config.from_mapping(test_config)

    # ensure the instance folder exists
    try:
        os.makedirs(app.instance_path)
    except OSError:
        pass

    # create the judge keys if they have not been created yet
    with app.app_context():
        db = get_db()
        row = db.execute('SELECT * FROM judge_keys').fetchone()
        if row is None:
            _, g, o = setup()
            aux = (g, o)
            (pk_j, sk_j) = dmf.KeyGen(aux)
            db.execute(
                'INSERT INTO judge_keys VALUES (?, ?, ?, ?)',
                (g.export(), o.hex().encode('ascii'), pk_j.export(), sk_j.hex().encode('ascii'))
            )
            db.commit()

    # GET request for the blacklisted users
    @app.route('/blacklist.txt', methods=('GET', 'POST'))
    def blacklist():
        if request.method == 'GET':
            db = get_db()
            rows = db.execute('SELECT * FROM blacklist').fetchall()
            names = list(map(lambda r : r['username'], rows))
            return "\n".join(names)

    # GET request for the auxiliary group data
    @app.route('/get_aux', methods=('GET', 'POST'))
    def get_aux():
        if request.method == 'GET':
            db = get_db()
            g = db.execute('SELECT g FROM judge_keys').fetchone()['g']
            o = db.execute('SELECT o FROM judge_keys').fetchone()['o']
            return binascii.b2a_base64(g).decode("ascii") + DELIMITER + \
                o.decode("ascii")

    # GET request for the judge's public keys
    @app.route('/get_pk_j', methods=('GET', 'POST'))
    def get_pk_j():
        if request.method == 'GET':
            db = get_db()
            pk_j = db.execute('SELECT pk_j FROM judge_keys').fetchone()['pk_j']
            return binascii.b2a_base64(pk_j).decode("ascii")

    # POST request to store the user's twitter and keybase usernames
    @app.route('/register', methods=('GET', 'POST'))
    def register():
        if request.method == 'POST':
            twitter = request.form['twitter']
            keybase = request.form['keybase']
            db = get_db()
            error = None

            if not twitter:
                error = 'Twitter username is required.'
            elif not keybase:
                error = 'Keybase username is required.'
            elif db.execute(
                'SELECT keybase FROM user WHERE twitter = ?', (twitter,)
            ).fetchone() is not None:
                error = 'User {} is already registered.'.format(username)

            if error is None:
                db.execute(
                    'INSERT INTO user (twitter, keybase) VALUES (?, ?)',
                    (twitter, keybase)
                )
                db.commit()
                return "Successfully added user."

            return error

    # POST request to get the keybase username associated to a twitter username
    @app.route('/get_username', methods=('GET', 'POST'))
    def get_username():
        if request.method == 'POST':
            twitter = request.form['twitter']
            db = get_db()
            error = None
            kb = db.execute(
                'SELECT keybase FROM user WHERE twitter = ?', (twitter,)
            ).fetchone()

            if kb is None:
                return "Incorrect username."
            return kb['keybase']

    # request to handle abuse reports
    @app.route('/report', methods=('GET', 'POST'))
    def report():
        frank = request.form['frank'].split(DELIMITER)
        sender = request.form['sender']
        reporter = request.form['reporter']
        msg = request.form['message']
        test = request.form['test']
        db = get_db()

        sig = str_to_frank(frank, G)

        if test == "True":
            with open("test.txt", "rb") as file:
                data = file.read()
                info = data.split(DELIMITER.encode('ascii'))
                pk_s = EcPt.from_binary(info[0], G)
                pk_r = EcPt.from_binary(info[2], G)

        else:
            sender_kb = db.execute(
                'SELECT keybase FROM user WHERE twitter = ?', (sender,)
            ).fetchone()['keybase']
            reporter_kb = db.execute(
                'SELECT keybase FROM user WHERE twitter = ?', (reporter,)
            ).fetchone()['keybase']

            r = requests.get("https://" + sender_kb + ".keybase.pub/amf/amf_pk.txt")
            pk_s = EcPt.from_binary(binascii.a2b_base64(r.text.encode('ascii')), G)

            r = requests.get("https://" + reporter_kb + ".keybase.pub/amf/amf_pk.txt")
            pk_r = EcPt.from_binary(binascii.a2b_base64(r.text.encode('ascii')), G)

        db = get_db()
        g_db = db.execute('SELECT g FROM judge_keys').fetchone()['g']
        o_db = db.execute('SELECT o FROM judge_keys').fetchone()['o']
        sk_j_db = db.execute('SELECT sk_j FROM judge_keys').fetchone()['sk_j']
        g = EcPt.from_binary(g_db, G)
        o = Bn.from_hex(o_db.decode('ascii'))
        sk_j = Bn.from_hex(sk_j_db.decode('ascii'))
        aux = (g, o)

        if not dmf.Judge(pk_s, pk_r, sk_j, msg, sig, aux):
            return "Message could not be authenticated by judge."
        else:
            prob = call_perspective_api(msg, ["TOXICITY"], PERSPECTIVE_KEY)
            if prob["TOXICITY"] > TOXICITY_THRESHOLD:
                db.execute('INSERT INTO blacklist VALUES (?)', (sender,))
                db.commit()
                return sender + " has been added to the blacklist."
            else:
                return "Message not judged to be abusive."

    from . import db
    db.init_app(app)

    return app
