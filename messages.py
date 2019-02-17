import tweepy
import webbrowser
import requests
import sys
from petlib.bn import Bn
from petlib.ec import EcGroup, EcPt
import binascii
import argparse
import time

sys.path.append(sys.path[0] + "/amf-algorithms/")
import dmf
from spok import setup

CONSUMER_TOKEN = ""
CONSUMER_SECRET = ""
DELIMITER = "$$$"
G = EcGroup(714)
ADDRESS = "http://127.0.0.1:5000/"

# Register the user by generating keys and authenticating the Twitter account
def register(twitter_user, kb_user, aux):
    generate_keys(aux, kb_user)
    twitter_auth()
    with open("messages.cfg", "a") as f:
        f.write("\n" + twitter_user + "\n" + kb_user)
    response = requests.post(ADDRESS + "register",
                  data = {"twitter": twitter_user, "keybase": kb_user})
    print(response.text)

# Authenticate the user's Twitter account
def twitter_auth():
    auth = tweepy.OAuthHandler(CONSUMER_TOKEN, CONSUMER_SECRET)

    try:
        redirect_url = auth.get_authorization_url()
    except tweepy.TweepError:
        print("Error! Failed to get request token.")

    webbrowser.open(redirect_url)
    verifier = input("Enter the PIN: ")

    try:
        auth.get_access_token(verifier)
    except tweepy.TweepError:
        print("Error! Failed to get access token.")

    with open("messages.cfg", "a") as f:
        f.write("\n" + auth.access_token + "\n" + auth.access_token_secret)

# Generate and store the user's public and private keys
def generate_keys(aux, kb_user):
    (g, o) = aux
    (pk, sk) = dmf.KeyGen(aux)

    with open("amf_pk.txt", "w+") as file:
        file.write(binascii.b2a_base64(pk.export()).decode("ascii"))

    with open("messages.cfg", "wb+") as file:
        file.write(g.export() + DELIMITER.encode('ascii'))
        file.write((o.hex() + DELIMITER).encode('ascii'))
        file.write((sk.hex() + DELIMITER).encode('ascii'))

    print("Put your amf_pk.txt file in the public Keybase directory " + \
        "/keybase/public/" + kb_user + "/amf/")

# Get the auxiliary group data from the AMF server
def get_aux():
    response = requests.get(ADDRESS + "get_aux")
    info = response.text.split(DELIMITER)
    g = EcPt.from_binary(binascii.a2b_base64(info[0].encode('ascii')), G)
    o = Bn.from_hex(info[1])
    return (g, o)

# Read a message
def read(sk_r, aux, pk_s, pk_j, count=1, user=None):
    with open("blacklist.txt", "r") as f:
        blacklist = f.read().splitlines()

    if user is not None and user in blacklist:
        print("User " + user + " has been blocked.")
        return

    # Setup Twitter API
    auth = tweepy.OAuthHandler(CONSUMER_TOKEN, CONSUMER_SECRET)
    with open("messages.cfg", "rb") as f:
        lines = f.read().splitlines()
    auth.set_access_token(lines[1], lines[2])
    api = tweepy.API(auth)

    if user is None:
        user_id = None
    else:
        user_id = api.get_user(user).id

    m = parse_direct_message(api.direct_messages(full_text=True, count=50)[0], str(user_id))
    if len(m) < count:
        print("There are fewer than " + str(count) + " messages available.")
    m = m[:count]

    # parse each DM as msg + tag
    messages = list(map(parse_message_tag, m))

    for message in messages:
        if type(message[1]) is not tuple:
            print("Message is not well-formed.")
        else:
            if user is None and message[0] in blacklist:
                print("User " + message[0] + " has been blocked.")
            else:
                sig = str_to_frank(message[1][1], G)
                if dmf.Verify(pk_s, sk_r, pk_j, message[1][0], sig, aux):
                    if user is None:
                        print(message[0] + ": " + message[1][0])
                    else:
                        print(user + ": " + message[1][0])
                else:
                    print("Message could not be verified.")

# Read the user's secrete key from messages.cfg
def read_sk():
    with open("messages.cfg", "rb") as file:
        data = file.read()
        info = data.split(DELIMITER.encode('ascii'))
        sk = Bn.from_hex(info[2].decode('ascii'))
    return sk

# Send a message
def send(user, msg, sk, aux, pk_r, pk_j):
    # Setup Twitter API
    auth = tweepy.OAuthHandler(CONSUMER_TOKEN, CONSUMER_SECRET)
    with open("messages.cfg", "rb") as f:
        lines = f.read().splitlines()
    auth.set_access_token(lines[1], lines[2])
    api = tweepy.API(auth)
    dest_id = api.get_user(user).id

    # run Frank on message
    sig = dmf.Frank(sk, pk_r, pk_j, msg, aux)

    # convert sig to string
    franked_message = msg + DELIMITER + frank_to_str(sig)

    # use twitter API to send message + tag
    event = {
      "event": {
        "type": "message_create",
        "message_create": {
          "target": {
            "recipient_id": dest_id
          },
          "message_data": {
            "text": franked_message
          }
        }
      }
    }
    api.send_direct_message_new(event)
    print("Message sent successfully.")

# Convert the frank signature into a string format
def frank_to_str(frank):
    if isinstance(frank, EcPt):
        return binascii.b2a_base64(frank.export()).decode("ascii") + DELIMITER
    if isinstance(frank, Bn):
        return frank.hex() + DELIMITER
    return "".join([frank_to_str(f) for f in frank])

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

# Report a message
def report(user, message, reporter, sk_r, aux, pk_s, pk_j, test):
    auth = tweepy.OAuthHandler(CONSUMER_TOKEN, CONSUMER_SECRET)
    with open("messages.cfg", "rb") as f:
        lines = f.read().splitlines()
    auth.set_access_token(lines[1], lines[2])
    api = tweepy.API(auth)
    user_id = api.get_user(user).id

    m = parse_direct_message(api.direct_messages(full_text=True, count=50)[0], str(user_id))

    # parse each DM as msg + tag
    messages = list(map(parse_message_tag, m))
    (g, o) = aux

    for m in messages:
        if type(m[1]) is not tuple:
            continue
        if m[1][0] == message:
            sig = str_to_frank(m[1][1], G)
            if dmf.Verify(pk_s, sk_r, pk_j, m[1][0], sig, aux):
                response = requests.post(ADDRESS + "report",
                              data = {"frank" : DELIMITER.join(m[1][1]),
                                      "sender" : user,
                                      "reporter" : reporter,
                                      "message" : message,
                                      "test": test})
                print(response.text)
            else:
                print("Error: Message was not reported due to bad verification.")
            return
    print("Error: Message not found.")

# Get the blacklist file from the AMF server
def get_blacklist():
    response = requests.get(ADDRESS + "blacklist.txt")
    with open("blacklist.txt", "w+") as file:
        file.write(response.text)

# Get the public key of the judge from the AMF server
def get_judge():
    response = requests.get(ADDRESS + "get_pk_j")
    return EcPt.from_binary(binascii.a2b_base64(response.text.encode('ascii')), G)

# Parse the message sent by Twitter's API
def parse_direct_message(direct_message, user_id):
    messages = []
    for event in vars(direct_message)['events']:
        if user_id is not None and user_id == event['message_create']['sender_id']:
            messages.append(
                (None, event['message_create']['message_data']['text']))
        elif user_id is None:
            messages.append(
                (event['message_create']['sender_id'],
                 event['message_create']['message_data']['text']))
    return messages

# Split the messages received over Twitter into tuples of text and signatures
def parse_message_tag(m):
    if DELIMITER not in m[1]:
        return m
    split = m[1].split(DELIMITER)
    return (m[0], (split[0], split[1:16]))

if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--test-gen", dest="test_gen", action="store_true")
    p.add_argument("--test", dest="test", action="store_true")
    a = p.parse_args()
    aux = get_aux()
    pk_j = get_judge()

    while True:
        try:
            i = input(">> ")
            if i == "register":
                twitter_user = input("Twitter username: ")
                kb_user = input("Keybase username: ")
                register(twitter_user, kb_user, aux)

            elif i == "blacklist":
                get_blacklist()

            elif i[0:4] == "read":
                parser = argparse.ArgumentParser()
                parser.add_argument("-u", dest="user", default=None, const=None)
                parser.add_argument("-n", dest="count", type=int, default=1,
                    nargs='?', const=1)
                args = parser.parse_args(i[4:].split())
                sk_r = read_sk()
                response = requests.post(ADDRESS + "get_username", data = {'twitter':args.user})
                kb_username = response.text
                r = requests.get("https://" + kb_username + ".keybase.pub/amf/amf_pk.txt")
                pk_s = EcPt.from_binary(binascii.a2b_base64(r.text.encode('ascii')), G)
                read(sk_r, aux, pk_s, pk_j, count=args.count, user=args.user)

            elif i[0:4] == "send":
                parser = argparse.ArgumentParser()
                parser.add_argument("-u", dest="user")
                parser.add_argument("-m", dest="message", nargs="*")
                args = parser.parse_args(i[4:].split())
                sk_s = read_sk()
                response = requests.post(ADDRESS + "get_username", data = {'twitter':args.user})
                kb_username = response.text
                r = requests.get("https://" + kb_username + ".keybase.pub/amf/amf_pk.txt")
                pk_r = EcPt.from_binary(binascii.a2b_base64(r.text.encode('ascii')), G)
                send(args.user, " ".join(args.message), sk_s, aux, pk_r, pk_j)

            elif i[0:6] == "report":
                parser = argparse.ArgumentParser()
                parser.add_argument("-u", dest="user")
                parser.add_argument("-m", dest="message", nargs="*")
                args = parser.parse_args(i[6:].split())
                with open("messages.cfg", "rb") as f:
                    twitter_user = f.read().splitlines()[3].decode("utf-8")
                sk_r = read_sk()
                response = requests.post(ADDRESS + "get_username", data = {'twitter':args.user})
                kb_username = response.text
                r = requests.get("https://" + kb_username + ".keybase.pub/amf/amf_pk.txt")
                pk_s = EcPt.from_binary(binascii.a2b_base64(r.text.encode('ascii')), G)
                report(args.user, " ".join(args.message), twitter_user, sk_r, aux, pk_s, pk_j, a.test)

        except (KeyboardInterrupt, EOFError):
            print("")
            sys.exit()
