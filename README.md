# Asymmetric Message Franking

This is a prototype of a third-party moderation system utilizing asymmetric message franking for Twitter direct messaging. We emphasize that this is only a prototype
and is therefore not optimized for the level of efficiency and security necessary
for full deployment.

## Pre-requisites
- Python3
- Twitter API keys
- Perspective API key
- [requests](http://docs.python-requests.org/en/master/user/install/)
- [Flask](http://flask.pocoo.org/)
- [Twitter](https://twitter.com/) account
- [Keybase](https://keybase.io/) account
- [Tweepy](https://tweepy.readthedocs.io/en/3.7.0/getting_started.html#)
- [Petlib](https://petlib.readthedocs.io/en/latest/)

__For installing Tweepy__: The library requires some modification to allow reading and sending direct messages via the Twitter API.

1. Update the library from [this](https://github.com/bakayim/tweepy) forked repository at the command line with:
```
pip install git+https://github.com/bakayim/tweepy@master#egg=tweepy
```
2. Locate where tweepy was installed. This can be done via command line with:
```
$ python3
>>> import tweepy
>>> tweepy.__file__
```
3. Change directories to where tweepy is installed. Add the two methods found [here](https://github.com/do-n-khanh/tweepy/commit/79772c976c64830149095f087c16c181912466ba#diff-ea5dd38a4efd9ff36c96e04ab0597cfb) to __api.py__
4. Add the three lines found [here](https://github.com/do-n-khanh/tweepy/commit/c978749edb944394bd412922d0eb30170e0598bf) to __binder.py__


__For installing Petlib__: The Petlib library works only with OpenSSL 1.0.x. If you have OpenSSL 1.1.x installed instead, then you will need to clone the library from [this](https://github.com/bogdan-kulynych/petlib) forked repository.

__To get API keys__: For Twitter, you can get your own API keys by applying to be
a Twitter developer [here](https://developer.twitter.com/en/apply-for-access.html) and creating your own application. Note that it may take a few hours for your developer account to be approved. For Perspective, you can get your own API keys
by requesting API access [here](https://www.perspectiveapi.com/#/). Note that it may take several weeks for your access to be approved. If you would like to test
the application, you can also email __jlen [AT] cs [DOT] cornell [DOT] edu__ for the keys.

## Installation
We currently only feature cloning the library directly:
```
git clone https://github.com/julialen/asymmetric-message-franking.git
```

## Usage
First change directories into the library.
To start the server for Linux and Mac (starting the server with other environments can be found [here](http://flask.pocoo.org/docs/1.0/tutorial/factory/)):
```
export FLASK_APP=amf
export FLASK_ENV=development
flask run
```

To re-initialize the database (database already initialized upon downloading):
```
flask init-db
```

Open another terminal for the client. Run the client with:
```
python3 messages.py
>>
```

First you must register your Twitter and Keybase accounts with the application.
Do this with:
```
>> register
Twitter username:
Keybase username:
```
Enter your usernames when prompted. A window should open asking you to authenticate
your Twitter account. Follow the instructions. A __messages.cfg__ file will be
created with your keys. Do not delete this file. Another file called __amf_pk.txt__ with your public key will also be created. Put this in the keybase directory as
prompted.

 Once you are registered, you can send and receive messages. To send a message:
 ```
 >> send -u [USER] -m [MESSAGE]
 ```
 where [USER] is the Twitter handle of the message receiver.

 To read a message:
 ```
 >> read -u [USER] -n [NUMBER]
 ```
where [USER] is the Twitter handle of the message sender and [NUMBER] is the
number of messages you want to view from them. This defaults to 1. Messages that
are not _franked_, or signed, correctly will not be displayed.

To report a message as abusive:
```
>> report -u [USER] -m [MESSAGE]
```
where [USER] is the abusive message sender and [MESSAGE] is the abusive message
they sent. If the message is deemed abusive, then the user will be added to the
blacklist and messages sent by the user will not be shown.

To update the blacklist:
```
>> blacklist
```
