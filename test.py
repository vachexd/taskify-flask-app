from datetime import datetime
import sqlite3
import os
from flask import Flask, render_template, request, url_for, redirect
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
# from sqlalchemy.sql import func
# con=sqlite3.Connection('newdb.db')
from random import randint
# cur=con.cursor()
import requests
from google.auth.transport.requests import Request
from vars import SCOPES
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
import json
from pprint import pprint
from vars import apppass
key = 'bb074f1bbb479904c0a31a0fe5fa4d0e'
date='2024-07-15'

parameters={
    'appid':key,
    'lat':41,
    'lon':44,
    'date':date
}
holidaykey='67ea3d73-db8f-42e3-8ccc-10fcc7e65504'
holidaparams={
    'key':holidaykey,
    'country':'GE',

}

holidaylink='https://holidayapi.com/v1/holidays'
url='https://api.openweathermap.org/data/3.0/onecall'





print(checkholidays('2025-01-01'))