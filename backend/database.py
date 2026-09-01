import os

from dotenv import load_dotenv
from pymongo import MongoClient

load_dotenv(dotenv_path=".env")

MONGODB_URI = os.getenv("MONGODB_URI")
MONGODB_DATABASE = os.getenv("MONGODB_DATABASE", "api_threat_detection")

if not MONGODB_URI:
    raise RuntimeError("MONGODB_URI is not configured")

client = MongoClient(MONGODB_URI)

database = client[MONGODB_DATABASE]

events_collection = database["events"]