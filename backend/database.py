import os
from pathlib import Path
from dotenv import load_dotenv
from pymongo import MongoClient



BASE_DIR = Path(__file__).resolve().parent
load_dotenv(dotenv_path=BASE_DIR / ".env")

MONGODB_URI = os.getenv("MONGODB_URI")
MONGODB_DATABASE = os.getenv("MONGODB_DATABASE", "api_threat_detection")

if not MONGODB_URI:
    raise RuntimeError("MONGODB_URI is not configured")

client = MongoClient(MONGODB_URI)

database = client[MONGODB_DATABASE]

events_collection = database["events"]