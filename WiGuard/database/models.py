from sqlalchemy import create_engine, Column, Integer, String, Float, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
import datetime

Base = declarative_base()

class TrustedNetwork(Base):
    __tablename__ = 'trusted_networks'
    id = Column(Integer, primary_key=True)
    ssid = Column(String, unique=True)
    bssid = Column(String)
    vendor = Column(String)
    encryption = Column(String)
    signal_baseline = Column(Float)
    channel = Column(Integer)
    date_added = Column(DateTime, default=datetime.datetime.utcnow)
    last_seen = Column(DateTime)
