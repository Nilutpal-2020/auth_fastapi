from sqlalchemy import Boolean, Column, Integer, String
from sqlalchemy.orm import relationship
from database import Base

class Users(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String(30), unique=True, index=True)
    username = Column(String(40))
    password = Column(String(50))
    role = Column(String)
