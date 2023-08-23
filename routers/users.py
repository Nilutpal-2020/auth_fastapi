from fastapi import Depends, HTTPException, status, APIRouter, Path
from pydantic import BaseModel, Field
from typing import Optional, Annotated
import models
from passlib.context import CryptContext
from sqlalchemy.orm import Session
from database import SessionLocal, engine
from fastapi.security import OAuth2PasswordRequestForm, OAuth2PasswordBearer
from datetime import datetime, timedelta
from jose import jwt, JWTError


SECRET_KEY = "141670983a2e47e88bb2ed33a8d40affc663969c6998aae1c178c16a67818dce"
ALGORITHM = "HS256"

class CreateUser(BaseModel):
    username: str
    email: str
    password: str = Field(min_length=6)
    role: str

class UserVerification(BaseModel):
    password: str
    new_password: str = Field(min_length=6)

bcrypt_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

models.Base.metadata.create_all(bind=engine)

oauth2_bearer = OAuth2PasswordBearer(tokenUrl="/users/login")

router = APIRouter(
    prefix="/users",
    tags=["users"],
    responses={401: {"user": "Not Authorized"}}
)

def get_db():
    try:
        db = SessionLocal()
        yield db
    finally:
        db.close()

def get_password_hash(password):
    return bcrypt_context.hash(password)

def verify_password(plain_password, hashed_password):
    return bcrypt_context.verify(plain_password, hashed_password)

def authenticate_user(email: str, password: str, db):
    user = db.query(models.Users)\
        .filter(models.Users.email == email).first()
    if not user:
        return False
    if not verify_password(password, user.password):
        return False
    return user

def create_access_token(email: str, 
                        id: int,
                        role: str,
                        expires_delta: Optional[timedelta] = None):
    encode = {"email": email, "id": id, "role": role}
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    encode.update({"exp": expire})
    return jwt.encode(encode, SECRET_KEY, algorithm=ALGORITHM)

async def get_current_user(token: str = Depends(oauth2_bearer)):
# async def get_current_user(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get('email')
        user_id: int = payload.get('id')
        user_role: str = payload.get('role')

        if email is None or user_id is None:
            raise token_exception()
        return {'email': email, 'id': user_id, 'role': user_role}
    except JWTError:
        raise token_exception()


def get_user_exception():
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    return credentials_exception

def token_exception():
    token_exception_response = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Incorrect email or password",
        headers={"WWW-Authenticate": "Bearer"},
    )
    return token_exception_response

db_dependency = Annotated[Session, Depends(get_db)]
user_dependency = Annotated[dict, Depends(get_current_user)]

# Users Routes

@router.get("/", status_code=status.HTTP_200_OK)
async def get_user_details(user: user_dependency,
                           db: db_dependency):
    if user is None:
        raise HTTPException(status_code=404, detail="User details not found!")
    user_model = db.query(models.Users).filter(models.Users.id == user.get('id')).first()
    if user_model is None:
        raise HTTPException(status_code=404, detail="User not found!")
    return {"username": user_model.username, "email": user_model.email, "role": user_model.role}

@router.post("/register", status_code=status.HTTP_201_CREATED)
async def create_new_user(create_user: CreateUser, db: db_dependency):

    existing_user = db.query(models.Users).filter(models.Users.email == create_user.email).first()

    if existing_user:
        raise HTTPException(status_code=400, detail="User Already Exists!")
    user_model = models.Users()
    user_model.email = create_user.email
    user_model.username = create_user.username
    
    hash_password = get_password_hash(create_user.password)

    user_model.password = hash_password
    user_model.role = create_user.role

    db.add(user_model)
    db.commit()

    user = authenticate_user(create_user.email, create_user.password, db)
    if not user:
        raise token_exception()

    token_expires = timedelta(minutes=30)
    token = create_access_token(user.email, user.id, user.role, expires_delta=token_expires)
    
    return {"access_token": token, "token_type": "Bearer"}

@router.post("/login")
# async def login_for_access_token(email: str,
#                                  password: str,
#                                  db: Session = Depends(get_db)):
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends(),
                                 db: Session = Depends(get_db)):
    user = authenticate_user(form_data.username, form_data.password, db)
    if not user:
        raise token_exception()
    token_expires = timedelta(minutes=10)
    token = create_access_token(user.email, user.id, user.role, expires_delta = token_expires)

    return {"access_token": token, "token_type": "Bearer"}

@router.put("/change_password", status_code=status.HTTP_202_ACCEPTED)
async def change_user_password(user: user_dependency,
                               db: db_dependency,
                               user_verify: UserVerification):
    if user is None:
        raise get_user_exception()
    
    user_model = db.query(models.Users).filter(models.Users.id == user.get('id')).first()

    if not bcrypt_context.verify(user_verify.password, user_model.password):
        raise HTTPException(status_code=401, detail="Error on password change")
    if user_model is None:
        raise HTTPException(status_code=404, detail="User not found!")
    
    user_model.password = bcrypt_context.hash(user_verify.new_password)

    db.add(user_model)
    db.commit()

@router.delete("/delete", status_code=status.HTTP_204_NO_CONTENT)
async def delete_user(user: user_dependency,
                      db: db_dependency):
    if user is None:
        raise get_user_exception()

    user_model = db.query(models.Users).filter(models.Users.id == user.get('id')).first()

    if user_model is None:
        raise HTTPException(status_code=404, detail="User Not Found!")
    db.query(models.Users).filter(models.Users.id == user.get('id')).delete()

    db.commit()