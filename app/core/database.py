from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from app.config import settings
from urllib.parse import quote_plus, urlparse, urlunparse
import sys

def encode_database_url(url: str) -> str:
    try:
        if not url:
            return url
        if isinstance(url, bytes):
            url = url.decode('utf-8', errors='replace')
        
        parsed = urlparse(url)
        if parsed.password:
            password = parsed.password
            if isinstance(password, bytes):
                password = password.decode('utf-8', errors='replace')
            
            try:
                from urllib.parse import unquote
                password = unquote(password)
            except:
                pass
            
            try:
                password_bytes = password.encode('utf-8')
                password = password_bytes.decode('utf-8', errors='replace')
            except:
                password = str(password).encode('utf-8', errors='replace').decode('utf-8', errors='replace')
            
            encoded_password = quote_plus(password, safe='')
            username = parsed.username or ''
            if isinstance(username, bytes):
                username = username.decode('utf-8', errors='replace')
            hostname = parsed.hostname or ''
            if isinstance(hostname, bytes):
                hostname = hostname.decode('utf-8', errors='replace')
            netloc = f"{username}:{encoded_password}@{hostname}"
            if parsed.port:
                netloc += f":{parsed.port}"
            encoded_url = urlunparse((
                parsed.scheme,
                netloc,
                parsed.path or '',
                parsed.params or '',
                parsed.query or '',
                parsed.fragment or ''
            ))
            return encoded_url
        return url
    except Exception as e:
        return url

def create_database_engine():
    try:
        from dotenv import dotenv_values
        import os
        
        env_vars = dotenv_values(".env")
        postgres_password = env_vars.get("POSTGRES_PASSWORD") or os.getenv("POSTGRES_PASSWORD")
        
        if postgres_password:
            try:
                if isinstance(postgres_password, bytes):
                    postgres_password = postgres_password.decode('utf-8', errors='replace')
                postgres_password = str(postgres_password).encode('utf-8', errors='replace').decode('utf-8', errors='replace')
                encoded_password = quote_plus(postgres_password, safe='')
                db_url = f"postgresql://waf_user:{encoded_password}@postgres:5432/waf_db"
            except Exception as e:
                db_url_raw = settings.database_url
                if isinstance(db_url_raw, bytes):
                    db_url_raw = db_url_raw.decode('utf-8', errors='replace')
                db_url = encode_database_url(db_url_raw)
        else:
            db_url_raw = settings.database_url
            if isinstance(db_url_raw, bytes):
                db_url_raw = db_url_raw.decode('utf-8', errors='replace')
            db_url = encode_database_url(db_url_raw)
        
        return create_engine(
            db_url,
            pool_pre_ping=True,
            pool_size=10,
            max_overflow=20,
            connect_args={
                "connect_timeout": 10,
                "client_encoding": "utf8"
            },
            echo=False
        )
    except Exception as e:
        from sqlalchemy import create_engine as create_engine_fallback
        return create_engine_fallback("sqlite:///./fallback.db")

engine = create_database_engine()

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

