"""
Shared database utilities for agent tools.
Provides database session management without circular imports.
"""
from sqlalchemy.orm import Session
from contextlib import contextmanager
from database import SessionLocal, Alert, Incident, Action, ChatMessage, AITimeEstimate


@contextmanager
def get_db_session():
    """Context manager for database sessions in tools"""
    db = SessionLocal()
    try:
        yield db
        db.commit()
    except Exception as e:
        db.rollback()
        raise e
    finally:
        db.close()


def get_db():
    """Generator for FastAPI dependency injection"""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
