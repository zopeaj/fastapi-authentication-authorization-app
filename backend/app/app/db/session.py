from app.app.config.settings.settingConfiguration import settings
from sqlalchemy.orm import sessionmaker
from sqlalchemy import create_engine

engine = create_engine(settings.SQLALCHEMY_DATABASE_URL_SQLITE, echo=True)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
