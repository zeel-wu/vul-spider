# -*- coding: utf-8 -*-
from sqlalchemy import create_engine

from sqlalchemy.orm import scoped_session, sessionmaker

from spider.config import DATABASE_URI
from spider.models import db_base


class DBManager(object):
    engine = None
    ss = None

    def init(self, database=None):
        if database:
            self.engine = database.get_engine()
        else:
            self.engine = create_engine(DATABASE_URI, pool_recycle=1200)
        sm = sessionmaker(autocommit=False, bind=self.engine)
        self.ss = scoped_session(sm)
        db_base.metadata.create_all(self.engine)
        db_base.query = self.ss.query_property()

    def bind(self, database):
        self.engine = database.get_engine()
        session = scoped_session(
            sessionmaker(autocommit=False, autoflush=False, bind=self.engine)
        )
        db_base.query = session.query_property()

    @property
    def session(self):
        return self.ss()

    def get_engine(self):
        return create_engine(DATABASE_URI, pool_recycle=1200)


db = DBManager()
db.init()
