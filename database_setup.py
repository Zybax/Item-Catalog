from sqlalchemy import Column, ForeignKey, Integer, String, Numeric
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy import create_engine

Base = declarative_base()

class User(Base):
  __tablename__ = 'user'

  id = Column(Integer, primary_key=True)
  name = Column(String(80), nullable=False)
  email = Column(String(250), nullable=False)
  picture = Column(String(250))

class Category(Base):
  __tablename__ = 'category'

  id = Column(Integer, primary_key=True)
  name = Column(String(80), nullable=False)
  picture = Column(String(250))

  @property
  def serialize(self):
    return {
      'id' : self.id,
      'name' : self.name
    }

class Item(Base):
  __tablename__ = 'item'

  id = Column(Integer, primary_key=True)
  name = Column(String(80), nullable=False)
  description = Column(String(250))
  price= Column(Numeric(5,2), nullable=False)
  category_id = Column(Integer, ForeignKey('category.id'))
  user_id = Column(Integer, ForeignKey('user.id'))
  picture = Column(String(250))

  @property
  def serialize(self):
    return {
      'id' : self.id,
      'name' : self.name,
      'description' : self.description,
      'price': str(self.price)
    }

engine = create_engine('sqlite:///itemcatalog.db')

Base.metadata.create_all(engine)
