from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

DATABASE_CONFIG = {
    'host': 'localhost',
    'port': 5432,
    'username': 'admin',
    'password': 'admin123',
    'database': 'bankofcx'
}

def get_database_connection():
    connection_string = f"postgresql://{DATABASE_CONFIG['username']}:{DATABASE_CONFIG['password']}@{DATABASE_CONFIG['host']}:{DATABASE_CONFIG['port']}/{DATABASE_CONFIG['database']}"
    
    engine = create_engine(connection_string)
    
    Session = sessionmaker(bind=engine)
    return Session()

def execute_query(query, params=None):
    session = get_database_connection()
    try:
        if params:
            result = session.execute(query, params)
        else:
            result = session.execute(query)
        return result
    except Exception as e:
        print(f"Database error: {str(e)}")
        raise e
    finally:
        session.close()

def execute_transaction(queries):
    session = get_database_connection()
    try:
        for query in queries:
            session.execute(query)
        session.commit()
    except Exception as e:
        print(f"Transaction error: {str(e)}")
        raise e
    finally:
        session.close() 