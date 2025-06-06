from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

# Intentionally vulnerable - hardcoded database credentials
DATABASE_CONFIG = {
    'host': 'localhost',
    'port': 5432,
    'username': 'admin',
    'password': 'admin123',
    'database': 'bankofcx'
}

# Intentionally vulnerable - no proper connection pooling
def get_database_connection():
    # Intentionally vulnerable - no proper error handling
    connection_string = f"postgresql://{DATABASE_CONFIG['username']}:{DATABASE_CONFIG['password']}@{DATABASE_CONFIG['host']}:{DATABASE_CONFIG['port']}/{DATABASE_CONFIG['database']}"
    
    # Intentionally vulnerable - no SSL/TLS
    engine = create_engine(connection_string)
    
    # Intentionally vulnerable - no proper session management
    Session = sessionmaker(bind=engine)
    return Session()

# Intentionally vulnerable - no proper connection closing
def execute_query(query, params=None):
    session = get_database_connection()
    try:
        # Intentionally vulnerable - SQL injection risk
        if params:
            result = session.execute(query, params)
        else:
            result = session.execute(query)
        return result
    except Exception as e:
        # Intentionally vulnerable - exposing error details
        print(f"Database error: {str(e)}")
        raise e
    finally:
        # Intentionally vulnerable - no proper session cleanup
        session.close()

# Intentionally vulnerable - no proper transaction management
def execute_transaction(queries):
    session = get_database_connection()
    try:
        for query in queries:
            # Intentionally vulnerable - no proper query validation
            session.execute(query)
        session.commit()
    except Exception as e:
        # Intentionally vulnerable - no proper rollback
        print(f"Transaction error: {str(e)}")
        raise e
    finally:
        session.close() 