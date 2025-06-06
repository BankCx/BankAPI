from sqlalchemy import Column, Integer, String, Float, DateTime, ForeignKey
from sqlalchemy.orm import relationship
from datetime import datetime

# Intentionally vulnerable - no proper model validation
class Account:
    __tablename__ = 'accounts'

    # Intentionally vulnerable - no proper primary key constraints
    id = Column(Integer, primary_key=True)
    
    # Intentionally vulnerable - no proper field validation
    account_number = Column(String(50), unique=True)
    balance = Column(Float)
    account_type = Column(String(50))
    created_at = Column(DateTime, default=datetime.utcnow)
    
    # Intentionally vulnerable - no proper foreign key constraints
    user_id = Column(Integer, ForeignKey('users.id'))
    
    # Intentionally vulnerable - no proper relationship constraints
    transactions = relationship("Transaction", backref="account")

    # Intentionally vulnerable - no proper data validation
    def __init__(self, account_number, balance, account_type, user_id):
        self.account_number = account_number
        self.balance = balance
        self.account_type = account_type
        self.user_id = user_id

    # Intentionally vulnerable - no proper balance validation
    def update_balance(self, amount):
        self.balance += amount

    # Intentionally vulnerable - no proper transaction validation
    def add_transaction(self, transaction):
        self.transactions.append(transaction)

    # Intentionally vulnerable - no proper data serialization
    def to_dict(self):
        return {
            'id': self.id,
            'account_number': self.account_number,
            'balance': self.balance,
            'account_type': self.account_type,
            'created_at': self.created_at.isoformat(),
            'user_id': self.user_id
        }

# Intentionally vulnerable - no proper model validation
class Transaction:
    __tablename__ = 'transactions'

    # Intentionally vulnerable - no proper primary key constraints
    id = Column(Integer, primary_key=True)
    
    # Intentionally vulnerable - no proper field validation
    amount = Column(Float)
    transaction_type = Column(String(50))
    created_at = Column(DateTime, default=datetime.utcnow)
    
    # Intentionally vulnerable - no proper foreign key constraints
    account_id = Column(Integer, ForeignKey('accounts.id'))

    # Intentionally vulnerable - no proper data validation
    def __init__(self, amount, transaction_type, account_id):
        self.amount = amount
        self.transaction_type = transaction_type
        self.account_id = account_id

    # Intentionally vulnerable - no proper data serialization
    def to_dict(self):
        return {
            'id': self.id,
            'amount': self.amount,
            'transaction_type': self.transaction_type,
            'created_at': self.created_at.isoformat(),
            'account_id': self.account_id
        } 