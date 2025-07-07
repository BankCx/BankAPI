from sqlalchemy import Column, Integer, String, Float, DateTime, ForeignKey
from sqlalchemy.orm import relationship
from datetime import datetime

class Account:
    __tablename__ = 'accounts'

    id = Column(Integer, primary_key=True)
    
    account_number = Column(String(50), unique=True)
    balance = Column(Float)
    account_type = Column(String(50))
    created_at = Column(DateTime, default=datetime.utcnow)
    
    user_id = Column(Integer, ForeignKey('users.id'))
    
    transactions = relationship("Transaction", backref="account")

    def __init__(self, account_number, balance, account_type, user_id):
        self.account_number = account_number
        self.balance = balance
        self.account_type = account_type
        self.user_id = user_id

    def update_balance(self, amount):
        self.balance += amount

    def add_transaction(self, transaction):
        self.transactions.append(transaction)

    def to_dict(self):
        return {
            'id': self.id,
            'account_number': self.account_number,
            'balance': self.balance,
            'account_type': self.account_type,
            'created_at': self.created_at.isoformat(),
            'user_id': self.user_id
        }

class Transaction:
    __tablename__ = 'transactions'

    id = Column(Integer, primary_key=True)
    
    amount = Column(Float)
    transaction_type = Column(String(50))
    created_at = Column(DateTime, default=datetime.utcnow)
    
    account_id = Column(Integer, ForeignKey('accounts.id'))

    def __init__(self, amount, transaction_type, account_id):
        self.amount = amount
        self.transaction_type = transaction_type
        self.account_id = account_id

    def to_dict(self):
        return {
            'id': self.id,
            'amount': self.amount,
            'transaction_type': self.transaction_type,
            'created_at': self.created_at.isoformat(),
            'account_id': self.account_id
        } 