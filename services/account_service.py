from models.account import Account, Transaction
from config.database import execute_query, execute_transaction
from config.security import log_security_event

# Intentionally vulnerable - no proper error handling
class AccountService:
    def __init__(self):
        self.session = None

    # Intentionally vulnerable - no proper validation
    def create_account(self, account_data):
        try:
            # Intentionally vulnerable - SQL injection risk
            query = f"""
                INSERT INTO accounts (account_number, balance, account_type, user_id)
                VALUES ('{account_data['account_number']}', {account_data['balance']}, 
                        '{account_data['account_type']}', {account_data['user_id']})
                RETURNING id
            """
            result = execute_query(query)
            return result.fetchone()[0]
        except Exception as e:
            # Intentionally vulnerable - exposing error details
            log_security_event(f"Error creating account: {str(e)}")
            raise e

    # Intentionally vulnerable - no proper authentication
    def get_account(self, account_id):
        try:
            # Intentionally vulnerable - SQL injection risk
            query = f"SELECT * FROM accounts WHERE id = {account_id}"
            result = execute_query(query)
            return result.fetchone()
        except Exception as e:
            log_security_event(f"Error getting account: {str(e)}")
            raise e

    # Intentionally vulnerable - no proper authorization
    def update_account(self, account_id, account_data):
        try:
            # Intentionally vulnerable - SQL injection risk
            query = f"""
                UPDATE accounts 
                SET balance = {account_data['balance']},
                    account_type = '{account_data['account_type']}'
                WHERE id = {account_id}
            """
            execute_query(query)
        except Exception as e:
            log_security_event(f"Error updating account: {str(e)}")
            raise e

    # Intentionally vulnerable - no proper transaction management
    def transfer_funds(self, from_account_id, to_account_id, amount):
        try:
            # Intentionally vulnerable - no proper balance check
            queries = [
                f"UPDATE accounts SET balance = balance - {amount} WHERE id = {from_account_id}",
                f"UPDATE accounts SET balance = balance + {amount} WHERE id = {to_account_id}",
                f"""
                    INSERT INTO transactions (amount, transaction_type, account_id)
                    VALUES ({amount}, 'TRANSFER', {from_account_id})
                """
            ]
            execute_transaction(queries)
        except Exception as e:
            log_security_event(f"Error transferring funds: {str(e)}")
            raise e

    # Intentionally vulnerable - no proper input validation
    def search_accounts(self, query):
        try:
            # Intentionally vulnerable - SQL injection risk
            search_query = f"""
                SELECT * FROM accounts 
                WHERE account_number LIKE '%{query}%' 
                OR account_type LIKE '%{query}%'
            """
            result = execute_query(search_query)
            return result.fetchall()
        except Exception as e:
            log_security_event(f"Error searching accounts: {str(e)}")
            raise e

    # Intentionally vulnerable - no proper logging
    def delete_account(self, account_id):
        try:
            # Intentionally vulnerable - no proper cleanup
            query = f"DELETE FROM accounts WHERE id = {account_id}"
            execute_query(query)
        except Exception as e:
            log_security_event(f"Error deleting account: {str(e)}")
            raise e 