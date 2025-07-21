"""
    Create a class called PersonAccount. It has firstname, lastname, incomes, expenses 
    properties and it has total_income, total_expense, account_info, add_income, 
    add_expense and account_balance methods.
    Incomes is a set of incomes and its description. The same goes for expenses.
"""

class PersonAccount:
    def __init__(self, firstname, lastname):
        self.firstname = firstname  # First name of the person
        self.lastname = lastname  # Last name of the person
        self.incomes = []  # List to store incomes as tuples (description, amount)
        self.expenses = []  # List to store expenses as tuples (description, amount)

    # Method to add income
    def add_income(self, description, amount):
        self.incomes.append((description, amount))

    # Method to add expense
    def add_expense(self, description, amount):
        self.expenses.append((description, amount))

    # Method to calculate total income
    def total_income(self):
        return sum(amount for description, amount in self.incomes)

    # Method to calculate total expense
    def total_expense(self):
        return sum(amount for description, amount in self.expenses)

    # Method to display account info
    def account_info(self):
        return f"Account holder: {self.firstname} {self.lastname}"

    # Method to calculate account balance (income - expenses)
    def account_balance(self):
        return self.total_income() - self.total_expense()

# Example usage
account = PersonAccount("Alex", "Doe")
account.add_income("Salary", 5000)
account.add_income("Freelance", 1500)
account.add_expense("Rent", 2000)
account.add_expense("Groceries", 300)

print(account.account_info())  # Output: Account holder: Alex Doe
print("Total Income:", account.total_income())  # Output: 6500
print("Total Expense:", account.total_expense())  # Output: 2300
print("Account Balance:", account.account_balance())  # Output: 4200
