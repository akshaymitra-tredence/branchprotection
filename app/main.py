def add(a, b):
    return a + b

def subtract(a, b):
    return a - b

def multiply(a, b):
    return a * b

def divide(a, b):
    # Bug: No check for division by zero
    return a / b

def complex_function(x):
    # High complexity function - will trigger complexity warnings
    if x > 100:
        if x > 200:
            if x > 300:
                if x > 400:
                    if x > 500:
                        return "very high"
                    else:
                        return "high"
                else:
                    return "medium-high" 
            else:
                return "medium"
        else:
            return "low-medium"
    else:
        return "low"

# Code duplication - similar functions
def calculate_area_rectangle(length, width):
    if length <= 0 or width <= 0:
        return 0
    result = length * width
    return result

def calculate_area_square(side):
    if side <= 0:
        return 0
    result = side * side  # Duplicate logic pattern
    return result

# Unused variable and dead code
def unused_function():
    unused_var = "this will trigger unused variable warning"
    dead_code = "never used"
    return "only this is returned"

# Long parameter list (code smell)
def function_with_many_params(a, b, c, d, e, f, g, h):
    return a + b + c + d + e + f + g + h

# Missing docstring and poor naming
def func(x, y, z):  # Poor function name
    temp = x + y  # Poor variable name
    return temp * z

# Hardcoded values (magic numbers)
def calculate_tax(amount):
    return amount * 0.18  # Magic number - should be a constant

# Security issues - multiple hotspots
def unsafe_eval(user_input):
    # This is intentionally unsafe for demo purposes
    return eval(f"2 + 2 + {user_input}")  # Security hotspot

import subprocess
def unsafe_command(user_input):
    # Command injection vulnerability
    return subprocess.call(f"echo {user_input}", shell=True)

import pickle
def unsafe_pickle(data):
    # Pickle deserialization vulnerability  
    return pickle.loads(data)

def weak_random():
    import random
    # Weak random number generation
    return random.random()

def sql_injection_risk(user_id):
    # SQL injection pattern
    query = f"SELECT * FROM users WHERE id = {user_id}"
    return query

# Memory inefficient - creating large lists
def inefficient_function():
    large_list = []
    for i in range(10000):  # Creates large list unnecessarily
        large_list.append(i * 2)
    return len(large_list)

# Exception handling issues
def risky_function(data):
    try:
        result = data['key']  # Might throw KeyError
        return result / data['divisor']  # Might throw ZeroDivisionError
    except:  # Too broad exception handling
        pass  # Empty except block

# TODO and FIXME comments (technical debt)
def todo_function():
    # TODO: Implement proper error handling
    # FIXME: This function has performance issues
    return "placeholder"