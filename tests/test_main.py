from app.main import (
    add, subtract, multiply, divide, 
    complex_function, calculate_area_rectangle, 
    function_with_many_params, calculate_tax,
    inefficient_function
)
import pytest

# Basic tests that pass
def test_add():
    assert add(2, 3) == 5

def test_subtract():
    assert subtract(10, 3) == 7

def test_multiply():
    assert multiply(4, 5) == 20

# Test that will fail
def test_temp():
    assert add(2, 3) == 6  # This will fail: 4 ≠ 6

# Test with expected exception
def test_divide_by_zero():
    with pytest.raises(ZeroDivisionError):
        divide(10, 0)

# Tests that will pass but cover edge cases
def test_complex_function():
    assert complex_function(50) == "low"
    assert complex_function(150) == "low-medium"
    assert complex_function(550) == "very high"

def test_area_calculations():
    assert calculate_area_rectangle(5, 4) == 20
    assert calculate_area_rectangle(0, 5) == 0  # Edge case
    assert calculate_area_rectangle(-1, 5) == 0  # Edge case

def test_many_params():
    result = function_with_many_params(1, 2, 3, 4, 5, 6, 7, 8)
    assert result == 36

def test_tax_calculation():
    assert calculate_tax(100) == 18.0

# Test that will be skipped
@pytest.mark.skip(reason="Feature not implemented yet")
def test_future_feature():
    assert True

# Slow test that takes time
def test_inefficient_function():
    result = inefficient_function()
    assert result == 10000

# Test with multiple assertions (not best practice - will show in quality report)
def test_multiple_assertions():
    assert add(1, 1) == 2
    assert add(2, 2) == 4
    assert add(3, 3) == 6
    assert add(4, 4) == 8

# Duplicate test logic (code duplication in tests)
def test_add_positive_numbers():
    assert add(1, 2) == 3
    assert add(5, 10) == 15

def test_add_more_positive_numbers():
    assert add(1, 2) == 3  # Duplicate assertion
    assert add(7, 8) == 15  # This will fail: 15 ≠ 15

# Test with poor naming
def test_xyz():  # Poor test name
    assert multiply(3, 3) == 9