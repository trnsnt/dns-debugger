"""Simple console ui"""
from dns_debugger.executors import TestSuite


def display(testsuite: TestSuite, display_all=True):
    """Simple console ui, just print the testsuite as json"""
    print(testsuite.to_json(display_all=display_all))
