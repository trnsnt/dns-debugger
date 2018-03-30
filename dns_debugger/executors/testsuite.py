"""Testsuite and testcase"""
import json
from typing import List


class TestCase:
    """A TestCase is... a testcase"""
    description: str
    result: str
    success: bool

    def __init__(self, description: str, result: str, success: bool):
        self.description = description
        self.result = result
        self.success = success

    def __str__(self):
        return '[TEST]\nDescription: {descritpion}\nstatus: {success}' \
               '\nresults: {results}'.format(descritpion=self.description, success='OK' if self.success else 'KO',
                                             results=self.result)


class TestSuite:
    """A testsuite is a list of testcase"""
    testcases: List[TestCase]
    success: int
    failures: int

    def __init__(self):
        self.testcases = list()
        self.failures = 0
        self.success = 0

    def add_testcase(self, testcase: TestCase):
        """Add a testcase to testcases"""
        self.testcases.append(testcase)
        if testcase.success:
            self.success += 1
        else:
            self.failures += 1

    def add_testcases(self, testcases: List[TestCase]):
        """Add list of testcases to testcases"""
        for testcase in testcases:
            self.add_testcase(testcase)

    def get_failues(self):
        return [t for t in self.testcases if not t.success]

    def get_success(self):
        return [t for t in self.testcases if t.success]

    def to_json(self, display_all=True):
        """self to json"""
        to_serialize = {'success': self.success, "failures": self.failures,
                        "testcases": {"failures": self.get_failues()}}
        if display_all:
            to_serialize["testcases"]["success"] = self.get_success()
        return json.dumps(to_serialize, default=lambda o: o.__dict__, indent=2)

    def __str__(self):
        return "\n".join(map(lambda x: '{}\n'.format(x), self.testcases))
