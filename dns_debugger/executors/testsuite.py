"""Testsuite and testcase"""
import typing
from enum import Enum

import simplejson as json


class TestStatus(Enum):
    """Status for tests"""
    SUCCESS = 1
    WARNING = 2
    ERROR = 3


TestStep = typing.NamedTuple("TestStep", [("description", str), ("result", str), ("status", TestStatus)])


class TestCase:
    """A testCase object"""
    description: str
    status: TestStatus
    steps: typing.List[TestStep]

    def __init__(self, description):
        self.description = description
        self.steps = list()
        self.status = TestStatus.SUCCESS

    def add_step(self, step: TestStep):
        """Add TestStep to testcase"""
        self.status = step.status if step.status.value > self.status.value else self.status
        self.steps.append(step)

    def add_steps(self, steps: typing.List[TestStep]):
        """Add TestStep to testcase"""
        for step in steps:
            self.add_step(step)


class TestSuite:
    """A testsuite is a list of testcase"""
    testcases: typing.List[TestCase]
    status: TestStatus
    failures: int
    success: int

    def __init__(self):
        self.testcases = list()
        self.failures = 0
        self.success = 0
        self.status = TestStatus.SUCCESS

    def add_testcase(self, testcase: TestCase):
        """Add a testcase to testcases"""
        self.testcases.append(testcase)
        if testcase.status.value < TestStatus.ERROR.value:
            self.success += 1
        else:
            self.failures += 1

    def add_testcases(self, testcases: typing.List[TestCase]):
        """Add list of testcases to testcases"""
        for testcase in testcases:
            self.add_testcase(testcase)

    def get_failures(self):
        """Get testcases in failure"""
        return [t for t in self.testcases if t.status.value == TestStatus.ERROR.value]

    def get_success(self):
        """Get testcases in success"""
        return [t for t in self.testcases if t.status.value < TestStatus.ERROR.value]

    def to_json(self, display_all=True):
        """self to json"""
        to_serialize = {'success': self.success, "failures": self.failures,
                        "testcases": {"failures": self.get_failures()}}
        if display_all:
            to_serialize["testcases"]["success"] = self.get_success()
        return json.dumps(to_serialize, default=lambda o: o.name if isinstance(o, TestStatus) else o.__dict__,
                          indent=2)
