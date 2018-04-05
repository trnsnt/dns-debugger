"""Exceptions related to dns_debugger"""


class DnsDebuggerException(Exception):
    """Generic exception"""

    def __init__(self, message):
        Exception.__init__(self)
        self.message = message

    def __str__(self):
        return self.message


class QueryTimeException(DnsDebuggerException):
    """Exception for timeout"""
    pass


class QueryErrException(DnsDebuggerException):
    """Exception for dns query error"""
    pass


class QueryNoResponseException(DnsDebuggerException):
    """Exception for dns query no response"""
    pass
