"""Create a small flask APP"""
from flask import Flask, Response, jsonify

from dns_debugger.executors import run_tests

APP = Flask(__name__)


@APP.route('/monitoring/ping')
def ping():
    """Check qname"""
    return jsonify("pong")


@APP.route('/<qname>')
def check_qname(qname):
    """Check qname"""
    testsuite = run_tests(qname=qname)
    return Response(testsuite.to_json(), status=200, mimetype='application/json')
