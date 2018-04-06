"""Create a small flask APP"""
from flask import Flask, Response, jsonify, render_template

from dns_debugger.executors import run_tests

APP = Flask(__name__, static_url_path='')


@APP.route('/monitoring/ping')
def ping():
    """Check qname"""
    return jsonify("pong")


@APP.route('/check/<qname>')
def check(qname):
    """Check qname"""
    testsuite = run_tests(qname=qname)
    return render_template("testsuite.html", testsuite=testsuite, qname=qname)


@APP.route('/api/check/<qname>')
def check_qname(qname):
    """Check qname"""
    testsuite = run_tests(qname=qname)
    return Response(testsuite.to_json(), status=200, mimetype='application/json')
