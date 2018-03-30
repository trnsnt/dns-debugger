"""Run"""
import argparse

from dns_debugger.executors import run_tests
from dns_debugger.ui import console


def run():
    """Parse args and run"""
    parser = argparse.ArgumentParser()
    parser.add_argument("-d", "--domain", dest="qname",
                        help="FQDN of the DNS zone you want to test")
    parser.add_argument("-x", "--ui", dest="ui", default="console",
                        help="Wanted display console|server")
    parser.add_argument("--all", dest="display_all", help="Display all testcases", action='store_true')
    parser.add_argument("--failures", dest="display_all", help="Display only testcases in failure",
                        action='store_false')
    parser.set_defaults(display_all=True)
    args = parser.parse_args()

    if args.ui == "console":
        if not args.qname:
            parser.error("domain not entered")
        qname = args.qname
        testsuite = run_tests(qname=qname)
        console.display(testsuite=testsuite, display_all=args.display_all)

    elif args.ui == "server":
        from dns_debugger.ui.server import APP

        APP.run()


if __name__ == "__main__":
    run()
