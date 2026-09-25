from parser import AuditParser
from relationship import RelationshipBuilder


def main():

    print("=" * 60)
    print("        XC Security Report Generator")
    print("=" * 60)

    # Parse the JSON file
    parser = AuditParser("input/security-audit.json")
    summary, findings = parser.parse()

    # Build Load Balancer relationships
    builder = RelationshipBuilder(findings, summary)
    reports, namespace_report = builder.build()

    # Print Audit Summary
    print(f"Tenant           : {summary.tenant}")
    print(f"Namespace        : {summary.namespace}")
    print(f"Security Score   : {summary.score}")
    print(f"Timestamp        : {summary.timestamp}")
    print(f"Duration (ms)    : {summary.duration_ms}")

    print("\n" + "-" * 60)

    print(f"Total Findings   : {summary.total}")
    print(f"Critical         : {summary.critical}")
    print(f"High             : {summary.high}")
    print(f"Medium           : {summary.medium}")
    print(f"Low              : {summary.low}")
    print(f"Info             : {summary.info}")

    print("\n" + "-" * 60)

    print(f"Passed           : {summary.passed}")
    print(f"Warnings         : {summary.warnings}")
    print(f"Errors           : {summary.errors}")
    print(f"Skipped          : {summary.skipped}")

    print("\n" + "-" * 60)

    print(f"Total Findings Parsed     : {len(findings)}")
    print(f"Unique Load Balancers     : {len(reports)}")

    print("\nDone Successfully!")


if __name__ == "__main__":
    main()