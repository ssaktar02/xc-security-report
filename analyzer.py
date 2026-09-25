from parser import AuditParser
from collections import Counter
import json


def main():

    parser = AuditParser("input/security-audit.json")
    summary, findings = parser.parse()

    print("=" * 80)
    print("OBJECT TYPE SUMMARY")
    print("=" * 80)

    counter = Counter()

    for finding in findings:
        counter[finding.object_type] += 1

    for object_type, count in counter.items():
        print(f"{object_type:30} {count}")

    print("\n")

    interesting_types = [
        "app_firewall",
        "origin_pool",
        "service_policy",
        "certificate",
        "http_loadbalancer"
    ]

    for obj_type in interesting_types:

        print("=" * 80)
        print(f"SAMPLE : {obj_type}")
        print("=" * 80)

        found = False

        for finding in findings:

            if finding.object_type == obj_type:

                print(f"Rule ID      : {finding.rule_id}")
                print(f"Rule Name    : {finding.rule_name}")
                print(f"Object Name  : {finding.object_name}")
                print(f"Status       : {finding.status}")

                print("\nDetails:")

                print(json.dumps(finding.details, indent=4))

                found = True
                break

        if not found:
            print("No findings found.")

        print("\n")


if __name__ == "__main__":
    main()