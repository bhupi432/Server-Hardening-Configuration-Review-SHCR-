# Solaris Security Review Script

![Script Logo](https://www.google.com/imgres?imgurl=https%3A%2F%2Fwww.trentonsystems.com%2Fhubfs%2Flock%2520computer%2520circuit%2520board%2520concept.jpeg&tbnid=6D2E4isCZR0jwM&vet=12ahUKEwjSuo3miYOFAxXlomMGHcxLAj8QMygZegUIARCKAQ..i&imgrefurl=https%3A%2F%2Fwww.trentonsystems.com%2Fen-us%2Fresource-hub%2Fblog%2Fsystem-hardening-overview&docid=clWI_xpLSvKrEM&w=999&h=500&q=os%20hardening%20images&ved=2ahUKEwjSuo3miYOFAxXlomMGHcxLAj8QMygZegUIARCKAQ)

## Purpose

This script aims to systematically review and enhance security configurations on Solaris OS version 11.4 systems. By automating various checks and configurations, it significantly reduces the time-consuming manual effort required for security review tasks.

## How to Run

1. Ensure the script is executable: `chmod +x solaris_security_review.sh`.
2. Execute the script: `./solaris_security_review.sh`.

## Regulations for the Script

1. Ensure proper permissions are set for executing the script.
2. Run the script with appropriate privileges (preferably as root) to access system configurations.
3. Review the output carefully to address any identified security concerns.
4. Customize script functionalities as per specific security requirements or environment configurations.

## Do's

- Run the script on Solaris OS version 11.4 systems.
- Regularly update and maintain the script according to evolving security standards and system changes.
- Ensure that necessary backups are taken before making any configuration changes suggested by the script.

## Don'ts

- Do not execute the script on unsupported Solaris OS versions or non-Solaris systems.
- Avoid making blind changes without understanding the implications of suggested configurations.
- Do not share sensitive output or system information from the script output publicly.

## Benefits of the Script

1. **Time Efficiency:** Reduces the time required for manual security configuration review by automating various checks.
2. **Consistency:** Ensures consistent application of security configurations across systems.
3. **Accuracy:** Minimizes human errors associated with manual configuration reviews.
4. **Enhanced Security:** Helps identify and address potential security vulnerabilities promptly.

## Additional Notes

- The script provides detailed prompts and outputs for each security configuration check, aiding in easy interpretation and action.
- Regularly update the script to incorporate new security recommendations or best practices.
- Exercise caution while implementing changes suggested by the script, especially in production environments.

---

### Configuration Audits Purpose

Host-Based Assessment is a process to audit an Infrastructure. Infrastructure has multiple resources like operating systems (Linux), databases, firewalls, servers, etc. If we are unable to audit these targets through professional tools like Nessus and Qualys, then in this scenario we prepare an automatic script.
