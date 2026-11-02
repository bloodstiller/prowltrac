"""Sample OCSF data for testing."""


def get_sample_finding():
    """Return a sample OCSF finding for testing."""
    return {
        "activity_id": 1,
        "activity_name": "Create",
        "category_name": "Findings",
        "category_uid": 2,
        "class_name": "Security Finding",
        "class_uid": 2001,
        "message": "S3 bucket allows public read access",
        "metadata": {
            "version": "1.0.0",
            "product": {"name": "Prowler", "vendor_name": "Prowler", "version": "3.0.0"},
        },
        "severity": "High",
        "severity_id": 4,
        "status": "New",
        "status_id": 1,
        "status_code": "FAIL",
        "type_name": "Security Finding: Create",
        "type_uid": 200101,
        "cloud": {
            "account": {"uid": "123456789012"},
            "provider": "AWS",
            "region": "us-east-1",
            "resource": {
                "name": "test-bucket",
                "type": "S3 Bucket",
                "uid": "arn:aws:s3:::test-bucket",
            },
        },
        "compliance": {"requirements": ["CIS-1.2.0"]},
        "finding": {
            "title": "S3 bucket allows public read access",
            "desc": "The S3 bucket test-bucket allows public read access",
            "remediation": {
                "desc": "Remove public read access from the S3 bucket",
                "references": [
                    "https://docs.aws.amazon.com/s3/latest/userguide/access-control-block-public-access.html"
                ],
            },
        },
        "resources": [
            {"name": "test-bucket", "type": "AWS::S3::Bucket", "uid": "arn:aws:s3:::test-bucket"}
        ],
        "unmapped": {
            "Provider": "aws",
            "Service": "s3",
            "CheckID": "s3_bucket_public_read_prohibited",
            "CheckTitle": "S3 buckets should prohibit public read access",
            "CheckType": "Software and Configuration Checks",
            "ResourceType": "AWS::S3::Bucket",
            "Severity": "HIGH",
            "ServiceName": "s3",
            "SubServiceName": "",
            "ResourceDetails": {},
            "Description": "This control checks that your S3 buckets do not allow public read access",
            "Risk": "Data Exposure",
            "RelatedUrl": "",
            "Remediation": {
                "Code": {
                    "CLI": "aws s3api put-public-access-block --bucket test-bucket --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true",
                    "NativeIaC": "",
                    "Other": "",
                    "Terraform": "",
                },
                "Recommendation": {
                    "Text": "Remove public read access from the S3 bucket by enabling Block Public Access settings",
                    "Url": "https://docs.aws.amazon.com/s3/latest/userguide/access-control-block-public-access.html",
                },
            },
            "Categories": [],
            "DependsOn": [],
            "RelatedTo": [],
            "Notes": "",
            "Compliance": {
                "CISA": [],
                "CIS-1.4": ["2.1.2"],
                "CIS-1.5": ["2.1.2"],
                "CIS-2.0": ["2.1.2"],
                "ENS-OP": [],
                "ISO27001": ["A.13.1.1"],
                "NIST-800-171-Revision-2": [],
                "NIST-800-53-Revision-4": [],
                "NIST-800-53-Revision-5": [],
                "NIST-CSF-1.1": [],
                "PCI-3.2.1": [],
                "SOC2-CC": [],
                "AWS-Foundational-Security-Standard": ["S3.1"],
                "AWS-Well-Architected-Framework-Security-Pillar": [],
                "GDPR": [],
            },
        },
    }


def get_sample_findings_list():
    """Return a list of sample OCSF findings for testing."""
    base_finding = get_sample_finding()

    findings = []

    # Critical finding
    critical = base_finding.copy()
    critical.update(
        {
            "severity": "Critical",
            "severity_id": 5,
            "status_code": "FAIL",
            "message": "S3 bucket allows public write access",
        }
    )
    findings.append(critical)

    # High finding (FAIL)
    high_fail = base_finding.copy()
    high_fail.update(
        {
            "severity": "High",
            "severity_id": 4,
            "status_code": "FAIL",
            "message": "S3 bucket encryption disabled",
        }
    )
    findings.append(high_fail)

    # Medium finding (PASS)
    medium_pass = base_finding.copy()
    medium_pass.update(
        {
            "severity": "Medium",
            "severity_id": 3,
            "status_code": "PASS",
            "message": "S3 bucket versioning enabled",
        }
    )
    findings.append(medium_pass)

    # Low finding (FAIL)
    low_fail = base_finding.copy()
    low_fail.update(
        {
            "severity": "Low",
            "severity_id": 2,
            "status_code": "FAIL",
            "message": "S3 bucket logging disabled",
        }
    )
    findings.append(low_fail)

    return findings
