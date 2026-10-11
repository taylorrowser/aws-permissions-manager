"""Owner-only: build and deploy the hosted service with CloudFormation, using the owner's admin
login (`aws login`). Secrets are generated straight into SSM Parameter Store and never printed."""
import hashlib
import io
import json
import secrets
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

from . import policy

STACK = "apm"
PARAM_PREFIX = "/apm"
TABLE = "apm"
FUNCTION = "apm"
RUNTIME, PY_VERSION = "python3.13", "3.13"
PACKAGE = Path(__file__).parent
SETTINGS_FILE = Path.home() / ".apm" / "deploy.json"


def template(account, region, domain, zone_id, owner_emails, workos_client_id, vapid_public, code_bucket, code_key):
    lambda_role_policy = policy.broker_policy(account)
    lambda_role_policy["Statement"] += [
        {"Sid": "State", "Effect": "Allow", "Resource": {"Fn::GetAtt": ["Table", "Arn"]},
         "Action": ["dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:UpdateItem", "dynamodb:DeleteItem", "dynamodb:Scan"]},
        {"Sid": "Secrets", "Effect": "Allow", "Action": "ssm:GetParameter",
         "Resource": f"arn:aws:ssm:{region}:{account}:parameter{PARAM_PREFIX}/*"},
    ]
    return {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Description": "apm: agents request scoped AWS permissions; the owner approves them",
        "Resources": {
            "Boundary": {"Type": "AWS::IAM::ManagedPolicy", "Properties": {
                "ManagedPolicyName": policy.BOUNDARY_NAME, "Description": "apm: maximum permissions for any agent role",
                "PolicyDocument": policy.boundary(account)}},
            "Table": {"Type": "AWS::DynamoDB::Table", "DeletionPolicy": "Retain", "UpdateReplacePolicy": "Retain",
                      "Properties": {
                "TableName": TABLE, "BillingMode": "PAY_PER_REQUEST",
                "AttributeDefinitions": [{"AttributeName": "pk", "AttributeType": "S"}],
                "KeySchema": [{"AttributeName": "pk", "KeyType": "HASH"}],
                "PointInTimeRecoverySpecification": {"PointInTimeRecoveryEnabled": True}}},
            "BrokerRole": {"Type": "AWS::IAM::Role", "DependsOn": "Boundary", "Properties": {
                "RoleName": policy.BROKER_ROLE, "Path": policy.BROKER_ROLE_PATH,
                "Description": "apm broker: the Lambda that creates agent roles and vends their credentials",
                "AssumeRolePolicyDocument": policy.doc({"Effect": "Allow", "Action": "sts:AssumeRole",
                                                        "Principal": {"Service": "lambda.amazonaws.com"}}),
                "ManagedPolicyArns": ["arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"],
                "Policies": [{"PolicyName": "apm-broker", "PolicyDocument": lambda_role_policy}]}},
            "Logs": {"Type": "AWS::Logs::LogGroup", "Properties": {
                "LogGroupName": f"/aws/lambda/{FUNCTION}", "RetentionInDays": 90}},
            "Function": {"Type": "AWS::Lambda::Function", "DependsOn": "Logs", "Properties": {
                "FunctionName": FUNCTION, "Runtime": RUNTIME, "Architectures": ["arm64"],
                "Handler": "apm.web.handler", "MemorySize": 512, "Timeout": 29,
                "Role": {"Fn::GetAtt": ["BrokerRole", "Arn"]},
                "Code": {"S3Bucket": code_bucket, "S3Key": code_key},
                "Environment": {"Variables": {
                    "TABLE_NAME": TABLE, "DOMAIN": domain, "OWNER_EMAILS": owner_emails,
                    "WORKOS_CLIENT_ID": workos_client_id, "VAPID_PUBLIC_KEY": vapid_public,
                    "PARAM_PREFIX": PARAM_PREFIX}}}},
            "Api": {"Type": "AWS::ApiGatewayV2::Api", "Properties": {
                "Name": "apm", "ProtocolType": "HTTP", "DisableExecuteApiEndpoint": True}},
            "Integration": {"Type": "AWS::ApiGatewayV2::Integration", "Properties": {
                "ApiId": {"Ref": "Api"}, "IntegrationType": "AWS_PROXY", "PayloadFormatVersion": "2.0",
                "IntegrationUri": {"Fn::GetAtt": ["Function", "Arn"]}}},
            "Route": {"Type": "AWS::ApiGatewayV2::Route", "Properties": {
                "ApiId": {"Ref": "Api"}, "RouteKey": "$default",
                "Target": {"Fn::Sub": "integrations/${Integration}"}}},
            "Stage": {"Type": "AWS::ApiGatewayV2::Stage", "Properties": {
                "ApiId": {"Ref": "Api"}, "StageName": "$default", "AutoDeploy": True,
                "DefaultRouteSettings": {"ThrottlingBurstLimit": 50, "ThrottlingRateLimit": 20}}},
            "InvokePermission": {"Type": "AWS::Lambda::Permission", "Properties": {
                "FunctionName": {"Ref": "Function"}, "Action": "lambda:InvokeFunction",
                "Principal": "apigateway.amazonaws.com",
                "SourceArn": {"Fn::Sub": "arn:aws:execute-api:${AWS::Region}:${AWS::AccountId}:${Api}/*"}}},
            "Certificate": {"Type": "AWS::CertificateManager::Certificate", "Properties": {
                "DomainName": domain, "ValidationMethod": "DNS",
                "DomainValidationOptions": [{"DomainName": domain, "HostedZoneId": zone_id}]}},
            "DomainName": {"Type": "AWS::ApiGatewayV2::DomainName", "Properties": {
                "DomainName": domain, "DomainNameConfigurations": [{
                    "CertificateArn": {"Ref": "Certificate"}, "EndpointType": "REGIONAL",
                    "SecurityPolicy": "TLS_1_2"}]}},
            "Mapping": {"Type": "AWS::ApiGatewayV2::ApiMapping", "DependsOn": ["DomainName", "Stage"], "Properties": {
                "ApiId": {"Ref": "Api"}, "DomainName": domain, "Stage": "$default"}},
            "Dns": {"Type": "AWS::Route53::RecordSet", "Properties": {
                "HostedZoneId": zone_id, "Name": domain, "Type": "A", "AliasTarget": {
                    "DNSName": {"Fn::GetAtt": ["DomainName", "RegionalDomainName"]},
                    "HostedZoneId": {"Fn::GetAtt": ["DomainName", "RegionalHostedZoneId"]}}}},
        },
        "Outputs": {"Url": {"Value": f"https://{domain}"}},
    }


def build_zip():
    """Lambda bundle: the apm package plus `cryptography` built for Linux arm64."""
    with tempfile.TemporaryDirectory() as tmp:
        subprocess.run([sys.executable, "-m", "pip", "install", "-q", "--disable-pip-version-check",
                        "--target", tmp, "--platform", "manylinux2014_aarch64", "--python-version", PY_VERSION,
                        "--implementation", "cp", "--only-binary=:all:", "cryptography"], check=True)
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
            for f in sorted(Path(tmp).rglob("*")):
                if f.is_file() and "__pycache__" not in f.parts:
                    _add(z, f, f.relative_to(tmp))
            for f in sorted(PACKAGE.rglob("*")):
                if f.is_file() and "__pycache__" not in f.parts:
                    _add(z, f, Path("apm") / f.relative_to(PACKAGE))
    return buf.getvalue()


def _add(z, path, arcname):
    info = zipfile.ZipInfo(str(arcname), date_time=(2020, 1, 1, 0, 0, 0))  # reproducible hash
    info.external_attr = 0o644 << 16
    z.writestr(info, path.read_bytes(), zipfile.ZIP_DEFLATED)


def _ensure_param(ssm, name, make, secure=True, log=print):
    try:
        return ssm.get_parameter(Name=name, WithDecryption=False)["Parameter"]["Value"]
    except ssm.exceptions.ParameterNotFound:
        value = make()
        ssm.put_parameter(Name=name, Value=value, Type="SecureString" if secure else "String")
        log(f"Created {name} in Parameter Store" + (" (secret not shown)" if secure else ""))
        return value


def _zone_for(r53, domain):
    labels = domain.rstrip(".").split(".")
    for i in range(1, len(labels) - 1):
        name = ".".join(labels[i:]) + "."
        zones = r53.list_hosted_zones_by_name(DNSName=name, MaxItems="1")["HostedZones"]
        if zones and zones[0]["Name"] == name and not zones[0]["Config"]["PrivateZone"]:
            return zones[0]["Id"].split("/")[-1]
    raise SystemExit(f"No public Route 53 hosted zone found for {domain}. Create one for the parent domain first.")


def deploy(domain, owner_emails, workos_client_id, profile=None, region="us-east-1", log=print):
    import boto3
    from . import push

    s = boto3.Session(profile_name=profile, region_name=region)
    account = s.client("sts").get_caller_identity()["Account"]
    log(f"Deploying to account {account}, region {region}, https://{domain}")
    zone_id = _zone_for(s.client("route53"), domain)

    ssm = s.client("ssm")
    _ensure_param(ssm, f"{PARAM_PREFIX}/session-secret", lambda: secrets.token_urlsafe(48), log=log)
    try:
        vapid_public = ssm.get_parameter(Name=f"{PARAM_PREFIX}/vapid-public-key")["Parameter"]["Value"]
    except ssm.exceptions.ParameterNotFound:
        private_pem, vapid_public = push.generate_vapid_keys()
        ssm.put_parameter(Name=f"{PARAM_PREFIX}/vapid-private-key", Value=private_pem, Type="SecureString", Overwrite=True)
        ssm.put_parameter(Name=f"{PARAM_PREFIX}/vapid-public-key", Value=vapid_public, Type="String")
        log("Created push notification keys in Parameter Store (private key not shown)")

    bucket = f"apm-artifacts-{account}-{region}"
    s3 = s.client("s3")
    try:
        s3.head_bucket(Bucket=bucket)
    except Exception:
        kw = {} if region == "us-east-1" else {"CreateBucketConfiguration": {"LocationConstraint": region}}
        s3.create_bucket(Bucket=bucket, **kw)
        s3.put_public_access_block(Bucket=bucket, PublicAccessBlockConfiguration={
            "BlockPublicAcls": True, "IgnorePublicAcls": True, "BlockPublicPolicy": True, "RestrictPublicBuckets": True})
        log(f"Created artifact bucket {bucket}")
    code = build_zip()
    key = f"lambda/{hashlib.sha256(code).hexdigest()[:16]}.zip"
    s3.put_object(Bucket=bucket, Key=key, Body=code)
    log(f"Uploaded Lambda bundle ({len(code) // 1024} KiB) to s3://{bucket}/{key}")

    body = json.dumps(template(account, region, domain, zone_id, owner_emails, workos_client_id,
                               vapid_public, bucket, key))
    cfn = s.client("cloudformation")
    try:
        cfn.describe_stacks(StackName=STACK)
        exists = True
    except cfn.exceptions.ClientError:
        exists = False
    try:
        if exists:
            cfn.update_stack(StackName=STACK, TemplateBody=body, Capabilities=["CAPABILITY_NAMED_IAM"])
            waiter = "stack_update_complete"
        else:
            cfn.create_stack(StackName=STACK, TemplateBody=body, Capabilities=["CAPABILITY_NAMED_IAM"],
                             Tags=[{"Key": "managed-by", "Value": "apm"}])
            waiter = "stack_create_complete"
    except cfn.exceptions.ClientError as e:
        if "No updates are to be performed" in str(e):
            log("Stack is already up to date.")
            return
        raise
    log(f"{'Updating' if exists else 'Creating'} CloudFormation stack {STACK} (a new certificate can take a few minutes)…")
    try:
        cfn.get_waiter(waiter).wait(StackName=STACK, WaiterConfig={"Delay": 10, "MaxAttempts": 180})
    except Exception:
        events = cfn.describe_stack_events(StackName=STACK)["StackEvents"]
        for ev in events[:40]:
            if "FAILED" in ev["ResourceStatus"]:
                log(f"  {ev['LogicalResourceId']}: {ev.get('ResourceStatusReason', '')}")
        raise SystemExit("Deploy failed; see the errors above.")
    log(f"Deployed: https://{domain}")


def load_settings():
    return json.loads(SETTINGS_FILE.read_text()) if SETTINGS_FILE.exists() else {}


def save_settings(settings):
    SETTINGS_FILE.parent.mkdir(parents=True, exist_ok=True)
    SETTINGS_FILE.write_text(json.dumps(settings, indent=2) + "\n")
