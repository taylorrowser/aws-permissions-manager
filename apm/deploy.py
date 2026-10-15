"""Build and deploy the hosted service with CloudFormation.

Two halves, so one immutable artifact can be promoted from dev to prod:
- build_artifact(): a reproducible Lambda zip plus manifest.json (sha256, git sha, Python version,
  locked dependencies). No AWS calls.
- deploy_artifact(): deploy an existing artifact to a stage after checking its digest.

`apm-admin deploy` (the owner path, using the owner's admin login) does both for prod. Secrets are
generated straight into SSM Parameter Store and never printed."""
import hashlib
import io
import json
import platform
import re
import secrets
import subprocess
import sys
import tempfile
import time
import datetime as dt
import urllib.error
import urllib.request
import zipfile
from pathlib import Path

from . import policy

# Prod names, kept for callers that predate stages. Use policy.Names(stage) for anything else.
STACK = "apm"
PARAM_PREFIX = "/apm"
TABLE = "apm"
FUNCTION = "apm"
RUNTIME, PY_VERSION, ARCH = "python3.13", "3.13", "arm64"
PIP_PLATFORM = "manylinux2014_aarch64"
PACKAGE = Path(__file__).parent
LOCK_FILE = PACKAGE / "lambda-requirements.txt"
SETTINGS_FILE = Path.home() / ".apm" / "deploy.json"
ZIP_NAME, MANIFEST_NAME = "lambda.zip", "manifest.json"
MANIFEST_SCHEMA = 1
PREVIEW_TTL_DAYS = 7
# Preview bundles share one bucket per account; they are disposable, so they expire. Dev and prod
# buckets have no expiry: their bundles and release records are kept for rollback.
PREVIEW_BUCKET_EXPIRY_DAYS = 30
EXPIRES_TAG = "apm:expires-at"
STAGE_TAG = "apm:stage"


def boundary_document(account, names):
    """The agent boundary as deployed: policy.boundary() plus a deny on this stack's own API."""
    doc = policy.boundary(account, names)
    doc["Statement"].append(policy.api_deny())
    return doc


def template(account, region, domain, zone_id, owner_emails, workos_client_id, vapid_public, code_bucket, code_key,
             stage=policy.PROD, certificate_arn=None):
    """CloudFormation template for one stage. For stage "prod" every name is identical to the
    original single-stage template; the only addition is the APM_STAGE environment variable."""
    n = policy.Names(stage)
    lambda_role_policy = policy.broker_policy(account, n)
    lambda_role_policy["Statement"] += [
        {"Sid": "State", "Effect": "Allow", "Resource": {"Fn::GetAtt": ["Table", "Arn"]},
         "Action": ["dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:UpdateItem", "dynamodb:DeleteItem", "dynamodb:Scan"]},
        {"Sid": "Secrets", "Effect": "Allow", "Action": "ssm:GetParameter",
         "Resource": f"arn:aws:ssm:{region}:{account}:parameter{n.param_prefix}/*"},
    ]
    # Previews are disposable: their table goes with the stack. prod and dev keep theirs.
    keep = "Delete" if n.is_preview else "Retain"
    cert = certificate_arn or {"Ref": "Certificate"}
    description = "apm: agents request scoped AWS permissions; the owner approves them"
    resources = {
        "Boundary": {"Type": "AWS::IAM::ManagedPolicy", "Properties": {
            "ManagedPolicyName": n.boundary_name, "Description": "apm: maximum permissions for any agent role",
            "PolicyDocument": boundary_document(account, n)}},
        "Table": {"Type": "AWS::DynamoDB::Table", "DeletionPolicy": keep, "UpdateReplacePolicy": keep,
                  "Properties": {
            "TableName": n.table, "BillingMode": "PAY_PER_REQUEST",
            "AttributeDefinitions": [{"AttributeName": "pk", "AttributeType": "S"}],
            "KeySchema": [{"AttributeName": "pk", "KeyType": "HASH"}],
            "PointInTimeRecoverySpecification": {"PointInTimeRecoveryEnabled": not n.is_preview}}},
        "BrokerRole": {"Type": "AWS::IAM::Role", "DependsOn": "Boundary", "Properties": {
            "RoleName": n.broker_role, "Path": n.broker_role_path,
            "Description": "apm broker: the Lambda that creates agent roles and vends their credentials",
            "AssumeRolePolicyDocument": policy.doc({"Effect": "Allow", "Action": "sts:AssumeRole",
                                                    "Principal": {"Service": "lambda.amazonaws.com"}}),
            "ManagedPolicyArns": ["arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"],
            "Policies": [{"PolicyName": "apm-broker" if n.is_prod else n.broker_role,
                          "PolicyDocument": lambda_role_policy}]}},
        "Logs": {"Type": "AWS::Logs::LogGroup", "Properties": {
            "LogGroupName": f"/aws/lambda/{n.function}", "RetentionInDays": 90 if n.is_prod else 14}},
        "Function": {"Type": "AWS::Lambda::Function", "DependsOn": "Logs", "Properties": {
            "FunctionName": n.function, "Runtime": RUNTIME, "Architectures": [ARCH],
            "Handler": "apm.web.handler", "MemorySize": 512, "Timeout": 29,
            "Role": {"Fn::GetAtt": ["BrokerRole", "Arn"]},
            "Code": {"S3Bucket": code_bucket, "S3Key": code_key},
            "Environment": {"Variables": {
                "TABLE_NAME": n.table, "DOMAIN": domain, "OWNER_EMAILS": owner_emails,
                "WORKOS_CLIENT_ID": workos_client_id, "VAPID_PUBLIC_KEY": vapid_public,
                "PARAM_PREFIX": n.param_prefix, "APM_STAGE": n.stage}}}},
        "Api": {"Type": "AWS::ApiGatewayV2::Api", "Properties": {
            "Name": n.base, "ProtocolType": "HTTP", "DisableExecuteApiEndpoint": True}},
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
        # The expiry sweep: tidies time-limited grants out of IAM and marks them expired (App.sweep).
        "Sweep": {"Type": "AWS::Events::Rule", "Properties": {
            "Name": f"{n.base}-sweep", "Description": "apm: remove expired grants every 15 minutes",
            "ScheduleExpression": "rate(15 minutes)", "State": "ENABLED",
            "Targets": [{"Id": "sweep", "Arn": {"Fn::GetAtt": ["Function", "Arn"]}, "Input": '{"apm_sweep": true}'}]}},
        "SweepPermission": {"Type": "AWS::Lambda::Permission", "Properties": {
            "FunctionName": {"Ref": "Function"}, "Action": "lambda:InvokeFunction",
            "Principal": "events.amazonaws.com", "SourceArn": {"Fn::GetAtt": ["Sweep", "Arn"]}}},
        "Certificate": {"Type": "AWS::CertificateManager::Certificate", "Properties": {
            "DomainName": domain, "ValidationMethod": "DNS",
            "DomainValidationOptions": [{"DomainName": domain, "HostedZoneId": zone_id}]}},
        "DomainName": {"Type": "AWS::ApiGatewayV2::DomainName", "Properties": {
            "DomainName": domain, "DomainNameConfigurations": [{
                "CertificateArn": cert, "EndpointType": "REGIONAL",
                "SecurityPolicy": "TLS_1_2"}]}},
        "Mapping": {"Type": "AWS::ApiGatewayV2::ApiMapping", "DependsOn": ["DomainName", "Stage"], "Properties": {
            "ApiId": {"Ref": "Api"}, "DomainName": domain, "Stage": "$default"}},
        "Dns": {"Type": "AWS::Route53::RecordSet", "Properties": {
            "HostedZoneId": zone_id, "Name": domain, "Type": "A", "AliasTarget": {
                "DNSName": {"Fn::GetAtt": ["DomainName", "RegionalDomainName"]},
                "HostedZoneId": {"Fn::GetAtt": ["DomainName", "RegionalHostedZoneId"]}}}},
    }
    if certificate_arn:  # e.g. a shared wildcard certificate for previews: no per-stack ACM wait
        del resources["Certificate"]
    return {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Description": description if n.is_prod else f"{description} (stage {n.stage})",
        "Resources": resources,
        "Outputs": {"Url": {"Value": f"https://{domain}"}},
    }


# ---------- build (no AWS) ----------

def lock_dependencies():
    """[(name, version)] pinned in the Lambda lock file."""
    deps = []
    for line in LOCK_FILE.read_text().splitlines():
        m = re.match(r"^([A-Za-z0-9_.-]+)==([^\s;\\]+)", line.strip())
        if m:
            deps.append((m.group(1).lower(), m.group(2)))
    return deps


def build_zip():
    """Lambda bundle: the apm package plus its locked dependencies built for Linux arm64.
    Reproducible: the same source and lock give the same bytes."""
    with tempfile.TemporaryDirectory() as tmp:
        subprocess.run([sys.executable, "-m", "pip", "install", "-q", "--disable-pip-version-check",
                        "--no-compile", "--no-deps", "--require-hashes", "-r", str(LOCK_FILE),
                        "--target", tmp, "--platform", PIP_PLATFORM, "--python-version", PY_VERSION,
                        "--implementation", "cp", "--only-binary=:all:"], check=True)
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
            for f in sorted(Path(tmp).rglob("*")):
                # bin/ scripts carry the builder's interpreter path in their shebang, and each
                # dist-info RECORD hashes them, so both would make the bytes depend on the build host.
                rel = f.relative_to(tmp).parts
                if rel[0] == "bin" or (rel[0].endswith(".dist-info") and rel[-1] == "RECORD"):
                    continue
                if _bundled(f, Path(tmp)):
                    _add(z, f, f.relative_to(tmp))
            for f in sorted(PACKAGE.rglob("*")):
                if _bundled(f, PACKAGE) and f != LOCK_FILE:
                    _add(z, f, Path("apm") / f.relative_to(PACKAGE))
    return buf.getvalue()


def _bundled(f, root):
    rel = f.relative_to(root).parts
    return f.is_file() and "__pycache__" not in rel and not any(p.startswith(".") for p in rel)


def _add(z, path, arcname):
    info = zipfile.ZipInfo(Path(arcname).as_posix(), date_time=(2020, 1, 1, 0, 0, 0))  # reproducible hash
    info.external_attr = 0o644 << 16
    z.writestr(info, path.read_bytes(), zipfile.ZIP_DEFLATED)


def s3_key(sha256):
    return f"lambda/{sha256[:16]}.zip"


def _git_sha():
    try:
        return subprocess.run(["git", "rev-parse", "HEAD"], cwd=PACKAGE, capture_output=True, text=True,
                              check=True).stdout.strip()
    except Exception:
        return "unknown"


def build_artifact(out_dir, git_sha=None, log=print):
    """Write lambda.zip and manifest.json to out_dir and return the manifest."""
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    code = build_zip()
    digest = hashlib.sha256(code).hexdigest()
    (out / ZIP_NAME).write_bytes(code)
    manifest = {
        "schema": MANIFEST_SCHEMA,
        "git_sha": git_sha or _git_sha(),
        "sha256": digest,
        "size": len(code),
        "s3_key": s3_key(digest),
        "runtime": RUNTIME,
        "python_version": PY_VERSION,
        "architecture": ARCH,
        "lock_sha256": hashlib.sha256(LOCK_FILE.read_bytes()).hexdigest(),
        "dependencies": [{"name": d, "version": v} for d, v in lock_dependencies()],
        "built_with": f"{platform.python_implementation()} {platform.python_version()} on {sys.platform}",
    }
    (out / MANIFEST_NAME).write_text(json.dumps(manifest, indent=2) + "\n")
    log(f"Built {ZIP_NAME} ({len(code) // 1024} KiB) sha256 {digest} for git {manifest['git_sha']}")
    return manifest


def verify_artifact(artifact_dir, expected_sha256=None, expected_git_sha=None):
    """Return the manifest if lambda.zip matches it (and the expectations); raise SystemExit if not."""
    d = Path(artifact_dir)
    manifest = json.loads((d / MANIFEST_NAME).read_text())
    if manifest.get("schema") != MANIFEST_SCHEMA:
        raise SystemExit(f"unsupported manifest schema {manifest.get('schema')!r}")
    actual = hashlib.sha256((d / ZIP_NAME).read_bytes()).hexdigest()
    if actual != manifest["sha256"]:
        raise SystemExit(f"artifact digest {actual} does not match its manifest ({manifest['sha256']})")
    if expected_sha256 and actual != expected_sha256:
        raise SystemExit(f"artifact digest {actual} is not the expected {expected_sha256}")
    if expected_git_sha and manifest["git_sha"] != expected_git_sha:
        raise SystemExit(f"artifact was built from {manifest['git_sha']}, not {expected_git_sha}")
    if manifest["s3_key"] != s3_key(actual):
        raise SystemExit("manifest s3_key does not match the digest")
    return manifest


# ---------- deploy (AWS) ----------

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


def _ensure_secrets(ssm, prefix, copy_workos_key_from=None, log=print):
    """Per-stage session secret and VAPID keys (never shared between stages). Returns the VAPID public key."""
    from . import push

    _ensure_param(ssm, f"{prefix}/session-secret", lambda: secrets.token_urlsafe(48), log=log)
    try:
        vapid_public = ssm.get_parameter(Name=f"{prefix}/vapid-public-key")["Parameter"]["Value"]
    except ssm.exceptions.ParameterNotFound:
        private_pem, vapid_public = push.generate_vapid_keys()
        ssm.put_parameter(Name=f"{prefix}/vapid-private-key", Value=private_pem, Type="SecureString", Overwrite=True)
        ssm.put_parameter(Name=f"{prefix}/vapid-public-key", Value=vapid_public, Type="String")
        log("Created push notification keys in Parameter Store (private key not shown)")
    if copy_workos_key_from:
        check_workos_copy(prefix, copy_workos_key_from)
        # Nonprod only: one WorkOS staging client secret, copied inside AWS to each preview stage.
        # The value stays in memory here and is never printed.
        try:
            ssm.get_parameter(Name=f"{prefix}/workos-api-key", WithDecryption=False)
        except ssm.exceptions.ParameterNotFound:
            try:
                value = ssm.get_parameter(Name=f"{copy_workos_key_from}/workos-api-key",
                                          WithDecryption=True)["Parameter"]["Value"]
            except ssm.exceptions.ParameterNotFound:
                log(f"No {copy_workos_key_from}/workos-api-key; sign-in will use PKCE without a client secret")
            else:
                ssm.put_parameter(Name=f"{prefix}/workos-api-key", Value=value, Type="SecureString")
                log(f"Set {prefix}/workos-api-key from {copy_workos_key_from} (secret not shown)")
    return vapid_public


def check_workos_copy(prefix, source):
    """The shared WorkOS secret copy is for nonprod stages from a nonprod prefix only: never into
    prod, and never from a prod or stage prefix (prod's /apm, /apm-dev, /apm-pr-N)."""
    if prefix == "/apm" or not prefix.startswith("/apm-"):
        raise SystemExit(f"refusing to copy a WorkOS secret into {prefix}: prod secrets are owner-managed")
    if not re.fullmatch(r"/apm-nonprod(-[a-z0-9]+)?", source or ""):
        raise SystemExit(f"refusing to copy a WorkOS secret from {source!r}: only /apm-nonprod is allowed")


def _ensure_bucket(s3, bucket, region, expire_days=None, log=print):
    try:
        s3.head_bucket(Bucket=bucket)
    except Exception:
        kw = {} if region == "us-east-1" else {"CreateBucketConfiguration": {"LocationConstraint": region}}
        s3.create_bucket(Bucket=bucket, **kw)
        s3.put_public_access_block(Bucket=bucket, PublicAccessBlockConfiguration={
            "BlockPublicAcls": True, "IgnorePublicAcls": True, "BlockPublicPolicy": True, "RestrictPublicBuckets": True})
        if expire_days:
            s3.put_bucket_lifecycle_configuration(Bucket=bucket, LifecycleConfiguration={"Rules": [{
                "ID": "expire-preview-bundles", "Status": "Enabled", "Filter": {"Prefix": ""},
                "Expiration": {"Days": expire_days}}]})
        log(f"Created artifact bucket {bucket}" + (f" (objects expire after {expire_days} days)" if expire_days else ""))


def _upload_code(s3, bucket, manifest, code, log=print):
    """Content-addressed: an existing key is reused, never overwritten."""
    key = manifest["s3_key"]
    try:
        existing = s3.get_object(Bucket=bucket, Key=key)["Body"].read()
    except Exception:
        existing = None
    if existing is not None:
        # The key is only a digest prefix: never trust an existing object without re-hashing it.
        if hashlib.sha256(existing).hexdigest() != manifest["sha256"]:
            raise SystemExit(f"s3://{bucket}/{key} exists with different content; refusing to deploy it")
        log(f"Lambda bundle already at s3://{bucket}/{key}")
    else:
        s3.put_object(Bucket=bucket, Key=key, Body=code,
                      Metadata={"sha256": manifest["sha256"], "git-sha": manifest["git_sha"]})
        log(f"Uploaded Lambda bundle ({len(code) // 1024} KiB) to s3://{bucket}/{key}")
    s3.put_object(Bucket=bucket, Key=f"manifests/{manifest['sha256']}.json",
                  Body=json.dumps(manifest, indent=2).encode(), ContentType="application/json")
    return key


def stack_tags(stage, now=None, ttl_days=PREVIEW_TTL_DAYS):
    """Tags for a new stack. Previews also carry an expiry (refreshed on every deploy) for the sweeper."""
    tags = [{"Key": "managed-by", "Value": "apm"}]
    if stage != policy.PROD:
        tags.append({"Key": STAGE_TAG, "Value": stage})
    if policy.Names(stage).is_preview:
        expires = (now or dt.datetime.now(dt.timezone.utc)) + dt.timedelta(days=ttl_days)
        tags.append({"Key": EXPIRES_TAG, "Value": expires.strftime("%Y-%m-%dT%H:%M:%SZ")})
    return tags


def _apply_stack(cfn, stack, body, stage, log=print, ttl_days=PREVIEW_TTL_DAYS):
    try:
        cfn.describe_stacks(StackName=stack)
        exists = True
    except cfn.exceptions.ClientError:
        exists = False
    tags = stack_tags(stage, ttl_days=ttl_days)
    try:
        if exists:
            # prod and dev keep their existing tags untouched; previews refresh their expiry.
            extra = {"Tags": tags} if policy.Names(stage).is_preview else {}
            cfn.update_stack(StackName=stack, TemplateBody=body, Capabilities=["CAPABILITY_NAMED_IAM"], **extra)
            waiter = "stack_update_complete"
        else:
            cfn.create_stack(StackName=stack, TemplateBody=body, Capabilities=["CAPABILITY_NAMED_IAM"], Tags=tags)
            waiter = "stack_create_complete"
    except cfn.exceptions.ClientError as e:
        if "No updates are to be performed" in str(e):
            log("Stack is already up to date.")
            return
        raise
    log(f"{'Updating' if exists else 'Creating'} CloudFormation stack {stack} (a new certificate can take a few minutes)…")
    try:
        cfn.get_waiter(waiter).wait(StackName=stack, WaiterConfig={"Delay": 10, "MaxAttempts": 180})
    except Exception:
        _log_failures(cfn, stack, log)
        raise SystemExit("Deploy failed; see the errors above.")


def _log_failures(cfn, stack, log):
    events = cfn.describe_stack_events(StackName=stack)["StackEvents"]
    for ev in events[:40]:
        if "FAILED" in ev["ResourceStatus"]:
            log(f"  {ev['LogicalResourceId']}: {ev.get('ResourceStatusReason', '')}")


def deploy_artifact(artifact_dir, domain, owner_emails, workos_client_id, stage=policy.PROD, profile=None,
                    region="us-east-1", zone_id=None, certificate_arn=None, expected_sha256=None,
                    expected_git_sha=None, expected_account=None, copy_workos_key_from=None,
                    preview_ttl_days=PREVIEW_TTL_DAYS, log=print):
    """Deploy an already-built artifact to a stage. Returns the verified manifest."""
    import boto3

    n = policy.Names(stage)
    manifest = verify_artifact(artifact_dir, expected_sha256, expected_git_sha)
    code = (Path(artifact_dir) / ZIP_NAME).read_bytes()
    if copy_workos_key_from:
        check_workos_copy(n.param_prefix, copy_workos_key_from)

    s = boto3.Session(profile_name=profile, region_name=region)
    account = s.client("sts").get_caller_identity()["Account"]
    if expected_account and account != str(expected_account):
        raise SystemExit(f"refusing to deploy: credentials are for account {account}, expected {expected_account}")
    log(f"Deploying {manifest['git_sha'][:12]} (sha256 {manifest['sha256'][:16]}) as stage {n.stage} "
        f"to account {account}, region {region}, https://{domain}")
    zone_id = zone_id or _zone_for(s.client("route53"), domain)

    vapid_public = _ensure_secrets(s.client("ssm"), n.param_prefix, copy_workos_key_from, log=log)
    bucket = n.artifact_bucket(account, region)
    s3 = s.client("s3")
    _ensure_bucket(s3, bucket, region, expire_days=PREVIEW_BUCKET_EXPIRY_DAYS if n.is_preview else None, log=log)
    key = _upload_code(s3, bucket, manifest, code, log=log)

    body = json.dumps(template(account, region, domain, zone_id, owner_emails, workos_client_id,
                               vapid_public, bucket, key, stage=n.stage, certificate_arn=certificate_arn))
    _apply_stack(s.client("cloudformation"), n.stack, body, n.stage, log=log, ttl_days=preview_ttl_days)
    record = {**manifest, "stage": n.stage, "domain": domain, "account": account, "region": region,
              "deployed_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
    s3.put_object(Bucket=bucket, Key=f"deployments/{n.stage}/{manifest['git_sha']}.json",
                  Body=json.dumps(record, indent=2).encode(), ContentType="application/json")
    s3.put_object(Bucket=bucket, Key=f"deployments/{n.stage}/current.json",
                  Body=json.dumps(record, indent=2).encode(), ContentType="application/json")
    log(f"Deployed: https://{domain}")
    return manifest


def deploy(domain, owner_emails, workos_client_id, profile=None, region="us-east-1", stage=policy.PROD, log=print):
    """Owner path (`apm-admin deploy`): build this checkout and deploy it."""
    with tempfile.TemporaryDirectory() as tmp:
        build_artifact(tmp, log=log)
        return deploy_artifact(tmp, domain, owner_emails, workos_client_id, stage=stage, profile=profile,
                               region=region, log=log)


def destroy(stage, profile=None, region="us-east-1", expected_account=None, log=print):
    """Tear down a preview stage and everything it retained: agent roles, the stack, then explicitly
    its table and log group if they outlived the stack, its SSM parameters and its deploy records.
    Refuses prod, dev and anything that isn't exactly pr-<number>, before touching AWS."""
    try:
        stage = policy.cleanup_stage(stage)
    except ValueError as e:
        raise SystemExit(str(e)) from None
    import boto3

    n = policy.Names(stage)
    s = boto3.Session(profile_name=profile, region_name=region)
    account = s.client("sts").get_caller_identity()["Account"]
    if expected_account and account != str(expected_account):
        raise SystemExit(f"refusing to destroy: credentials are for account {account}, expected {expected_account}")

    # Agent roles are created by the broker, outside the stack, and keep the boundary attached;
    # they must go first or the stack can't delete the boundary policy.
    iam = s.client("iam")
    for page in iam.get_paginator("list_roles").paginate(PathPrefix=n.role_path):
        for role in page["Roles"]:
            name = role["RoleName"]
            if role["Path"] != n.role_path or not name.startswith(n.role_prefix):
                continue
            for p in iam.list_role_policies(RoleName=name)["PolicyNames"]:
                iam.delete_role_policy(RoleName=name, PolicyName=p)
            for p in iam.list_attached_role_policies(RoleName=name)["AttachedPolicies"]:
                iam.detach_role_policy(RoleName=name, PolicyArn=p["PolicyArn"])
            iam.delete_role(RoleName=name)
            log(f"Deleted agent role {name}")

    cfn = s.client("cloudformation")
    try:
        cfn.describe_stacks(StackName=n.stack)
    except cfn.exceptions.ClientError:
        log(f"Stack {n.stack} does not exist")
    else:
        cfn.delete_stack(StackName=n.stack)
        log(f"Deleting stack {n.stack}…")
        try:
            cfn.get_waiter("stack_delete_complete").wait(StackName=n.stack,
                                                         WaiterConfig={"Delay": 10, "MaxAttempts": 180})
        except Exception:
            _log_failures(cfn, n.stack, log)
            raise SystemExit("Stack delete failed; see the errors above.")

    # Retained data, handled explicitly: a table or log group left behind (an older template with
    # DeletionPolicy Retain, or Lambda recreating its log group) would otherwise outlive the preview.
    ddb = s.client("dynamodb")
    try:
        ddb.delete_table(TableName=n.table)
        log(f"Deleted leftover table {n.table}")
    except ddb.exceptions.ResourceNotFoundException:
        pass
    logs = s.client("logs")
    try:
        logs.delete_log_group(logGroupName=f"/aws/lambda/{n.function}")
        log(f"Deleted leftover log group /aws/lambda/{n.function}")
    except logs.exceptions.ResourceNotFoundException:
        pass
    # Deploy records of this stage in the shared preview bucket (bundles there expire by lifecycle).
    s3 = s.client("s3")
    bucket = n.artifact_bucket(account, region)
    try:
        for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket, Prefix=f"deployments/{n.stage}/"):
            keys = [{"Key": o["Key"]} for o in page.get("Contents", [])]
            if keys:
                s3.delete_objects(Bucket=bucket, Delete={"Objects": keys})
    except s3.exceptions.NoSuchBucket:
        pass

    ssm = s.client("ssm")
    names = [p["Name"] for page in ssm.get_paginator("get_parameters_by_path").paginate(
        Path=n.param_prefix, Recursive=True) for p in page["Parameters"]]
    for i in range(0, len(names), 10):
        ssm.delete_parameters(Names=names[i:i + 10])
    if names:
        log(f"Deleted {len(names)} parameters under {n.param_prefix}")
    log(f"Destroyed stage {n.stage}")


def smoke(url, attempts=30, delay=10, log=print):
    """Check a deployed stage answers: /healthz says ok and the web app manifest is served."""
    url = url.rstrip("/")
    last = None
    for i in range(attempts):
        try:
            with urllib.request.urlopen(f"{url}/healthz", timeout=10) as r:
                if json.loads(r.read()).get("ok") is not True:
                    raise RuntimeError("/healthz did not report ok")
            with urllib.request.urlopen(f"{url}/manifest.webmanifest", timeout=10) as r:
                manifest = json.loads(r.read())
                if r.status != 200 or "name" not in manifest:
                    raise RuntimeError("/manifest.webmanifest is not a web app manifest")
            log(f"Smoke test passed: {url}")
            return
        except (OSError, urllib.error.URLError, ValueError, RuntimeError) as e:
            last = e
            if i + 1 < attempts:
                time.sleep(delay)
    raise SystemExit(f"Smoke test failed for {url}: {last}")


def load_settings():
    return json.loads(SETTINGS_FILE.read_text()) if SETTINGS_FILE.exists() else {}


def save_settings(settings):
    SETTINGS_FILE.parent.mkdir(parents=True, exist_ok=True)
    SETTINGS_FILE.write_text(json.dumps(settings, indent=2) + "\n")
