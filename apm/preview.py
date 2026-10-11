"""Preview lifecycle decisions: which PR, which commit, deploy or remove, and what the sweeper deletes.

Runs in the trusted preview workflow, from reviewed main, never from PR code. It reads the event
payload as JSON and the GitHub API (through an injected `api` callable), never shell-interpolated
PR text, and returns only validated values: a PR number, a 40-hex head sha, a CI run id and a stage
that passed policy.cleanup_stage. The deploy job then uses the artifact CI built for that exact sha.
"""
import datetime as dt
import json
import re
import subprocess

from . import deploy, policy

LABEL = "preview"
CI_WORKFLOW_PATH = ".github/workflows/ci.yml"
PR_RE = re.compile(r"[1-9][0-9]{0,6}", re.ASCII)
SHA_RE = re.compile(r"[0-9a-f]{40}", re.ASCII)


class PlanError(ValueError):
    pass


def gh_api(path):
    """GET a GitHub API path with the gh CLI (GH_TOKEN from the workflow)."""
    return json.loads(subprocess.run(["gh", "api", path], check=True, capture_output=True, text=True).stdout)


def _pr_number(value):
    value = str(value)
    if not PR_RE.fullmatch(value):
        raise PlanError(f"invalid PR number {value!r}")
    return int(value)


def _labels(pr):
    return {label.get("name") for label in pr.get("labels") or []}


def _same_repo(pr, repo):
    head_repo = (pr.get("head") or {}).get("repo") or {}
    return head_repo.get("full_name") == repo and (pr.get("base") or {}).get("repo", {}).get("full_name") == repo


def _plan(action, pr, reason, head_sha="", ci_run_id=""):
    stage = policy.cleanup_stage(f"pr-{pr}") if pr else ""
    return {"action": action, "pr": str(pr or ""), "stage": stage, "head_sha": head_sha,
            "ci_run_id": str(ci_run_id), "reason": reason}


def find_ci_run(api, repo, head_sha):
    """The newest successful pull_request CI run for exactly this head sha, or None."""
    runs = api(f"repos/{repo}/actions/workflows/ci.yml/runs?head_sha={head_sha}&event=pull_request"
               "&status=success&per_page=20").get("workflow_runs", [])
    runs = [r for r in runs if r.get("head_sha") == head_sha and r.get("conclusion") == "success"
            and r.get("path") == CI_WORKFLOW_PATH and (r.get("head_repository") or {}).get("full_name") == repo]
    return max(runs, key=lambda r: r["id"])["id"] if runs else None


def plan(event_name, event, repo, api, dispatch_pr=None, dispatch_action=None):
    """Decide what the preview workflow does. Returns a dict (action deploy|remove|none)."""
    if event_name == "workflow_run":
        run = event.get("workflow_run") or {}
        if run.get("conclusion") != "success" or run.get("event") != "pull_request" \
                or run.get("path") != CI_WORKFLOW_PATH:
            return _plan("none", None, "not a successful pull_request CI run")
        if (run.get("head_repository") or {}).get("full_name") != repo:
            return _plan("none", None, "CI run is from a fork; previews are same-repository only")
        head_sha = run.get("head_sha", "")
        prs = [p for p in run.get("pull_requests") or [] if (p.get("head") or {}).get("sha") == head_sha]
        if len(prs) != 1:
            return _plan("none", None, "CI run is not for exactly one open PR head")
        number = _pr_number(prs[0].get("number"))
        ci_run_id = run.get("id")
    elif event_name == "pull_request_target":
        number = _pr_number((event.get("pull_request") or {}).get("number"))
        action = event.get("action")
        label = (event.get("label") or {}).get("name")
        if action == "closed":
            if LABEL in _labels(event.get("pull_request") or {}):
                return _plan("remove", number, "PR closed")
            return _plan("none", number, "closed PR had no preview")
        if action == "unlabeled" and label == LABEL:
            return _plan("remove", number, "preview label removed")
        if action != "labeled" or label != LABEL:
            return _plan("none", number, f"ignored {action} event")
        ci_run_id = None
    elif event_name == "workflow_dispatch":
        number = _pr_number(dispatch_pr)
        if dispatch_action == "remove":
            return _plan("remove", number, "maintainer dispatch")
        if dispatch_action != "deploy":
            raise PlanError(f"unknown dispatch action {dispatch_action!r}")
        ci_run_id = None
    else:
        return _plan("none", None, f"event {event_name} does not deploy previews")

    # Live PR state from the API, not the (possibly stale) event payload.
    pr = api(f"repos/{repo}/pulls/{number}")
    if not _same_repo(pr, repo):
        return _plan("none", number, "fork PR: previews are same-repository only")
    if pr.get("state") != "open":
        return _plan("remove", number, "PR is closed")
    if event_name != "workflow_dispatch" and LABEL not in _labels(pr):
        return _plan("none", number, f"PR has no {LABEL!r} label")
    head_sha = (pr.get("head") or {}).get("sha", "")
    if not SHA_RE.fullmatch(head_sha):
        raise PlanError("PR head sha is malformed")
    if event_name == "workflow_run" and event["workflow_run"].get("head_sha") != head_sha:
        return _plan("none", number, "PR head moved on; the newer commit's CI run will deploy it")
    if ci_run_id is None:
        ci_run_id = find_ci_run(api, repo, head_sha)
        if ci_run_id is None:
            return _plan("none", number, "CI has not succeeded for the PR head yet; it deploys when CI passes")
    if not re.fullmatch(r"[1-9][0-9]{0,19}", str(ci_run_id), re.ASCII):
        raise PlanError("CI run id is malformed")
    return _plan("deploy", number, "checks passed for the PR head", head_sha, ci_run_id)


# ---------- sweeper ----------

def _parse_time(value):
    try:
        return dt.datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=dt.timezone.utc)
    except (TypeError, ValueError):
        return None


def sweep_decisions(stacks, pr_info, now):
    """stacks: [{"StackName", "StackStatus", "Tags": [...]}] from describe_stacks.
    pr_info(number) -> (state, labeled). Returns [(stage, reason)] to delete. Only stacks whose name
    AND stage tag both name the same preview stage are ever candidates; everything else is ignored."""
    out = []
    for stack in stacks:
        try:
            stage = policy.stage_from_stack(stack.get("StackName"))
        except ValueError:
            continue
        tags = {t.get("Key"): t.get("Value") for t in stack.get("Tags") or []}
        try:
            if policy.cleanup_stage(tags.get(deploy.STAGE_TAG)) != stage:
                continue
        except ValueError:
            continue  # untagged or mis-tagged: never delete on a guess
        if str(stack.get("StackStatus", "")).endswith("_IN_PROGRESS"):
            continue  # a deploy or delete is running; next sweep
        expires = _parse_time(tags.get(deploy.EXPIRES_TAG))
        state, labeled = pr_info(int(stage[3:]))
        if state != "open":
            out.append((stage, f"PR is {state}"))
        elif not labeled:
            out.append((stage, f"no {LABEL!r} label"))
        elif expires is None:
            out.append((stage, "missing or malformed expiry tag"))
        elif expires <= now:
            out.append((stage, f"expired at {tags[deploy.EXPIRES_TAG]}"))
    return out


def gh_unlabel(repo, number, reason):
    """Drop the opt-in label (so a later CI run doesn't redeploy) and say why. GITHUB_TOKEN edits
    don't trigger another workflow run."""
    subprocess.run(["gh", "pr", "edit", str(number), "--repo", repo, "--remove-label", LABEL], check=False)
    subprocess.run(["gh", "pr", "comment", str(number), "--repo", repo, "--body",
                    f"Preview `pr-{number}` was deleted by the daily sweep ({reason}). "
                    f"Add the `{LABEL}` label to deploy it again."], check=False)


def sweep(repo, api=gh_api, unlabel=gh_unlabel, region="us-east-1", profile=None, expected_account=None,
          dry_run=False, log=print):
    import boto3

    s = boto3.Session(profile_name=profile, region_name=region)
    account = s.client("sts").get_caller_identity()["Account"]
    if expected_account and account != str(expected_account):
        raise SystemExit(f"refusing to sweep: credentials are for account {account}, expected {expected_account}")
    stacks = [st for page in s.client("cloudformation").get_paginator("describe_stacks").paginate()
              for st in page["Stacks"]]

    def pr_info(number):
        try:
            pr = api(f"repos/{repo}/pulls/{number}")
        except Exception:
            return "unknown", False
        return pr.get("state", "unknown"), LABEL in _labels(pr)

    decisions = sweep_decisions(stacks, pr_info, dt.datetime.now(dt.timezone.utc))
    failed = []
    for stage, reason in decisions:
        log(f"{'would delete' if dry_run else 'deleting'} {stage}: {reason}")
        if dry_run:
            continue
        number = int(stage[3:])
        if pr_info(number) == ("open", True):
            unlabel(repo, number, reason)
        try:
            deploy.destroy(stage, profile=profile, region=region, expected_account=account, log=log)
        except (SystemExit, Exception) as e:  # keep sweeping the others
            log(f"failed to delete {stage}: {e}")
            failed.append(stage)
    return decisions, failed
