import hashlib
import ipaddress
import json
import logging
import os
import urllib.request
import urllib.parse
import boto3
from datetime import datetime, timezone, timedelta

log = logging.getLogger()
log.setLevel(logging.INFO)

CF_API = "https://api.cloudflare.com/client/v4"
DRAINING_TTL = timedelta(minutes=5)


def cf_token():
    log.info("fetching CF API token from SSM: %s", os.environ["CF_API_TOKEN_SSM_PATH"])
    ssm = boto3.client("ssm", region_name=os.environ["AWS_REGION"])
    value = ssm.get_parameter(
        Name=os.environ["CF_API_TOKEN_SSM_PATH"], WithDecryption=True
    )["Parameter"]["Value"]
    log.info("CF API token fetched")
    return value


def cf(method, path, token, body=None):
    log.info("CF %s %s body=%s", method, path, json.dumps(body) if body else None)
    req = urllib.request.Request(
        f"{CF_API}{path}",
        data=json.dumps(body).encode() if body else None,
        headers={"Authorization": f"Bearer {token}",
                 "Content-Type": "application/json"},
        method=method,
    )
    try:
        with urllib.request.urlopen(req) as r:
            result = json.loads(r.read())["result"]
    except urllib.error.HTTPError as e:
        error_body = e.read().decode()
        log.error("CF %s %s -> HTTP %d: %s", method, path, e.code, error_body)
        raise
    log.info("CF %s %s -> %s", method, path, json.dumps(result))
    return result


def instance_ipv6(instance_id):
    log.info("looking up IPv6 for instance %s", instance_id)
    ec2 = boto3.client("ec2", region_name=os.environ["AWS_REGION"])
    inst = ec2.describe_instances(InstanceIds=[instance_id])[
        "Reservations"][0]["Instances"][0]
    for iface in inst.get("NetworkInterfaces", []):
        for addr in iface.get("Ipv6Addresses", []):
            log.info("found IPv6 %s for instance %s", addr["Ipv6Address"], instance_id)
            return addr["Ipv6Address"]
    raise ValueError(f"no IPv6 address found for {instance_id}")


def asg_instances(asg_name, exclude_id=None):
    """Return list of (instance_id, ipv6) for all running/pending ASG instances."""
    log.info("querying ASG instances for %s (excluding %s)", asg_name, exclude_id)
    ec2 = boto3.client("ec2", region_name=os.environ["AWS_REGION"])
    paginator = ec2.get_paginator("describe_instances")
    instances = []
    for page in paginator.paginate(Filters=[
        {"Name": "tag:aws:autoscaling:groupName", "Values": [asg_name]},
        {"Name": "instance-state-name", "Values": ["running", "pending"]},
    ]):
        for r in page["Reservations"]:
            for inst in r["Instances"]:
                if inst["InstanceId"] == exclude_id:
                    continue
                for iface in inst.get("NetworkInterfaces", []):
                    for addr in iface.get("Ipv6Addresses", []):
                        instances.append((inst["InstanceId"], addr["Ipv6Address"]))
    log.info("found %d ASG instances: %s", len(instances), instances)
    return instances


def node_hostname(ip, zone_name):
    """Derive node hostname from the first 4 bytes of SHA-256(canonical IP).
    Matches the derivation in cmd/server/main.go ipNodeURL().
    e.g. node-a1b2c3d4.peerwave.ai"""
    canonical = str(ipaddress.ip_address(ip))
    prefix = hashlib.sha256(canonical.encode()).hexdigest()[:8]
    return f"node-{prefix}.{zone_name}"


def get_records(zone_id, token, **filters):
    """Fetch up to 100 DNS records matching the given filters."""
    qs = "&".join(f"{urllib.parse.quote(k)}={urllib.parse.quote(str(v))}"
                  for k, v in filters.items())
    qs = f"&{qs}&per_page=100" if qs else "?per_page=100"
    records = cf("GET", f"/zones/{zone_id}/dns_records?{qs}", token) or []
    log.info("found %d records matching %s", len(records), filters)
    return records


def set_domain_records(zone_id, token, domain, ips, comment):
    """Atomically replace all AAAA records for domain with exactly the given IPs."""
    existing = get_records(zone_id, token, name=domain, type="AAAA")
    body = {
        "deletes": [{"id": r["id"]} for r in existing],
        "posts": [
            {"type": "AAAA", "name": domain, "content": ip,
             "proxied": True, "ttl": 1, "comment": comment}
            for ip in ips
        ],
    }
    log.info("batch update %s: deleting %d, posting %d records",
             domain, len(body["deletes"]), len(body["posts"]))
    cf("POST", f"/zones/{zone_id}/dns_records/batch", token, body)


def cleanup_draining(zone_id, token):
    """Delete draining CNAME records that have been stale for more than 5 minutes."""
    now = datetime.now(timezone.utc)
    records = get_records(zone_id, token, type="CNAME", **{"comment.startswith": "draining:"})
    for rec in records:
        modified = datetime.fromisoformat(rec["modified_on"])
        age = now - modified
        if age > DRAINING_TTL:
            log.info("deleting stale draining record %s (age=%s)", rec["name"], age)
            cf("DELETE", f"/zones/{zone_id}/dns_records/{rec['id']}", token)
        else:
            log.info("draining record %s is only %s old, leaving it", rec["name"], age)


def complete_hook(detail):
    log.info("completing lifecycle hook %s with CONTINUE", detail["LifecycleHookName"])
    boto3.client("autoscaling", region_name=os.environ["AWS_REGION"]).complete_lifecycle_action(
        LifecycleHookName=detail["LifecycleHookName"],
        AutoScalingGroupName=detail["AutoScalingGroupName"],
        LifecycleActionToken=detail["LifecycleActionToken"],
        LifecycleActionResult="CONTINUE",
    )
    log.info("lifecycle hook completed")


def reconcile(asg_name):
    """Reconcile DNS to match current ASG state. Safe to run at any time."""
    zone_id = os.environ["CF_ZONE_ID"]
    domain = os.environ["CF_DOMAIN"]
    zone_name = os.environ["CF_ZONE_NAME"]

    token = cf_token()
    instances = asg_instances(asg_name)
    active_ips = [ip for _, ip in instances]
    log.info("reconciling %d active instances: %s", len(instances), instances)

    set_domain_records(zone_id, token, domain, active_ips, "signaling-round-robin")

    for inst_id, inst_ip in instances:
        inst_node = node_hostname(inst_ip, zone_name)
        if not get_records(zone_id, token, name=inst_node, type="AAAA", content=inst_ip):
            cf("POST", f"/zones/{zone_id}/dns_records", token, {
                "type": "AAAA", "name": inst_node, "content": inst_ip,
                "proxied": True, "ttl": 1,
                "comment": f"signaling-node:{inst_id}",
            })

    cleanup_draining(zone_id, token)


def handler(event, context):
    detail = event["detail"]
    instance_id = detail["EC2InstanceId"]
    asg_name = detail["AutoScalingGroupName"]
    is_launch = "LAUNCHING" in detail["LifecycleTransition"]
    zone_id = os.environ["CF_ZONE_ID"]
    domain = os.environ["CF_DOMAIN"]
    zone_name = os.environ["CF_ZONE_NAME"]

    log.info("event: instance=%s asg=%s transition=%s",
             instance_id, asg_name, detail["LifecycleTransition"])

    try:
        token = cf_token()
    except Exception as e:
        log.error("failed to fetch CF token: %s", e)
        complete_hook(detail)
        return

    try:
        ip = instance_ipv6(instance_id)
    except Exception as e:
        log.error("failed to get instance IPv6: %s", e)
        complete_hook(detail)
        return

    node_name = node_hostname(ip, zone_name)

    # Build the authoritative set of active instances.
    # Exclude the terminating instance on scale-down; include the new instance
    # on scale-up even if EC2 doesn't yet show it as "running".
    try:
        instances = asg_instances(asg_name, exclude_id=None if is_launch else instance_id)
        if is_launch and ip not in [i for _, i in instances]:
            instances.append((instance_id, ip))
    except Exception as e:
        log.error("failed to get ASG instances: %s", e)
        complete_hook(detail)
        return

    active_ips = [i for _, i in instances]

    # 1. Set main domain round-robin to exactly the active instance set.
    try:
        set_domain_records(zone_id, token, domain, active_ips, "signaling-round-robin")
    except Exception as e:
        log.error("failed to set domain round-robin for %s: %s", domain, e)

    # 2. Ensure a node-specific AAAA record exists for every active instance.
    for inst_id, inst_ip in instances:
        inst_node = node_hostname(inst_ip, zone_name)
        try:
            if not get_records(zone_id, token, name=inst_node, type="AAAA", content=inst_ip):
                cf("POST", f"/zones/{zone_id}/dns_records", token, {
                    "type": "AAAA", "name": inst_node, "content": inst_ip,
                    "proxied": True, "ttl": 1,
                    "comment": f"signaling-node:{inst_id}",
                })
        except Exception as e:
            log.error("failed to ensure node record %s: %s", inst_node, e)

    # 3. On scale-down: flip the terminating node's record to a CNAME so cached
    #    clients following the redirect land on an active node.
    if not is_launch:
        try:
            records = get_records(zone_id, token, name=node_name, type="AAAA")
            if records:
                cf("PUT", f"/zones/{zone_id}/dns_records/{records[0]['id']}", token, {
                    "type": "CNAME", "name": node_name, "content": domain,
                    "proxied": True, "ttl": 1,
                    "comment": f"draining:{instance_id}",
                })
            else:
                log.warning("no AAAA record found for %s, skipping CNAME flip", node_name)
        except Exception as e:
            log.error("failed to flip node record %s to CNAME: %s", node_name, e)

    # 4. Remove draining CNAME records that have been around for more than 5 minutes.
    try:
        cleanup_draining(zone_id, token)
    except Exception as e:
        log.error("failed to clean up draining records: %s", e)

    complete_hook(detail)


if __name__ == "__main__":
    import argparse
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    p = argparse.ArgumentParser(description="Reconcile Cloudflare DNS to current ASG state")
    p.add_argument("--asg-name", required=True, help="Auto Scaling Group name")
    args = p.parse_args()
    reconcile(args.asg_name)
