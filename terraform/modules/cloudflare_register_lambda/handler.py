import json
import logging
import os
import urllib.request
import urllib.parse
import boto3

log = logging.getLogger()
log.setLevel(logging.INFO)

CF_API = "https://api.cloudflare.com/client/v4"


def cf_token():
    ssm = boto3.client("ssm", region_name=os.environ["AWS_REGION"])
    value = ssm.get_parameter(
        Name=os.environ["CF_API_TOKEN_SSM_PATH"], WithDecryption=True
    )["Parameter"]["Value"]
    return value


def cf(method, path, token, body=None):
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
    ec2 = boto3.client("ec2", region_name=os.environ["AWS_REGION"])
    inst = ec2.describe_instances(InstanceIds=[instance_id])[
        "Reservations"][0]["Instances"][0]
    for iface in inst.get("NetworkInterfaces", []):
        for addr in iface.get("Ipv6Addresses", []):
            log.info("found IPv6 %s for instance %s",
                     addr["Ipv6Address"], instance_id)
            return addr["Ipv6Address"]
    raise ValueError(f"no IPv6 address found for {instance_id}")


def asg_active_ips(asg_name):
    """Return dict of instance_id -> IPv6 for all running/pending ASG instances."""
    ec2 = boto3.client("ec2", region_name=os.environ["AWS_REGION"])
    paginator = ec2.get_paginator("describe_instances")
    instances = {}
    for page in paginator.paginate(Filters=[
        {"Name": "tag:aws:autoscaling:groupName", "Values": [asg_name]},
        {"Name": "instance-state-name", "Values": ["running", "pending"]},
    ]):
        for r in page["Reservations"]:
            for inst in r["Instances"]:
                for iface in inst.get("NetworkInterfaces", []):
                    for addr in iface.get("Ipv6Addresses", []):
                        instances[inst["InstanceId"]] = addr["Ipv6Address"]
    log.info("found %d active instances: %s", len(instances), instances)
    return instances


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


def complete_hook(detail):
    log.info("completing lifecycle hook %s with CONTINUE",
             detail["LifecycleHookName"])
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

    token = cf_token()
    instances = asg_active_ips(asg_name)
    log.info("reconciling domain %s to %d active IPs: %s",
             domain, len(instances), instances)

    set_domain_records(zone_id, token, domain, list(
        instances.values()), "signaling-round-robin")


def handler(event, context):
    detail = event["detail"]
    instance_id = detail["EC2InstanceId"]
    asg_name = detail["AutoScalingGroupName"]
    is_launch = "LAUNCHING" in detail["LifecycleTransition"]
    zone_id = os.environ["CF_ZONE_ID"]
    domain = os.environ["CF_DOMAIN"]

    log.info("event: instance=%s asg=%s transition=%s",
             instance_id, asg_name, detail["LifecycleTransition"])

    try:
        token = cf_token()
    except Exception as e:
        log.error("failed to fetch CF token: %s", e)
        complete_hook(detail)
        return

    # Build the authoritative set of active IPs.
    # On scale-down, remove the terminating instance. On scale-up, add the
    # launching instance even if EC2 doesn't yet show it as "running".
    try:
        instances = asg_active_ips(asg_name)
    except Exception as e:
        log.error("failed to get ASG instances: %s", e)
        complete_hook(detail)
        return

    if is_launch:
        try:
            ip = instance_ipv6(instance_id)
            instances[instance_id] = ip
        except Exception as e:
            log.error("failed to get instance IPv6: %s", e)
            complete_hook(detail)
            return
    else:
        instances.pop(instance_id, None)

    try:
        set_domain_records(zone_id, token, domain, list(
            instances.values()), "signaling-round-robin")
    except Exception as e:
        log.error("failed to set domain records for %s: %s", domain, e)

    complete_hook(detail)


if __name__ == "__main__":
    import argparse
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    p = argparse.ArgumentParser(
        description="Reconcile Cloudflare DNS to current ASG state")
    p.add_argument("--asg-name", required=True, help="Auto Scaling Group name")
    args = p.parse_args()
    reconcile(args.asg_name)
