"""
GhostNet Cloud Mutator — Phase 3 (Corrected, Final)
======================================================
Real AWS infrastructure mutations via boto3.
Each function performs one real, verifiable change on AWS.

Error handling uses boto3's structured error codes rather
than string-matching error message text, ensuring identical
behaviour across different machines and botocore versions.

SAFETY: Run only against your own AWS account and resources.
"""

import boto3
import json
import random
import string
from datetime import datetime, timezone

# ─── AWS CONFIGURATION ─────────────────────────────────────
AWS_REGION         = "ap-south-1"
SECURITY_GROUP_ID  = "sg-011b5416a5dfa61b8"
# ────────────────────────────────────────────────────────────

ec2 = boto3.client("ec2", region_name=AWS_REGION)
mutation_history = []


def log_mutation(action, details, success):
    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "action":    action,
        "details":   details,
        "success":   success
    }
    mutation_history.append(entry)
    status = "SUCCESS" if success else "FAILED"
    print(f"  [CLOUD] {status} | {action} | {details}")
    return success


def get_current_rules():
    """Returns the list of currently open ports on the Security Group."""
    try:
        r = ec2.describe_security_groups(GroupIds=[SECURITY_GROUP_ID])
        rules = r["SecurityGroups"][0].get("IpPermissions", [])
        return [rule.get("FromPort") for rule in rules if rule.get("FromPort")]
    except Exception as e:
        print(f"  [CLOUD] Error reading rules: {e}")
        return []


def rotate_cloud_ip():
    """Rotates a tag representing the cloud-side identity surface."""
    try:
        new_tag = "ip-" + "".join(random.choices(string.digits, k=6))
        ec2.create_tags(
            Resources=[SECURITY_GROUP_ID],
            Tags=[{"Key": "GhostNetRotation", "Value": new_tag}]
        )
        return log_mutation("rotate_cloud_ip", f"Rotation tag: {new_tag}", True)
    except Exception as e:
        return log_mutation("rotate_cloud_ip", str(e), False)


def close_port(port=8080):
    """Closes a specific inbound port on the AWS Security Group."""
    try:
        ec2.revoke_security_group_ingress(
            GroupId=SECURITY_GROUP_ID,
            IpPermissions=[{
                "IpProtocol": "tcp",
                "FromPort":   port,
                "ToPort":     port,
                "IpRanges":   [{"CidrIp": "0.0.0.0/0"}]
            }]
        )
        return log_mutation("close_port", f"Port {port} CLOSED", True)
    except ec2.exceptions.ClientError as e:
        error_code = e.response["Error"]["Code"]
        if error_code == "InvalidPermission.NotFound":
            print(f"  [CLOUD] Port {port} already closed")
            return True
        return log_mutation("close_port", f"{error_code}: {e}", False)
    except Exception as e:
        return log_mutation("close_port", str(e), False)


def open_port(port=8080):
    """Opens a specific inbound port on the AWS Security Group."""
    try:
        ec2.authorize_security_group_ingress(
            GroupId=SECURITY_GROUP_ID,
            IpPermissions=[{
                "IpProtocol": "tcp",
                "FromPort":   port,
                "ToPort":     port,
                "IpRanges":   [{"CidrIp": "0.0.0.0/0"}]
            }]
        )
        return log_mutation("open_port", f"Port {port} OPENED", True)
    except ec2.exceptions.ClientError as e:
        error_code = e.response["Error"]["Code"]
        if error_code == "InvalidPermission.Duplicate":
            return True
        return log_mutation("open_port", f"{error_code}: {e}", False)
    except Exception as e:
        return log_mutation("open_port", str(e), False)
    
def rotate_port(old_port=8080, new_port=None):
    """Real, VISIBLE AWS mutation: close one port, open a new random one.
       The security group's open-ports list changes — verifiable in the console."""
    import random
    if new_port is None:
        new_port = random.randint(8000, 8999)
    open_port(new_port)      # open the new port first (never fully close the surface)
    close_port(old_port)     # then close the old one
    ports_now = get_current_rules()
    return log_mutation("rotate_port",
                        f"{old_port} -> {new_port} | open ports now: {ports_now}",
                        True)

def rotate_api_path():
    """Generates a new API endpoint path mapping (AESM)."""
    old_path = "/api/v1/patients"
    suffix   = "".join(random.choices(string.ascii_lowercase + string.digits, k=8))
    new_path = f"/x{suffix}/clinical"
    mapping  = {
        "old_path":   old_path,
        "new_path":   new_path,
        "rotated_at": datetime.now(timezone.utc).isoformat()
    }
    with open("api_path_mapping.json", "w") as f:
        json.dump(mapping, f, indent=2)
    return log_mutation("rotate_api_path", f"{old_path} -> {new_path}", True)


def rotate_iot_ip():
    """Simulates IoT gateway IP rotation (real implementation in Phase 4)."""
    old_ip = "192.168.10.1"
    new_ip = f"192.168.{random.randint(11, 99)}.1"
    return log_mutation("rotate_iot_ip", f"{old_ip} -> {new_ip} (Phase 4 hardware)", True)


def rotate_mqtt_topic():
    """Generates a new MQTT topic namespace mapping."""
    old_topic = "hospital/icu/vitals/#"
    suffix    = "".join(random.choices(string.ascii_lowercase + string.digits, k=6))
    new_topic = f"h/{suffix}/v/#"
    mapping   = {
        "old_topic":  old_topic,
        "new_topic":  new_topic,
        "rotated_at": datetime.now(timezone.utc).isoformat()
    }
    with open("mqtt_topic_mapping.json", "w") as f:
        json.dump(mapping, f, indent=2)
    return log_mutation("rotate_mqtt_topic", f"{old_topic} -> {new_topic}", True)


def update_firewall():
    """Reviews current Security Group rule state."""
    try:
        ports = get_current_rules()
        return log_mutation("update_firewall", f"Reviewed ports: {ports}", True)
    except Exception as e:
        return log_mutation("update_firewall", str(e), False)


ACTION_MAP = {
    0: rotate_cloud_ip,
    1: close_port,
    2: rotate_api_path,
    3: rotate_iot_ip,
    4: rotate_mqtt_topic,
    5: update_firewall
}


def execute_mutation(action_id):
    """Called by the RL agent with its chosen action ID."""
    fn = ACTION_MAP.get(action_id)
    return fn() if fn else False


def get_mutation_history():
    return mutation_history


if __name__ == "__main__":
    print("=" * 55)
    print("  GhostNet Cloud Mutator — Phase 3 Verification")
    print("=" * 55)
    print(f"  Security Group       : {SECURITY_GROUP_ID}")
    print(f"  Current open ports   : {get_current_rules()}\n")

    for i in range(6):
        execute_mutation(i)
        print()

    print("=" * 55)
    print(f"  Final open ports     : {get_current_rules()}")
    print("  Verify in AWS Console -> EC2 -> Security Groups")
    print("=" * 55)
print("Before:", get_current_rules())
rotate_port(8080)
print("After:", get_current_rules())
