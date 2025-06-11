import csv
import json
import boto3
import requests
import pandas as pd
from botocore.exceptions import ClientError

# Cyera API Configuration
BASE_URL = "https://api.cyera.io"
AUTH_ENDPOINT = "/v1/login"
DATASTORES_ENDPOINT = "/v2/datastores"
LIMIT = 100

# File paths
DATASTORES_CSV = "aws_datastores_filtered.csv"
FINDINGS_FILE = "finding-details.csv"
ENRICHED_FINDINGS_FILE = "finding-details-enriched.csv"
PERMISSIONS_MATRIX_FILE = "permissions_matrix.csv"
LOG_FILE = "unmatched_snapshots.log"

def get_credentials_from_secrets_manager(secret_name="cyera_tenant", region_name="us-east-1"):
    client = boto3.client("secretsmanager", region_name=region_name)
    try:
        response = client.get_secret_value(SecretId=secret_name)
        secret = json.loads(response["SecretString"])
        return secret["CLIENT_ID"], secret["CLIENT_SECRET"]
    except ClientError as e:
        print(f"❌ Failed to retrieve secret: {e}")
        return None, None

def get_jwt_token(client_id, client_secret):
    response = requests.post(f"{BASE_URL}{AUTH_ENDPOINT}", json={"clientId": client_id, "secret": client_secret})
    if response.status_code == 200:
        return response.json().get("jwt")
    print(f"❌ Authentication failed: {response.status_code} - {response.text}")
    return None

def get_all_datastores(jwt_token):
    offset = 0
    datastores = []
    headers = {"Authorization": f"Bearer {jwt_token}"}
    while True:
        resp = requests.get(f"{BASE_URL}{DATASTORES_ENDPOINT}", headers=headers, params={"limit": LIMIT, "offset": offset})
        if resp.status_code != 200:
            raise Exception(f"❌ Error fetching datastores: {resp.text}")
        chunk = resp.json().get("results", [])
        if not chunk:
            break
        datastores.extend(chunk)
        offset += LIMIT
    return datastores

def write_filtered_aws_datastores(datastores):
    fields = ["name", "engine", "account", "arn", "sensitivity", "sensitivityDisplayName"]
    aws_ds = [ds for ds in datastores if ds.get("provider") == "AWS"]
    with open(DATASTORES_CSV, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        for ds in aws_ds:
            writer.writerow({k: ds.get(k, "") for k in fields})
    print(f"✅ AWS datastores saved to {DATASTORES_CSV}")

def enrich_findings():
    rds = boto3.client("rds", region_name="us-east-1")
    sts = boto3.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    df = pd.read_csv(FINDINGS_FILE)
    df["sourceDbArn"] = ""
    df["snapshotCreatedAt"] = ""
    failures, success_count = [], 0

    for i, row in df.iterrows():
        rtype, res_arn = row.get("resourceType"), row.get("resource")
        if rtype not in ["AWS::RDS::DBSnapshot", "AWS::RDS::DBClusterSnapshot"]:
            continue

        snapshot_id = res_arn.split(":")[-1]
        try:
            if rtype == "AWS::RDS::DBSnapshot":
                try:
                    snap = rds.describe_db_snapshots(DBSnapshotIdentifier=res_arn)["DBSnapshots"][0]
                except:
                    snap = rds.describe_db_snapshots(DBSnapshotIdentifier=snapshot_id)["DBSnapshots"][0]
                db_id = snap.get("DBInstanceIdentifier")
                timestamp = snap.get("SnapshotCreateTime")
                df.at[i, "sourceDbArn"] = f"arn:aws:rds:us-east-1:{account_id}:db:{db_id}"
                df.at[i, "snapshotCreatedAt"] = timestamp

            elif rtype == "AWS::RDS::DBClusterSnapshot":
                try:
                    snap = rds.describe_db_cluster_snapshots(DBClusterSnapshotIdentifier=res_arn)["DBClusterSnapshots"][0]
                except:
                    snap = rds.describe_db_cluster_snapshots(DBClusterSnapshotIdentifier=snapshot_id)["DBClusterSnapshots"][0]
                cluster_id = snap.get("DBClusterIdentifier")
                timestamp = snap.get("SnapshotCreateTime")
                df.at[i, "sourceDbArn"] = f"arn:aws:rds:us-east-1:{account_id}:cluster:{cluster_id}"
                df.at[i, "snapshotCreatedAt"] = timestamp

            success_count += 1

        except Exception as e:
            failures.append(f"{rtype} | {res_arn} | {str(e)}")

    # Ensure sourceDbArn contains only empty strings, not NaNs
    df["sourceDbArn"] = df["sourceDbArn"].fillna("").astype(str)
    
    # Save enriched file
    df.to_csv(ENRICHED_FINDINGS_FILE, index=False)

    # Save log
    with open(LOG_FILE, "w") as log:
        log.write("\n".join(failures))

    print(f"✅ Enrichment complete: {success_count} successes, {len(failures)} failures.")

def merge_and_generate_matrix():
    findings_df = pd.read_csv(ENRICHED_FINDINGS_FILE)
    datastores_df = pd.read_csv(DATASTORES_CSV)

    findings_df["resource"] = findings_df["resource"].astype(str).str.strip()
    findings_df["sourceDbArn"] = findings_df["sourceDbArn"].astype(str).str.strip()
    datastores_df["arn"] = datastores_df["arn"].astype(str).str.strip()

    merged_df = findings_df.merge(datastores_df, left_on="resource", right_on="arn", how="left")
    unmatched = merged_df[merged_df["account"].isna()]
    unmatched_cleaned = unmatched.drop(columns=datastores_df.columns, errors="ignore")

    fallback_merge = unmatched_cleaned.merge(datastores_df, left_on="sourceDbArn", right_on="arn", how="left")
    final_df = pd.concat([merged_df[~merged_df["account"].isna()], fallback_merge], ignore_index=True)

    final_df.to_csv(PERMISSIONS_MATRIX_FILE, index=False)
    print(f"✅ Permissions matrix saved to {PERMISSIONS_MATRIX_FILE}")

def main():
    client_id, client_secret = get_credentials_from_secrets_manager()
    if not client_id or not client_secret:
        return
    jwt_token = get_jwt_token(client_id, client_secret)
    if not jwt_token:
        return
    datastores = get_all_datastores(jwt_token)
    write_filtered_aws_datastores(datastores)
    enrich_findings()
    merge_and_generate_matrix()

if __name__ == "__main__":
    main()
