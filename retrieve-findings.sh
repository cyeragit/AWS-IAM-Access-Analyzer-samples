#!/bin/bash

# Set variables
REGION="us-east-1"
OUTPUT_FILE="finding-details.csv"

# Write CSV header
echo '"id","resource","resourceType","resourceOwnerAccount","status","findingType","createdAt","updatedAt","principal","principalType","accessType","actions","actions_count","sources","analyzerArn"' > "$OUTPUT_FILE"

# Step 1: Retrieve all analyzers in the region
echo "Listing analyzers..."
ANALYZERS=$(aws accessanalyzer-private-beta list-analyzers --region "$REGION")

# Step 2: Extract analyzer ARNs and loop through each one
echo "$ANALYZERS" | jq -r '.analyzers[].arn' | while read -r ANALYZER_ARN; do
  echo "Processing analyzer: $ANALYZER_ARN"

  # Step 3: List findings for each analyzer
  FINDINGS=$(aws accessanalyzer-private-beta list-findings-v2 \
    --region "$REGION" \
    --analyzer-arn "$ANALYZER_ARN")

  # Step 4: Loop through each finding ID and retrieve details
  echo "$FINDINGS" | jq -r '.findings[].id' | while read -r FINDING_ID; do
    echo "Getting details for Finding ID: $FINDING_ID from Analyzer: $ANALYZER_ARN"

    FINDING_DETAIL=$(aws accessanalyzer-private-beta get-finding-v2 \
      --region "$REGION" \
      --analyzer-arn "$ANALYZER_ARN" \
      --id "$FINDING_ID")

    echo "$FINDING_DETAIL" | jq -r --arg ANALYZER "$ANALYZER_ARN" '
      def safe_join(array): if array == null then "" else array | join("; ") end;
      def safe_length(array): if array == null then 0 else array | length end;
      def normalize_time(ts): if ts == null then "" else (ts | sub("\\.\\d{3,6}(\\+00:00)?"; "") + "Z") end;

      [
        (.id // ""),
        (.resource // ""),
        (.resourceType // ""),
        (.resourceOwnerAccount // ""),
        (.status // ""),
        (.findingType // ""),
        (normalize_time(.createdAt)),
        (normalize_time(.updatedAt)),
        (.findingDetails[0]?.internalAccessDetails?.principal?.AWS // ""),
        (.findingDetails[0]?.internalAccessDetails?.principalType // ""),
        (.findingDetails[0]?.internalAccessDetails?.accessType // ""),
        (safe_join(.findingDetails[0]?.internalAccessDetails?.action)),
        (safe_length(.findingDetails[0]?.internalAccessDetails?.action)),
        (safe_join((.findingDetails[0]?.internalAccessDetails?.sources // []) | map(.type))),
        $ANALYZER
      ] | @csv
    ' >> "$OUTPUT_FILE"

  done
done

echo "✅ QuickSight-compatible CSV written to $OUTPUT_FILE"