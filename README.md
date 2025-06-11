# AWS-IAM-Access-Analyzer-samples
Public repository to demonstrate the use of AWS IAM Access Analyzer CLI with Cyera DSPM platform


1. To execute retrieve-findings.sh follow the steps:
    - In AWS CLI install the new model 

    aws configure add-model --service-model file://Api-model-private-beta.json --service-name accessanalyzer-private-beta

    This model should be installed in the AWS Organization's Master account

2. Ensure that AWW CLI and Python 3.11 or later is installed. 
3. Log into Organization's Master account and execute retrieve-findings.sh from the bash shell.

4. Generate the CLIENT_ID and CLIENT_SECRET for your Cyera tenant and store them in the AWS Secrets manager secret cyera_tenant in the AWS member account where the resorces are located.
5. To run generate permissions.py make sure that you are logged into the member account where your resources are located.