# oic-custom-scopes
OCI Function to use Custom Scopes to Restrict Access to OIC REST Endpoints with OCI IAM and API Gateway.
This repo is the code for my blog post https://www.ateam-oracle.com/post/use-custom-scopes-to-restrict-access-to-oic-rest-endpoints-with-oci-iam-and-api-gateway

# Running the script

how to run in OCI:

1. Login to OCI Tenancy
2. Create an OCI Function
3. fn _init --runtime python MyCustomAuthorizer_, then press Enter.
4. Navigate to the function directory, open the func.py file, and seamlessly replace the existing code snippet with the func.py.
5. Copy the ociVault.py file in the same folder location.
6. Include the requirements from the requirements.txt file
7. Navigate to the function folder and run the following command _fn -v deploy --app MyCustomAuthorizer_ to deploy it.

