#!/bin/bash

slave_SAE="bob2"
master_SAE="bob1"
# key_id="802bada7-3c4c-430b-98a8-7be354abb87f"

# curl --cacert certs/ca.cert.pem \
#     --cert certs/sae1.cert.pem --key certs/sae1.key.pem \
#     --header "Content-Type: application/json" \
#     --request GET \
#     "https://localhost:3333/api/v1/keys/$slave_SAE/enc_keys?number=3&size=1024"

curl --cacert certs/ca.cert.pem \
    --cert certs/sae2.cert.pem --key certs/sae2.key.pem \
    --header "Content-Type: application/json" \
    --request POST \
    --data '{"key_IDs": [{"key_ID": "9803581e-9763-48ea-ab89-e0db52ee379c"}]}' \
    "https://localhost:4444/api/v1/keys/$master_SAE/dec_keys"
