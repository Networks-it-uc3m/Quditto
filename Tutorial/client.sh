#!/bin/bash

# Key exchange between the nodes with no eavesdropper (A and B)

echo "[*] Fetching keys between A and B..."

# Send request to node A
echo "[*] Requesting key to A..."
response_AB=$(wget -qO - "http://10.4.48.59:8000/api/v1/keys/B/enc_keys?size=512")

# Check if response is empty
if [[ -z "$response_AB" ]]; then
  echo "[!] No response received. Exiting."
  exit 1
fi

key_AB=$(echo "$response_AB" | sed "s/.*'key': '\([^']*\)'.*/\1/")
key_id_AB=$(echo "$response_AB" | sed "s/.*'key_ID': '\([^']*\)'.*/\1/")

echo "[*] The key retrieved from A is: $key_AB"

# Check if key_id extraction succeeded
if [[ -z "$key_id_AB" ]]; then
  echo "[!] Failed to extract key_ID. Response was:"
  echo "$response_AB"
  exit 1
fi

echo "[*] The corresponding key_ID is: $key_id_AB"

# Send request to node B with the retrieved key_ID
echo "[*] Sending request to B node with the key_ID..."
response_BA=$(wget -qO - "http://10.4.48.129:8000/api/v1/keys/A/dec_keys?key_ID=${key_id_AB}")

# Check if response is empty
if [[ -z "$response_BA" ]]; then
  echo "[!] No response received. Exiting."
  exit 1
fi

key_BA=$(echo "$response_BA" | sed "s/.*'key': '\([^']*\)'.*/\1/")

echo "[*] The key retrieved from B is: $key_BA"


# Compare keys
if [[ "$key_AB" == "$key_BA" ]]; then
  echo "[✅] The keys match! There were indeed no eavesdroppers."
else
  echo "[❌] The keys do NOT match. Something went wrong..."
fi

# Try to do a request with a false key_ID

echo "[*] Sending a request to B node with a false key_ID..."
response_B=$(wget -qO - "http://10.4.48.129:8000/api/v1/keys/A/dec_keys?key_ID=628459b2-0454-49e2-a208-f1c7484e7c29")
key_B=$(echo "$response_B" | sed "s/.*'key': '\([^']*\)'.*/\1/")

echo "[*] The response was:"
echo "$key_B"

if [[ "$key_B" == 'No key with specified key_ID' ]]; then
  echo "[✅] The node recognized that it does not have any key with that ID"
else
  echo "[❌] Something went wrong..."
fi


# Key exchange between the nodes with eavesdropper (A and C)

echo "[*] Fetching keys between A and C..."

# Send request to node C (to change a bit the process)
echo "[*] Requesting key to C..."
response_CA=$(wget -qO - "http://10.4.48.188:8000/api/v1/keys/A/enc_keys?size=512")

# Check if response is empty
if [[ -z "$response_CA" ]]; then
  echo "[!] No response received. Exiting."
  exit 1
fi

key_CA=$(echo "$response_CA" | sed "s/.*'key': '\([^']*\)'.*/\1/")
key_id_CA=$(echo "$response_CA" | sed "s/.*'key_ID': '\([^']*\)'.*/\1/")

echo "[*] The key retrieved from C is: $key_CA"

# Check if key_id extraction succeeded
if [[ -z "$key_id_CA" ]]; then
  echo "[!] Failed to extract key_ID. Response was:"
  echo "$response_CA"
  exit 1
fi

echo "[*] The corresponding key_ID is: $key_id_CA"

# Send request to node A with the retrieved key_ID
echo "[*] Sending request to A node with the key_ID..."
response_AC=$(wget -qO - "http://10.4.48.59:8000/api/v1/keys/C/dec_keys?key_ID=${key_id_CA}")

# Check if response is empty
if [[ -z "$response_AC" ]]; then
  echo "[!] No response received. Exiting."
  exit 1
fi

key_AC=$(echo "$response_AC" | sed "s/.*'key': '\([^']*\)'.*/\1/")

echo "[*] The key retrieved from A is: $key_AC"


# Compare keys
if [[ "$key_CA" != "$key_AC" ]]; then
  echo "[✅] The keys do NOT match! The eavesdropper module is working."
else
  echo "[❌] The keys match. Maybe you have been lucky? Highly unlikely but possible..."
fi

# Try key exchange between the nodes without link (B and C)

echo "[*] Fetching keys between B and C..."

# Send request to node B
echo "[*] Requesting key to B..."
response_BC=$(wget -qO - "http://10.4.48.129:8000/api/v1/keys/C/enc_keys?size=512")

message_BC=$(echo "$response_BC" | sed "s/.*'message': '\([^']*\)'.*/\1/")

echo "[*] The response was:"
echo "$message_BC"

if [[ "$message_BC" == 'Invalid partner requested.' ]]; then
  echo "[✅] The node recongnizes that C is not its neighbour."
else
  echo "[❌] Something went wrong..."
fi

# Send request to node C

echo "[*] Requesting key to C..."
response_CB=$(wget -qO - "http://10.4.48.188:8000/api/v1/keys/B/enc_keys?size=512")

message_CB=$(echo "$response_CB" | sed "s/.*'message': '\([^']*\)'.*/\1/")

echo "[*] The response was:"
echo "$message_CB"

if [[ "$message_CB" == 'Invalid partner requested.' ]]; then
  echo "[✅] The node recongnizes that B is not its neighbour."
else
  echo "[❌] Something went wrong..."
fi

