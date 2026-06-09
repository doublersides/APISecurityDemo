#!/usr/bin/env bash
# Sample API calls for the Vulnerable API Demo
# Usage: ./sample-api-calls.sh
# Ensure the app is running: python app.py

BASE_URL="${BASE_URL:-http://127.0.0.1:5050}"

echo "Using BASE_URL=${BASE_URL}"
echo

# 1. List available endpoints
echo "=== 1. GET / ==="
curl -s "${BASE_URL}/" | python3 -m json.tool
echo

# 2. Login with valid credentials
echo "=== 2. POST /api/login ==="
curl -s -X POST "${BASE_URL}/api/login" \
  -H "Content-Type: application/json" \
  -d '{"username":"alice","password":"password123"}' | python3 -m json.tool
echo

# 3. List all users (includes sensitive fields)
echo "=== 3. GET /api/users ==="
curl -s "${BASE_URL}/api/users" | python3 -m json.tool
echo

# 4. Get a specific user by ID (IDOR)
echo "=== 4. GET /api/users/3 ==="
curl -s "${BASE_URL}/api/users/3" | python3 -m json.tool
echo

# 5. Create a user with mass assignment
echo "=== 5. POST /api/users ==="
curl -s -X POST "${BASE_URL}/api/users" \
  -H "Content-Type: application/json" \
  -d '{"username":"eve","password":"secret","email":"eve@example.com","role":"admin"}' | python3 -m json.tool
echo

# 6. Search users by username
echo "=== 6. GET /api/search?q=ali ==="
curl -s "${BASE_URL}/api/search?q=ali" | python3 -m json.tool
echo

# 7. Fetch profile using client-supplied header
echo "=== 7. GET /api/profile ==="
curl -s "${BASE_URL}/api/profile" \
  -H "X-User-Id: 1" | python3 -m json.tool
echo

# 8. Fetch a remote URL (SSRF)
echo "=== 8. POST /api/fetch ==="
curl -s -X POST "${BASE_URL}/api/fetch" \
  -H "Content-Type: application/json" \
  -d '{"url":"https://example.com"}' | python3 -m json.tool
echo

# 9. Read a file from the data directory
echo "=== 9. GET /api/files?path=notes.txt ==="
curl -s "${BASE_URL}/api/files?path=notes.txt" | python3 -m json.tool
echo

# 10. Run ping via shell command
echo "=== 10. POST /api/exec ==="
curl -s -X POST "${BASE_URL}/api/exec" \
  -H "Content-Type: application/json" \
  -d '{"hostname":"localhost"}' | python3 -m json.tool
echo
