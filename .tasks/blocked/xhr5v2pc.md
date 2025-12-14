---
title: 'CA client: Hello request'
id: xhr5v2pc
created: 2025-12-14T05:18:26.298430Z
updated: 2025-12-14T17:39:04.916773Z
author: Brian McCallister
priority: medium
tags:
- protocol
- ca-client
blocked_by:
- bxt3mhas
- 0e5x04z3
---

Add hello/validate request support to CA client.

Files: pkg/caclient/caclient.go, pkg/caclient/caclient_test.go

Implementation:
- Add Hello(token string) method
- Send empty JSON body {} with Authorization Bearer header
- Return HelloResponse with identity
- Return http.Header so caller can access Link header for discovery

Used by broker during bootstrap to validate token and get discovery URL.

---
## Log

---
# Log: 2025-12-14T05:18:26Z Brian McCallister

Created task.
---
# Log: 2025-12-14T05:18:33Z Brian McCallister

Implementation details:

New method in pkg/caclient/caclient.go:

func (c *Client) Hello(token []byte) (*HelloResponse, http.Header, error) {
    encoded := base64.RawURLEncoding.EncodeToString(token)
    req, _ := http.NewRequest("POST", c.caURL, strings.NewReader("{}"))
    req.Header.Set("Authorization", "Bearer " + encoded)
    req.Header.Set("Content-Type", "application/json")
    
    resp, err := c.httpClient.Do(req)
    // ... handle response
    
    var helloResp HelloResponse
    json.Unmarshal(body, &helloResp)
    return &helloResp, resp.Header, nil  // Return headers for Link header access
}

type HelloResponse struct {
    Identity string `json:"identity"`
}

Key: Return http.Header so caller can access Link header for discovery URL.

Used by broker during bootstrap:
1. Call Hello() to validate token
2. Read Link header from response  
3. Fetch discovery from that URL
---
# Log: 2025-12-14T05:18:38Z Brian McCallister

Added blocker: bxt3mhas
---
# Log: 2025-12-14T05:18:38Z Brian McCallister

Added blocker: 0e5x04z3