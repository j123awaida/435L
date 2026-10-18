# API reference (Joseph Awaida)
All protected requests require a bearer token. Full request/response schemas are in the exported OpenAPI JSON and interactive `/docs`. Error format: `{"status":"error","message":"..."}`. Common errors: 401 missing/invalid authentication; 403 role/ownership; 404 missing resource; 409 conflicting step or workflow; 422 input validation.

## Identity integration adapter (Service 1 boundary)

### Health
`GET /Joseph-Awaida/health`

Success: 200. See Postman requests for runnable examples.

### Login
`POST /Joseph-Awaida/auth/login`

JSON body: `username, password`. Required: `username, password`.

Success: 200. See Postman requests for runnable examples.

## Service 7: Vulnerability Management

### Health
`GET /Joseph-Awaida/health`

Success: 200. See Postman requests for runnable examples.

### Create
`POST /Joseph-Awaida/vulnerabilities`

JSON body: `title, description, cve_identifier, cvss_score, severity, asset_id, discovery_source`. Required: `title, description, cve_identifier, cvss_score, severity, asset_id, discovery_source`.

Success: 201. See Postman requests for runnable examples.

### All Records
`GET /Joseph-Awaida/vulnerabilities`

Parameters: limit (query, optional), offset (query, optional)

Success: 200. See Postman requests for runnable examples.

### Search
`GET /Joseph-Awaida/vulnerabilities/search`

Parameters: cve_identifier (query, optional), severity (query, optional), asset_id (query, optional), status (query, optional)

Success: 200. See Postman requests for runnable examples.

### Retrieve
`GET /Joseph-Awaida/vulnerabilities/{id}`

Parameters: id (path, required)

Success: 200. See Postman requests for runnable examples.

### Update
`PUT /Joseph-Awaida/vulnerabilities/{id}`

Parameters: id (path, required)

JSON body: `description, severity, status, cvss_score`. Required: ``.

Success: 200. See Postman requests for runnable examples.

### Delete
`DELETE /Joseph-Awaida/vulnerabilities/{id}`

Parameters: id (path, required)

Success: 200. See Postman requests for runnable examples.

## Service 8: Notification and Alert Management

### Health
`GET /Joseph-Awaida/health`

Success: 200. See Postman requests for runnable examples.

### Create
`POST /Joseph-Awaida/notifications`

JSON body: `user_id, title, message, notification_type, severity`. Required: `user_id, title, message, notification_type, severity`.

Success: 201. See Postman requests for runnable examples.

### By User
`GET /Joseph-Awaida/notifications/user/{user_id}`

Parameters: user_id (path, required)

Success: 200. See Postman requests for runnable examples.

### Search
`GET /Joseph-Awaida/notifications/search`

Parameters: user_id (query, optional), notification_type (query, optional), severity (query, optional), status (query, optional)

Success: 200. See Postman requests for runnable examples.

### Retrieve
`GET /Joseph-Awaida/notifications/{id}`

Parameters: id (path, required)

Success: 200. See Postman requests for runnable examples.

### Delete
`DELETE /Joseph-Awaida/notifications/{id}`

Parameters: id (path, required)

Success: 200. See Postman requests for runnable examples.

### Mark Read
`PUT /Joseph-Awaida/notifications/{id}/read`

Parameters: id (path, required)

Success: 200. See Postman requests for runnable examples.

## Service 9: Security Playbook and Response Automation

### Health
`GET /Joseph-Awaida/health`

Success: 200. See Postman requests for runnable examples.

### All Records
`GET /Joseph-Awaida/playbooks`

Success: 200. See Postman requests for runnable examples.

### Create
`POST /Joseph-Awaida/playbooks`

JSON body: `name, description, incident_category, severity`. Required: `name, description, incident_category, severity`.

Success: 201. See Postman requests for runnable examples.

### Retrieve
`GET /Joseph-Awaida/playbooks/{id}`

Parameters: id (path, required)

Success: 200. See Postman requests for runnable examples.

### Delete
`DELETE /Joseph-Awaida/playbooks/{id}`

Parameters: id (path, required)

Success: 200. See Postman requests for runnable examples.

### Add Action
`POST /Joseph-Awaida/playbooks/{id}/actions`

Parameters: id (path, required)

JSON body: `description, step_number, assigned_user_id`. Required: `description, step_number`.

Success: 201. See Postman requests for runnable examples.

### Update Action
`PUT /Joseph-Awaida/actions/{id}/status`

Parameters: id (path, required)

JSON body: `status, assigned_user_id`. Required: `status`.

Success: 200. See Postman requests for runnable examples.
