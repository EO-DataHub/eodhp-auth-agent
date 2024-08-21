# Auth Agent

## v0.1.0 (Unreleased)

- Created Cobra CLI
  - Root command runs API server
  - Subcommand initdb initialises the database
- Created internal/authn package to handle authentication
  - Extracts authentication from headers and/or cookies and requests authentication from upstream client
  - If authenticated then claims are returned
- Created internal/authz package to handle authorization
  - Uses authenticated claims to query upstream OPA client policy
- Created internal/db package to act as a database client
  - Created user table and helper functions
  - Created tokens table and helper functions
  - Created crypto helper to hash/encrypt sensitive row fields
- Created internal/keycloak package to act as client to Keycloak
  - Requests refresh tokens
  - Exchanges regular session access tokens for offline access/refresh tokens
- Created api/auth package to handle auth endpoint
- Created api/tokens package to handle token CRUD endpoints
- Created api/middleware package
  - Adds logging context to request context
  - Adds claims context to request context when authenticated
