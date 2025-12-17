# AGENTS.md

Project documentation for AI coding agents.

## Technology Stack

- **Language**: Go 1.24+
- **Router**: github.com/go-chi/chi/v5 (HTTP routing and middleware)
- **Database**: SQLite3 with WAL mode (PostgreSQL-ready architecture)
- **Templating**: Templ (type-safe HTML generation)
- **Frontend**: HTMX + TailwindCSS
- **Cryptography**: bcrypt, crypto/rand
- **Containers**: Podman + Podman Compose
  - Test container: Full image with development tools
  - Production container: Distroless image for minimal attack surface
- **Task Runner**: [just](https://github.com/casey/just) (not make) for helper scripts

## Project Structure

```
cmd/
├── server/main.go           # Main application entry point
└── migrate/main.go          # Database migration tool

internal/
├── config/                  # Configuration management (env vars)
├── db/                      # Database setup and connection
│   └── migrations/          # SQL migration files (numbered)
├── models/                  # Data structures (no business logic)
├── handlers/                # HTTP request handlers (thin, delegate to services)
├── services/                # Business logic layer
├── repository/              # Data access interfaces
│   └── sqlite/              # SQLite implementations
└── middleware/              # HTTP middleware (auth, logging)

web/
├── templates/
│   ├── layout/              # Base layouts (Templ files)
│   └── pages/               # Page templates (Templ files)
└── static/                  # CSS, JS, images
```

## Architecture

### Layered Architecture

```
HTTP Request
    ↓
Middleware (auth, logging)
    ↓
Handlers (HTTP concerns only)
    ↓
Services (business logic)
    ↓
Repositories (data access via interfaces)
    ↓
Database
```

### Repository Pattern

- Interfaces defined in `internal/repository/`
- Implementations in `internal/repository/sqlite/`
- Allows database swapping without code changes
- Return `nil, nil` for "not found" at the repository layer (not an error)
  - Use sentinel `ErrNotFound` when business logic needs to distinguish "not found" as an error condition
  - Repository returns `nil, nil`; service decides if that's an error for the use case

### Transaction Support

- Use `repository.Transactional` interface for transaction-aware operations
- `WithTransaction(ctx, func(txRepo) error)` wraps operations in a transaction
- Transaction rolls back on error, commits on success
- Repositories implement `Transactional` via `dbExecutor` abstraction
- Services receive `Transactional` via dependency injection

```go
// Transactional interface for repositories that support transactions
type Transactional interface {
    WithTransaction(ctx context.Context, fn func(tx Transactional) error) error
}

// dbExecutor abstracts *sql.DB and *sql.Tx for repository implementations
type dbExecutor interface {
    ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
    QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
    QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}
```

### Verify Interface Compliance

Use compile-time assertions to verify types implement required interfaces:

```go
// Good - compile-time check
var _ http.Handler = (*Handler)(nil)
var _ repository.GameDataRepository = (*GameDataRepo)(nil)

// For value receivers
var _ io.Reader = MyReader{}
```

---

## Design Principles

### SOLID

#### S - Single Responsibility Principle

Each type/function should have one reason to change.

```go
// Bad - handler does too much
func (h *Handler) CreateUser(w http.ResponseWriter, r *http.Request) {
    // Parse request
    // Validate input
    // Hash password
    // Insert into database
    // Send welcome email
    // Return response
}

// Good - separated responsibilities
func (h *Handler) CreateUser(w http.ResponseWriter, r *http.Request) {
    var req CreateUserRequest
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        http.Error(w, "invalid request", http.StatusBadRequest)
        return
    }
    user, err := h.userService.Create(r.Context(), req)  // Service handles business logic
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }
    json.NewEncoder(w).Encode(user)
}

// Service handles business logic
func (s *UserService) Create(ctx context.Context, req CreateUserRequest) (*User, error) {
    hash, err := s.hasher.Hash(req.Password)  // Hasher handles hashing
    if err != nil {
        return nil, err
    }
    user := &User{Name: req.Name, PasswordHash: hash}
    if err := s.repo.Create(ctx, user); err != nil {  // Repo handles persistence
        return nil, err
    }
    s.emailer.SendWelcome(user.Email)  // Emailer handles notifications
    return user, nil
}
```

#### O - Open/Closed Principle

Open for extension, closed for modification. Use interfaces to allow new behavior without changing existing code.

```go
// Open for extension via interface
type Notifier interface {
    Notify(ctx context.Context, user *User, message string) error
}

type EmailNotifier struct { /* ... */ }
func (e *EmailNotifier) Notify(ctx context.Context, user *User, msg string) error { /* ... */ }

type SMSNotifier struct { /* ... */ }
func (s *SMSNotifier) Notify(ctx context.Context, user *User, msg string) error { /* ... */ }

// Service doesn't change when adding new notifier types
type UserService struct {
    notifiers []Notifier
}

func (s *UserService) NotifyUser(ctx context.Context, user *User, msg string) error {
    for _, n := range s.notifiers {
        if err := n.Notify(ctx, user, msg); err != nil {
            return err
        }
    }
    return nil
}
```

#### L - Liskov Substitution Principle

Subtypes must be substitutable for their base types. In Go, types implementing an interface must honor its contract.

```go
// Interface contract: Get returns nil, nil when not found
type UserRepository interface {
    GetByID(ctx context.Context, id int) (*User, error)
}

// Good - both implementations honor the contract
type SQLiteUserRepo struct { db *sql.DB }
func (r *SQLiteUserRepo) GetByID(ctx context.Context, id int) (*User, error) {
    user := &User{}
    err := r.db.QueryRowContext(ctx, "SELECT ...", id).Scan(...)
    if err == sql.ErrNoRows {
        return nil, nil  // Contract: not found = nil, nil
    }
    return user, err
}

type CachedUserRepo struct { cache *Cache; repo UserRepository }
func (r *CachedUserRepo) GetByID(ctx context.Context, id int) (*User, error) {
    if user := r.cache.Get(id); user != nil {
        return user, nil
    }
    return r.repo.GetByID(ctx, id)  // Returns nil, nil if not found
}
```

#### I - Interface Segregation Principle

Clients should not depend on interfaces they don't use. Keep interfaces small and focused.

```go
// Bad - fat interface forces unnecessary implementations
type Repository interface {
    Create(ctx context.Context, entity any) error
    GetByID(ctx context.Context, id int) (any, error)
    Update(ctx context.Context, entity any) error
    Delete(ctx context.Context, id int) error
    List(ctx context.Context) ([]any, error)
    Search(ctx context.Context, query string) ([]any, error)
    Export(ctx context.Context, format string) ([]byte, error)
}

// Good - small, focused interfaces
type Reader interface {
    GetByID(ctx context.Context, id int) (*User, error)
}

type Writer interface {
    Create(ctx context.Context, user *User) error
    Update(ctx context.Context, user *User) error
}

type ReadWriter interface {
    Reader
    Writer
}

// Function only requires what it needs
func GetUserHandler(repo Reader) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        // Only needs Reader, not full Repository
    }
}
```

#### D - Dependency Inversion Principle

Depend on abstractions (interfaces), not concretions. High-level modules should not depend on low-level modules.

```go
// Bad - service depends on concrete implementation
type UserService struct {
    repo *SQLiteUserRepo  // Concrete dependency
}

// Good - service depends on interface
type UserService struct {
    repo UserRepository  // Interface dependency
}

func NewUserService(repo UserRepository) *UserService {
    return &UserService{repo: repo}
}

// In main.go - wire up concrete implementations
func main() {
    db := openDatabase()
    repo := sqlite.NewUserRepo(db)        // Concrete
    service := NewUserService(repo)        // Inject via interface
    handler := NewUserHandler(service)
}
```

---

### DRY - Don't Repeat Yourself

Extract common logic, but only when there's true duplication (same business reason to change).

```go
// Bad - repeated error handling
func (h *Handler) GetUser(w http.ResponseWriter, r *http.Request) {
    id := chi.URLParam(r, "id")
    user, err := h.service.GetUser(r.Context(), id)
    if err != nil {
        log.Printf("error getting user: %v", err)
        http.Error(w, "internal error", http.StatusInternalServerError)
        return
    }
    json.NewEncoder(w).Encode(user)
}

func (h *Handler) GetOrder(w http.ResponseWriter, r *http.Request) {
    id := chi.URLParam(r, "id")
    order, err := h.service.GetOrder(r.Context(), id)
    if err != nil {
        log.Printf("error getting order: %v", err)
        http.Error(w, "internal error", http.StatusInternalServerError)
        return
    }
    json.NewEncoder(w).Encode(order)
}

// Good - extract common pattern
func (h *Handler) handleError(w http.ResponseWriter, err error, msg string) {
    log.Printf("%s: %v", msg, err)
    http.Error(w, "internal error", http.StatusInternalServerError)
}

func (h *Handler) respondJSON(w http.ResponseWriter, data any) {
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(data)
}

func (h *Handler) GetUser(w http.ResponseWriter, r *http.Request) {
    id := chi.URLParam(r, "id")
    user, err := h.service.GetUser(r.Context(), id)
    if err != nil {
        h.handleError(w, err, "get user")
        return
    }
    h.respondJSON(w, user)
}
```

**Warning**: Don't over-apply DRY. Similar-looking code with different business reasons to change should remain separate.

---

### YAGNI - You Aren't Gonna Need It

Don't add functionality until it's necessary. Avoid speculative generalization.

```go
// Bad - speculative features
type User struct {
    ID        int
    Name      string
    Email     string
    // "We might need these later"
    Timezone      string
    Locale        string
    Theme         string
    Preferences   map[string]any
    Metadata      map[string]any
    Tags          []string
    CustomFields  []CustomField
}

// Bad - over-engineered for hypothetical requirements
type UserRepository interface {
    Create(ctx context.Context, user *User) error
    GetByID(ctx context.Context, id int) (*User, error)
    GetByEmail(ctx context.Context, email string) (*User, error)
    GetByUsername(ctx context.Context, username string) (*User, error)
    GetByPhone(ctx context.Context, phone string) (*User, error)  // Not needed yet
    Search(ctx context.Context, opts SearchOptions) ([]*User, error)  // Not needed yet
    BulkCreate(ctx context.Context, users []*User) error  // Not needed yet
    SoftDelete(ctx context.Context, id int) error  // Not needed yet
    Restore(ctx context.Context, id int) error  // Not needed yet
}

// Good - only what's needed now
type User struct {
    ID    int
    Name  string
    Email string
}

type UserRepository interface {
    Create(ctx context.Context, user *User) error
    GetByID(ctx context.Context, id int) (*User, error)
    GetByEmail(ctx context.Context, email string) (*User, error)
}
```

---

### KISS - Keep It Simple, Stupid

Prefer simple, straightforward solutions over clever ones.

```go
// Bad - over-engineered
type QueryBuilder struct {
    table      string
    columns    []string
    conditions []Condition
    joins      []Join
    orderBy    []Order
    limit      int
    offset     int
}

func (qb *QueryBuilder) Select(cols ...string) *QueryBuilder { /* ... */ }
func (qb *QueryBuilder) Where(cond Condition) *QueryBuilder { /* ... */ }
func (qb *QueryBuilder) Join(j Join) *QueryBuilder { /* ... */ }
func (qb *QueryBuilder) Build() (string, []any) { /* ... */ }

// Usage becomes complex
query, args := NewQueryBuilder("users").
    Select("id", "name", "email").
    Where(Eq("active", true)).
    Where(Gt("created_at", lastWeek)).
    Join(LeftJoin("orders", "users.id = orders.user_id")).
    OrderBy(Desc("created_at")).
    Limit(10).
    Build()

// Good - simple and direct
func (r *UserRepo) ListActiveUsers(ctx context.Context, limit int) ([]*User, error) {
    query := `
        SELECT id, name, email
        FROM users
        WHERE active = ? AND created_at > ?
        ORDER BY created_at DESC
        LIMIT ?
    `
    rows, err := r.db.QueryContext(ctx, query, true, lastWeek, limit)
    // ...
}
```

```go
// Bad - unnecessary abstraction
type StringProcessor interface {
    Process(s string) string
}

type TrimProcessor struct{}
func (p TrimProcessor) Process(s string) string { return strings.TrimSpace(s) }

type LowerProcessor struct{}
func (p LowerProcessor) Process(s string) string { return strings.ToLower(s) }

func ProcessString(s string, processors ...StringProcessor) string {
    for _, p := range processors {
        s = p.Process(s)
    }
    return s
}

// Good - just use the standard library
func normalizeInput(s string) string {
    return strings.ToLower(strings.TrimSpace(s))
}
```

---

## Go Style Guide

Based on the [Uber Go Style Guide](https://github.com/uber-go/guide).

### Error Handling

#### Error Types - Choose Based on Use Case

| Error matching? | Error Message | Guidance                            |
|-----------------|---------------|-------------------------------------|
| No              | static        | `errors.New()`                      |
| No              | dynamic       | `fmt.Errorf()`                      |
| Yes             | static        | top-level `var` with `errors.New()` |
| Yes             | dynamic       | custom `error` type                 |

```go
// Static error, needs matching - use exported var
var ErrNotFound = errors.New("not found")

// Dynamic error, no matching needed
return fmt.Errorf("user %q not found", username)

// Dynamic error, needs matching - custom type
type NotFoundError struct {
    Resource string
}

func (e *NotFoundError) Error() string {
    return fmt.Sprintf("%s not found", e.Resource)
}
```

#### Error Wrapping - Keep Context Succinct

```go
// Bad - verbose phrases pile up
return fmt.Errorf("failed to create new store: %w", err)
// Results in: failed to x: failed to y: failed to create new store: the error

// Good - concise context
return fmt.Errorf("new store: %w", err)
// Results in: x: y: new store: the error
```

- Use `%w` when callers need to match/extract underlying error
- Use `%v` to obfuscate underlying error from callers

#### Handle Errors Once

Either handle (log, degrade) OR return - never both:

```go
// Bad - logs and returns
if err != nil {
    log.Printf("error: %v", err)
    return err
}

// Good - just return with context
if err != nil {
    return fmt.Errorf("operation: %w", err)
}

// Good - handle and don't return
if err != nil {
    log.Printf("Warning: %v", err)
    // continue with fallback behavior
}
```

### Reduce Nesting

Handle error cases first, return early:

```go
// Bad - deeply nested
for _, v := range data {
    if v.F1 == 1 {
        v = process(v)
        if err := v.Call(); err == nil {
            v.Send()
        } else {
            return err
        }
    } else {
        log.Printf("Invalid v: %v", v)
    }
}

// Good - early returns reduce nesting
for _, v := range data {
    if v.F1 != 1 {
        log.Printf("Invalid v: %v", v)
        continue
    }

    v = process(v)
    if err := v.Call(); err != nil {
        return err
    }
    v.Send()
}
```

### Container Capacity

Always specify capacity hints to avoid reallocations:

```go
// Bad - unknown capacity causes reallocations
data := make([]int, 0)
for k := 0; k < size; k++ {
    data = append(data, k)
}

// Good - pre-allocate with known capacity
data := make([]int, 0, size)
for k := 0; k < size; k++ {
    data = append(data, k)
}

// Maps - provide size hint
files, _ := os.ReadDir("./files")
m := make(map[string]os.DirEntry, len(files))
```

### Slices

#### nil is a Valid Slice

```go
// Bad - return empty slice
if x == "" {
    return []int{}
}

// Good - return nil
if x == "" {
    return nil
}

// Check emptiness with len, not nil
if len(s) == 0 {  // Good
    // ...
}
if s == nil {  // Bad
    // ...
}

// Zero value is usable without make()
var nums []int  // Good
nums = append(nums, 1)
```

### Struct Initialization

#### Use Field Names

```go
// Bad - positional
k := User{"John", "Doe", true}

// Good - named fields
k := User{
    FirstName: "John",
    LastName:  "Doe",
    Admin:     true,
}
```

Exception: Test tables with 3 or fewer fields may omit names.

#### Omit Zero Values

```go
// Bad - explicit zero values
user := User{
    FirstName: "John",
    LastName:  "Doe",
    Admin:     false,  // unnecessary
}

// Good - omit zero values
user := User{
    FirstName: "John",
    LastName:  "Doe",
}
```

### Defer for Cleanup

Always use defer for resource cleanup:

```go
// Bad - easy to miss unlock on multiple returns
p.Lock()
if p.count < 10 {
    p.Unlock()
    return p.count
}
p.count++
p.Unlock()
return p.count

// Good - defer guarantees cleanup
p.Lock()
defer p.Unlock()

if p.count < 10 {
    return p.count
}
p.count++
return p.count
```

### Functional Options Pattern

For constructors with 3+ optional parameters:

```go
type options struct {
    cache  bool
    logger *zap.Logger
}

type Option interface {
    apply(*options)
}

type cacheOption bool

func (c cacheOption) apply(opts *options) {
    opts.cache = bool(c)
}

func WithCache(c bool) Option {
    return cacheOption(c)
}

func Open(addr string, opts ...Option) (*Connection, error) {
    options := options{
        cache:  defaultCache,
        logger: zap.NewNop(),
    }
    for _, o := range opts {
        o.apply(&options)
    }
    // ...
}

// Usage
db.Open(addr)
db.Open(addr, db.WithCache(false))
db.Open(addr, db.WithCache(false), db.WithLogger(log))
```

### Table-Driven Tests

```go
func TestSplitHostPort(t *testing.T) {
    tests := []struct {
        give     string
        wantHost string
        wantPort string
    }{
        {
            give:     "192.0.2.0:8000",
            wantHost: "192.0.2.0",
            wantPort: "8000",
        },
        {
            give:     ":8000",
            wantHost: "",
            wantPort: "8000",
        },
    }

    for _, tt := range tests {
        t.Run(tt.give, func(t *testing.T) {
            host, port, err := net.SplitHostPort(tt.give)
            require.NoError(t, err)
            assert.Equal(t, tt.wantHost, host)
            assert.Equal(t, tt.wantPort, port)
        })
    }
}
```

Conventions:
- Slice named `tests`, each case `tt`
- Use `give` prefix for inputs, `want` prefix for expected outputs
- Avoid complex conditional logic in table tests - split into separate tests instead

### Database Queries

#### Always Check rows.Err()

```go
rows, err := db.QueryContext(ctx, query)
if err != nil {
    return nil, err
}
defer rows.Close()

var results []*Model
for rows.Next() {
    m := &Model{}
    if err := rows.Scan(&m.Field); err != nil {
        return nil, err
    }
    results = append(results, m)
}
// Critical - check for errors during iteration
if err := rows.Err(); err != nil {
    return nil, err
}
return results, nil
```

---

## Project Conventions

### Naming

- Interfaces: `UserRepository`, `SessionRepository` (noun)
- Implementations: `UserRepo`, `SessionRepo` (concrete)
- Constructors: `NewUserRepo()`, `NewAuthService()`
- HTTP handlers: `GetLogin()`, `PostLogin()` (verb-noun)
- Private functions: lowercase `createSession()`
- Error variables: `ErrNotFound` (exported), `errNotFound` (unexported)

### Database

- All queries use `context.Context` for cancellation
- Use parameterized queries (never string concatenation)
- Migration files: `NNN_description.sql` (e.g., `001_initial_schema.sql`)
  - Use embedded up/down sections with comments:
    ```sql
    -- +migrate Up
    CREATE TABLE users (...);

    -- +migrate Down
    DROP TABLE users;
    ```

### Security

- bcrypt for password hashing (cost 12)
- `crypto/rand` for secure token generation
- HttpOnly, SameSite=Strict cookies
- CSRF protection via tokens for state-changing operations
- Prepared statements prevent SQL injection
- Templ auto-escaping prevents XSS

### Logging

- Use `log/slog` for structured logging
- Log at handler level for request context (method, path, status, duration)
- Services should return errors, not log them (let caller decide)
- Log levels:
  - `Error`: Unexpected failures requiring attention
  - `Warn`: Recoverable issues, degraded behavior
  - `Info`: Significant events (startup, shutdown, requests)
  - `Debug`: Detailed diagnostic information

### HTTP Handlers

- Keep handlers thin - delegate to services
- Validate input at handler level
- Return appropriate HTTP status codes
- Log errors before returning error responses

### Services

- Contain all business logic
- Accept repository interfaces (dependency injection)
- Return domain errors, not HTTP errors
- Handle transactions when needed

### Templates (Templ)

- Templates in `web/templates/`
- Use a base layout component for consistent page structure
- Pass user from context for auth-aware rendering
- Generated Go files: `*_templ.go` (do not edit)

---

## Development Workflow

### Commands

Use `just` for common tasks. Run `just --list` to see available recipes.

```bash
# Example justfile recipes
just dev          # Run development server with hot reload
just build        # Build for production
just test         # Run tests
just lint         # Run linters
just migrate up   # Run migrations
just generate     # Generate Templ files

# Direct Go commands (if needed)
templ generate
go run ./cmd/server
go run ./cmd/migrate up
go build -o server ./cmd/server
go test ./...
golangci-lint run
```

### Container Commands

```bash
# Build containers
podman-compose build

# Run test container
podman-compose up test

# Run production container
podman-compose up prod
```

### Adding New Features

1. Add migration if schema changes needed
2. Define models in `internal/models/`
3. Add repository interface methods
4. Implement repository in database package
5. Add service with business logic
6. Create handler for HTTP endpoints
7. Register routes in server setup
8. Create Templ templates if needed

### Adding Migrations

1. Create new file: `internal/db/migrations/NNN_description.sql`
2. Register migration in the migrate command
3. Run migrations up

---

## File Upload Handling

- Max size: 10MB (configurable via `ParseMultipartForm`)
- Validate file content type, not just extension
- Read entire file into memory for processing
- Return clear error messages on failure

---

## Testing

- Repository interfaces enable mocking
- Test services with mock repositories
- Integration tests against SQLite in-memory database
- Use table-driven tests for multiple input/output scenarios
- Recommended: `go.uber.org/goleak` to detect goroutine leaks

---

## Linting

Recommended linters (via golangci-lint):
- **errcheck** - Ensure errors are handled
- **goimports** - Format code and manage imports
- **govet** - Analyze for common mistakes
- **staticcheck** - Various static analysis checks
