# RFC: Secure Refetch Protocol

## Abstract

This document defines the **Refetch Protocol**, a secure mechanism for a client to instruct a server to fetch data from a third-party source, extract specific claims, and return a cryptographically verifiable proof of the result. Crucially, it provides a guarantee that the requested data is **tamper-proof** and **originates correctly from the source**, with fields that can be independently verified. The protocol is designed to be **transport-agnostic**, **flexible** (supporting various data formats and extraction logic), and **type-safe** (ensuring strictly defined schemas for all interactions).

## 1. Protocol Overview

The protocol follows a "Sealed Instructions" model:
1.  **Client** constructs a `RefetchRequest` containing execution instructions, extraction logic, and cryptographic parameters.
2.  **Client** encrypts and signs this request into a **JWE (JSON Web Encryption)** container.
3.  **Verifier** receives (or observes) the JWE, decrypts it, validates the signature, and executes the instructions.
4.  **Verifier** performs the verification (e.g. fetches the target resource or verifies a ZK proof), runs the extraction logic, and computes proofs.
5.  **Verifier** constructs a `RefetchResponse`, signs/encrypts it into a new JWE, and returns it to the client.

*Note: The **Verifier** is the entity responsible for attesting to the response. Depending on the `verificationMode`, this could be a Relay Server, a Notary in a ZK-TLS session, or a Trusted Execution Environment (TEE), etc.*

### 1.1 Goals

*   **Security**: End-to-end secrecy and integrity of instructions and results.
*   **Flexibility**: Support for HTTP/HTTPS, various methods (GET, POST), and complex extraction (Regex, JSONPath, XPath, Byte Range).
*   **Type Safety**: All payloads and selectors are strictly typed to minimize runtime errors and ambiguity.
*   **Verifiability**: The response contains a cryptographic proof that can be independently verified.

---

## 2. Data Structures

The core of the protocol is the `RefetchRequest` and `RefetchResponse` structures.

### 2.1 RefetchRequest

The decrypted payload of the request JWE.

```typescript
type RefetchRequest = {
  /** Unique identifier for this request trace */
  requestId: string;

  /** The target resource to fetch */
  target: HttpTarget;

  /** 
   * Variables to inject into templates ({{var}}).
   * Values can be marked as 'secret' to be scrubbed from logs.
   */
  parameters?: Record<string, ParameterValue>;

  /** 
   * Ordered list of extractions to perform on the fetched data.
   */
  extractions: Extraction[];

  /**
   * Configuration for the execution environment.
   */
  options?: RequestOptions;

  /**
   * Specifies how the verification should be performed and by whom.
   * Dictionary of supported modes is extensible. 
   * - `relay`: A generic Verifier (Server) makes the request on behalf of the client (Default).
   * - (Future modes can include `zk-tls`, `tee`, etc. where Client makes request and Verifier observes).
   */
  verificationMode?: "relay" | string;
};

type ParameterValue = {
  value: string | number | boolean;
  isSecret?: boolean;
};

type RequestOptions = {
  timeoutMs?: number;
  followRedirects?: boolean;
  verifySsl?: boolean;
};
```

### 2.2 HttpTarget

Defines *what* to fetch. Supports templating in most fields.

```typescript
type HttpTarget = {
  url: string; // Supports templating: "https://api.site.com/users/{{userId}}"
  method: "GET" | "POST" | "PUT" | "DELETE" | "PATCH";
  headers?: Record<string, string>;
  body?: string; // Supports templating
};
```

### 2.3 Extraction & Selectors

Defines *how* to extract data. This is where flexibility and type safety meet.

```typescript
type Extraction = {
  /** The key name for the result in the response */
  name: string;

  /** Where to look for the data */
  source: "response_body" | "response_header" | "response_status" | "request_url";

  /** The logic to extract the data */
  selector: Selector;

  /** Optional assertions to validate the extracted value */
  assertion?: Assertion;
  
  /** Post-processing (e.g., hashing) */
  transform?: Transform;
};

/**
 * discriminated union for type-safe selectors
 */
type Selector = 
  | { type: "regex"; pattern: string; group?: number }
  | { type: "jsonpath"; query: string }
  | { type: "range"; start: number; end?: number } // Byte range. End is optional (to overwrite until end)
  | { type: "xpath"; query: string };

type Assertion = {
  /**
   * - `equal`: Strict string equality (===).
   * - `contains`: substring check (includes).
   * - `regex_match`: Tests against a regex pattern.
   */
  operator: "equal" | "contains" | "regex_match";
  value: string;
  errorOnMismatch?: boolean; // If true, finding a mismatch fails the whole request
};

type Transform = {
  type: "hash_sha256" | "redact";
};
```

### 2.4 RefetchResponse

The decrypted payload of the response JWE.

```typescript
type RefetchResponse = {
  requestId: string;
  
  /** Status of the overall execution */
  status: "success" | "partial_error" | "failed";
  
  /** 
   * The original request information (sanitized/redacted).
   * Useful for verifying what was actually executed.
   */
  requestTrace: {
    targetUrl: string;
    method: string;
    // ... metadata
  };

  /** The extracted results */
  results: Record<string, ExtractionResult>;

  /** Any errors encountered during execution */
  errors?: ExecutionError[];
  
  /** Cryptographic proof of the execution */
  integrity: {
    hash: string; // Hash of the raw response body
    timestamp: number;
  };
};

type ExtractionResult = {
  /** 
   * The extracted value. 
   * - If `transform` was "redact", this will be null.
   * - If `transform` was "hash_sha256", this will be the hex hash.
   * - Otherwise, it's the raw string.
   */
  value: string | null;
  verified: boolean; // True if assertion passed
  
  /** 
   * The redaction status of the value.
   */
  redaction_mode: "none" | "redacted" | "hashed"; 
};

type ExecutionError = {
  code: string;
  message: string;
  field?: string; // If related to a specific extraction
};
```

---

## 3. Security (JWE/JWS)

The protocol relies on standard JOSE (Javascript Object Signing and Encryption) formats.

### 3.1 Request JWE

*   **Header**:
    *   `alg`: `ECDH-ES` (or similar standard key agreement)
    *   `enc`: `A256GCM` (AES GCM for authenticated encryption)
    *   `kid`: ID of the server's public key utilized for encryption.
    *   `cty`: `application/refetch-request+json`
*   **Payload**: JSON serialization of `RefetchRequest`.

### 3.2 Response JWE

*   **Header**:
    *   `alg`: `ECDH-ES`
    *   `enc`: `A256GCM`
    *   `kid`: ID of the server's signing key.
*   **Payload**: JSON serialization of `RefetchResponse`.

### 3.3 Replay Protection

The `requestId` combined with `iat` (issued at) and `exp` (expiration) claims in the JWE standard header MUST be validated by the server to prevent replay attacks.

---

## 4. Templating

To allow dynamic requests (e.g. injecting a user's session token or specific ID), the `RefetchRequest` supports Mustache-style templating.

**Example:**

Request:
```json
{
  "target": { "url": "https://api.example.com/data/{{id}}" },
  "parameters": { "id": { "value": "123" } }
}
```

Resolves to: `https://api.example.com/data/123`

**Security Note:** All interpolated specific values MUST be strictly escaped to prevent injection attacks (e.g., ensuring a `{{param}}` cannot break out of a JSON string structure if used in a body).

---

## 5. Usage Example

### 5.1 Fetching a User's ID from a JSON API

**Scenario:** We want to fetch `https://api.social.com/me` and extract the `id` field.

**Detailed Request Construction:**

```json
{
  "requestId": "req_unique_001",
  "target": {
    "url": "https://api.social.com/me",
    "method": "GET",
    "headers": { "Authorization": "Bearer {{token}}" }
  },
  "parameters": {
    "token": { "value": "s3cr3t_t0k3n", "isSecret": true }
  },
  "extractions": [
    {
      "name": "user_id",
      "source": "response_body",
      "selector": {
        "type": "jsonpath",
        "query": "$.id"
      }
    },
    {
      "name": "account_type",
      "source": "response_body",
      "selector": {
        "type": "jsonpath",
        "query": "$.account.type"
      },
      "assertion": {
        "operator": "equal",
        "value": "premium",
        "errorOnMismatch": true
      }
    },
    {
      "name": "email_domain",
      "source": "response_body",
      "selector": {
        "type": "regex",
        "pattern": "@([a-zA-Z.]+)",
        "group": 1
      },
      "assertion": {
        "operator": "regex_match",
        "value": "company\\.com$",
        "errorOnMismatch": false
      }
    }
  ]
}
```

### 5.2 Server Execution Logic

1.  Server decrypts JWE.
2.  Parses `RefetchRequest`.
3.  Substitutes `{{token}}`.
4.  Executes `GET https://api.social.com/me`.
5.  Receives JSON response: `{"id": "user_555", "account": {"type": "premium"}, "email": "bob@company.com"}`.
6.  Extracts `$.id` -> `"user_555"`.
7.  Extracts `$.account.type` -> `"premium"`. Checks assertion `"premium" === "premium"` (PASS).
8.  Extracts Regex `@([a-zA-Z.]+)` -> `"company.com"`. Checks assertion `company.com` matches `company\.com$` (PASS).
9.  Constructs `RefetchResponse`.
10. Encrypts/Signs and returns.

### 5.3 Constructed Response

This is the payload inside the response JWE:

```json
{
  "requestId": "req_unique_001",
  "status": "success",
  "requestTrace": {
    "targetUrl": "https://api.social.com/me",
    "method": "GET"
  },
  "results": {
    "user_id": {
      "value": "user_555",
      "verified": false, // No assertion was present
      "redaction_mode": "none"
    },
    "account_type": {
      "value": "premium",
      "verified": true, // Assertion passed
      "redaction_mode": "none"
    },
    "email_domain": {
      "value": "company.com",
      "verified": true,
      "redaction_mode": "none"
    }
  },
  "integrity": {
    "hash": "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "timestamp": 1715000100
  }
}
```

---

## 6. Future Extensions
