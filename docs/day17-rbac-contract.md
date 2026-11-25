# Day 17: Role-Based Masking Policy Contract

## 1. Purpose

This document defines the role-based masking policy used by the
LLM Guard DLP engine.

The policy determines which detected sensitive entities may remain
unmasked for a particular application role.

## 2. Supported Roles

### Finance

Allowed unmasked entities:

- CREDIT_CARD
- US_SSN

All other detected sensitive entities must be masked.

### Developer

Allowed unmasked entities:

- AWS_ACCESS_KEY
- AWS_SECRET_KEY
- JWT_TOKEN
- DB_CONNECTION_STRING
- PRIVATE_KEY
- INTERNAL_IPV4

All other detected sensitive entities must be masked.

### General

No entities are allowed to remain unmasked.

All detected sensitive entities must be masked.

## 3. Default Behavior

- If role is None, all detected sensitive entities are masked.
- Unknown roles default to General.
- Role matching is case-sensitive.
- Unrecognized roles fail closed.

## 4. Engine Responsibilities

The DLP engine must:

1. Detect sensitive entities independently of the role.
2. Apply the configured masking policy.
3. Preserve authorized values.
4. Mask unauthorized values using placeholders.
5. Include a Boolean `masked` field in entity metadata.
6. Set `placeholder` to None for unmasked entities.

## 5. Interceptor Responsibilities

The DLP interceptor must:

1. Pass the supplied role to the DLP engine.
2. Allocate Redis placeholders only for masked entities.
3. Never allocate placeholders for authorized unmasked entities.
4. Remove original values from returned entity metadata.
5. Preserve session isolation and restoration behavior.

## 6. Security Boundary

The role supplied to the masking policy is currently a mock
application input.

Authentication and trusted role resolution are outside the
scope of Day 17.

In a production deployment, the role must come from a trusted
authentication and authorization layer.

Users must not be allowed to choose their own privileged role.

## 7. Fail-Closed Principle

Unknown roles and missing roles must not receive additional
permissions.

The default behavior is to mask all detected sensitive entities.

## 8. Future Integration

Trusted role resolution and authentication integration will be
implemented in the later M4 integration phase.
