# Database Schema Inspection — Users and Related Tables

**Inspection Date:** 2026-03-05
**Database:** PostgreSQL 16 + Citus 12.1 (distributed)
**ORM:** Sequelize 6
**Source:** Derived from migration history (`src/database/migrations/`) and Sequelize model definitions (`src/database/models/`). Schema reflects the fully-migrated state after all migrations up to `20251022160602-add-tenant-admin-role.js` have been applied.

---

## Table of Contents

1. [users Table](#1-users-table)
2. [Tables with Foreign Keys Referencing users.id](#2-tables-with-foreign-keys-referencing-usersid)
3. [user_organization_roles Table](#3-user_organization_roles-table)
4. [user_roles (Roles) Table](#4-user_roles-roles-table)
5. [user_organizations Table](#5-user_organizations-table)
6. [entities Table](#6-entities-table)
7. [entity_types Table](#7-entity_types-table)
8. [notification_templates Table](#8-notification_templates-table)
9. [users_credentials Table](#9-users_credentials-table)
10. [user_sessions Table](#10-user_sessions-table)
11. [Uniqueness Constraints Summary](#11-uniqueness-constraints-summary)
12. [Role ID Scoping: Tenant-Scoped vs Global](#12-role-id-scoping-tenant-scoped-vs-global)
13. [Citus Distribution Summary](#13-citus-distribution-summary)
14. [Migration Notes for User Tenant Migration](#14-migration-notes-for-user-tenant-migration)

---

## 1. `users` Table

### Primary Key Structure

The `users` table uses a **composite primary key** consisting of two columns:

| Column        | Type    | Notes                                            |
|---------------|---------|--------------------------------------------------|
| `id`          | INTEGER | Auto-increment. Not globally unique on its own.  |
| `tenant_code` | STRING  | NOT NULL. Citus distribution column.             |

**Constraint name:** `users_pkey`
**SQL:** `PRIMARY KEY (id, tenant_code)`

> **Important:** `id` alone does NOT uniquely identify a user across the database. A user with `id = 42` can exist in multiple tenants. Uniqueness of `id` is only guaranteed within a single `tenant_code` shard.

### Evolution History

| Migration | Change |
|-----------|--------|
| `20230531105847-create-users-table.js` | Original table created with PK `(id, organization_id)` |
| `20250506091445-update-user-org-tables.js` | `organization_id` removed, `tenant_code` added; PK changed to `(id, tenant_code)` |
| `20250506095633-update-relations.js` | FK from `user_organizations` to `users(id, tenant_code)` established |

### Full Column Listing (Current State)

| Column                              | Type         | Nullable | Default    | Notes                                   |
|-------------------------------------|--------------|----------|------------|-----------------------------------------|
| `id`                                | INTEGER      | NOT NULL | auto-incr  | Part of composite PK                    |
| `tenant_code`                       | STRING       | NOT NULL | —          | Part of composite PK; FK → tenants(code)|
| `email`                             | STRING       | NULL     | —          | Made nullable in `20250509103819`       |
| `email_verified`                    | STRING       | NULL     | `'false'`  | Stored as string, not boolean           |
| `name`                              | STRING       | NOT NULL | —          |                                         |
| `username`                          | STRING       | NULL     | —          | Stored as lowercase; unique per tenant  |
| `phone`                             | STRING       | NULL     | —          | Unique per tenant                       |
| `phone_code`                        | STRING       | NULL     | —          |                                         |
| `password`                          | STRING       | NOT NULL | —          | bcrypt hash                             |
| `status`                            | STRING       | NOT NULL | `'ACTIVE'` |                                         |
| `has_accepted_terms_and_conditions` | BOOLEAN      | NOT NULL | `false`    |                                         |
| `roles`                             | INTEGER[]    | NOT NULL | —          | Denormalized legacy array; authoritative roles are in `user_organization_roles` |
| `languages`                         | STRING[]     | NULL     | —          |                                         |
| `preferred_language`                | STRING       | NULL     | `'en'`     |                                         |
| `location`                          | STRING       | NULL     | —          |                                         |
| `about`                             | TEXT         | NULL     | —          |                                         |
| `share_link`                        | STRING       | NULL     | —          |                                         |
| `image`                             | STRING       | NULL     | —          |                                         |
| `custom_entity_text`                | JSON         | NULL     | —          |                                         |
| `configs`                           | JSONB        | NULL     | —          |                                         |
| `meta`                              | JSONB        | NULL     | —          |                                         |
| `created_at`                        | DATE         | NOT NULL | —          |                                         |
| `updated_at`                        | DATE         | NOT NULL | —          |                                         |
| `deleted_at`                        | DATE         | NULL     | —          | Soft-delete (paranoid mode)             |

### Indexes on `users`

| Index Name                  | Columns                   | Type    |
|-----------------------------|---------------------------|---------|
| `users_pkey`                | `(id, tenant_code)`       | PK      |
| `idx_users_tenant_code`     | `(tenant_code)`           | B-tree  |
| `unique_phone_per_tenant`   | `(phone, tenant_code)`    | UNIQUE  |
| `unique_username_per_tenant`| `(username, tenant_code)` | UNIQUE  |

### Foreign Keys on `users`

| Constraint Name    | Column(s)     | References            | On Delete |
|--------------------|---------------|-----------------------|-----------|
| `fk_users_tenant`  | `tenant_code` | `tenants(code)`       | CASCADE   |

> **Note:** The historical FK `fk_user_organization` referencing `organizations(id)` via `organization_id` was dropped in migration `20250506091445`. The `organization_id` column itself was also removed.

---

## 2. Tables with Foreign Keys Referencing `users.id`

Because the PK is composite `(id, tenant_code)`, **all FKs reference the composite pair `(user_id, tenant_code)` → `users(id, tenant_code)`**, not `id` alone.

### Active Foreign Key Constraints

| Referencing Table              | FK Constraint Name                     | Referencing Columns            | References             | On Delete  |
|-------------------------------|----------------------------------------|--------------------------------|------------------------|------------|
| `user_organizations`          | `fk_user_organizations_users`          | `(user_id, tenant_code)`       | `users(id, tenant_code)` | — (not set) |
| `user_sessions`               | `fk_user_sessions_user`                | `(user_id, tenant_code)`       | `users(id, tenant_code)` | CASCADE    |
| `organization_role_requests`  | `fk_org_role_requests_requester`       | `(requester_id, tenant_code)`  | `users(id, tenant_code)` | CASCADE    |
| `organization_role_requests`  | `fk_org_role_requests_handled_by`      | `(handled_by, tenant_code)`    | `users(id, tenant_code)` | NO ACTION  |

### Commented-Out / Intentionally Deferred FK Constraints

The following FKs were defined in migration `20250626180047-add-pending-realtions.js` but were **commented out** and are **NOT currently enforced** in the database:

| Referencing Table        | Intended FK Column(s)           | Intended Target            | Reason Skipped                 |
|--------------------------|---------------------------------|----------------------------|--------------------------------|
| `entities`               | `(created_by, tenant_code)`     | `users(id, tenant_code)`   | Commented out — pending review |
| `entities`               | `(updated_by, tenant_code)`     | `users(id, tenant_code)`   | Commented out — pending review |
| `entity_types`           | `(created_by, tenant_code)`     | `users(id, tenant_code)`   | Commented out — pending review |
| `entity_types`           | `(updated_by, tenant_code)`     | `users(id, tenant_code)`   | Commented out — pending review |
| `file_uploads`           | `(created_by, tenant_code)`     | `users(id, tenant_code)`   | Commented out — pending review |
| `file_uploads`           | `(updated_by, tenant_code)`     | `users(id, tenant_code)`   | Commented out — pending review |
| `invitations`            | `(created_by, tenant_code)`     | `users(id, tenant_code)`   | Commented out — pending review |
| `organization_features`  | `(created_by, tenant_code)`     | `users(id, tenant_code)`   | Commented out — pending review |
| `organization_features`  | `(updated_by, tenant_code)`     | `users(id, tenant_code)`   | Commented out — pending review |
| `organization_user_invites` | `(created_by, tenant_code)`  | `users(id, tenant_code)`   | Commented out — pending review |
| `organization_email_domains` | `(created_by, tenant_code)` | `users(id, tenant_code)`   | Commented out — pending review |
| `organizations`          | `(created_by, tenant_code)`     | `users(id, tenant_code)`   | Commented out — pending review |
| `organizations`          | `(updated_by, tenant_code)`     | `users(id, tenant_code)`   | Commented out — pending review |
| `tenants`                | `(created_by, code)`            | `users(id, tenant_code)`   | Commented out — pending review |

> **⚠️ Migration Implication:** When migrating a user between tenants, only the **4 active FK constraints** above require handling at the database level. However, the `created_by` / `updated_by` columns on many tables reference `users.id` without DB enforcement — these must be handled at the **application level**.

---

## 3. `user_organization_roles` Table

This is the authoritative join table linking users, organizations, and roles within a tenant.

### Primary Key

**4-column composite primary key:**

| Column              | Type    | Notes                        |
|---------------------|---------|------------------------------|
| `tenant_code`       | STRING  | NOT NULL; Citus shard key    |
| `user_id`           | INTEGER | NOT NULL                     |
| `organization_code` | STRING  | NOT NULL                     |
| `role_id`           | INTEGER | NOT NULL                     |

**Constraint name:** `user_organization_roles_pkey`

### Full Column Listing

| Column              | Type    | Nullable | Default     |
|---------------------|---------|----------|-------------|
| `tenant_code`       | STRING  | NOT NULL | —           |
| `user_id`           | INTEGER | NOT NULL | —           |
| `organization_code` | STRING  | NOT NULL | —           |
| `role_id`           | INTEGER | NOT NULL | —           |
| `created_at`        | DATE    | NOT NULL | `NOW()`     |
| `updated_at`        | DATE    | NOT NULL | `NOW()`     |
| `deleted_at`        | DATE    | NULL     | —           |

### Foreign Key Constraints

| Constraint Name                             | Columns                                | References                                          | On Delete |
|---------------------------------------------|----------------------------------------|-----------------------------------------------------|-----------|
| `fk_user_org_roles_user_organizations`      | `(user_id, organization_code, tenant_code)` | `user_organizations(user_id, organization_code, tenant_code)` | — |
| `fk_user_organization_roles_role_composite` | `(role_id, tenant_code)`              | `user_roles(id, tenant_code)`                       | —         |

> **Note:** There is no direct FK from `user_organization_roles` to `users(id, tenant_code)`. The dependency on `users` is enforced transitively via `user_organizations → users`.

### Relationship Summary

```
users(id, tenant_code)
  └── user_organizations(user_id, organization_code, tenant_code)
        └── user_organization_roles(user_id, organization_code, role_id, tenant_code)
                                                            │
                                              user_roles(id, tenant_code)
```

---

## 4. `user_roles` (Roles) Table

### Primary Key

**2-column composite primary key** (added in migration `20250505110935`):

| Column        | Type    | Notes                            |
|---------------|---------|----------------------------------|
| `tenant_code` | STRING  | NOT NULL; Citus shard key        |
| `id`          | INTEGER | Auto-increment (within tenant)   |

**Constraint name:** `user_roles_pkey` (altered to `(tenant_code, id)`)

### Full Column Listing

| Column          | Type    | Nullable | Default    | Notes                                        |
|-----------------|---------|----------|------------|----------------------------------------------|
| `id`            | INTEGER | NOT NULL | auto-incr  | Part of composite PK                         |
| `tenant_code`   | STRING  | NOT NULL | —          | Part of composite PK; FK → tenants(code)     |
| `title`         | STRING  | NOT NULL | —          | Role identifier string (e.g., `'admin'`, `'mentor'`) |
| `label`         | STRING  | NOT NULL | —          | Display name                                 |
| `user_type`     | INTEGER | NOT NULL | —          | `0` = non-system user; `1` = system user     |
| `status`        | STRING  | NULL     | `'ACTIVE'` |                                              |
| `organization_id` | INTEGER | NOT NULL | —        | Owning organization within the tenant        |
| `visibility`    | STRING  | NULL     | `'PUBLIC'` |                                              |
| `translations`  | JSON    | NULL     | —          |                                              |
| `created_at`    | DATE    | NOT NULL | —          |                                              |
| `updated_at`    | DATE    | NOT NULL | —          |                                              |
| `deleted_at`    | DATE    | NULL     | —          | Soft-delete (paranoid mode)                  |

### Unique Constraints on `user_roles`

| Constraint / Index Name            | Columns                                      | Type                   |
|------------------------------------|----------------------------------------------|------------------------|
| `unique_title_org_id_tenant_code`  | `(title, organization_id, tenant_code)`      | PARTIAL UNIQUE INDEX `WHERE deleted_at IS NULL` |

> A role named `'admin'` can exist multiple times in different organizations or tenants but **not twice in the same `(organization_id, tenant_code)` combination** (among non-deleted rows).

### Foreign Keys on `user_roles`

| Constraint Name            | Column(s)                      | References                    | On Delete |
|----------------------------|--------------------------------|-------------------------------|-----------|
| `fk_user_roles_organization` | `(organization_id, tenant_code)` | `organizations(id, tenant_code)` | CASCADE |
| `fk_user_roles_tenant`     | `(tenant_code)`                | `tenants(code)`               | CASCADE   |

---

## 5. `user_organizations` Table

Join table linking users to organizations within a tenant.

### Primary Key

**3-column composite primary key:**

| Column              | Type    |
|---------------------|---------|
| `tenant_code`       | STRING  |
| `user_id`           | INTEGER |
| `organization_code` | STRING  |

**Constraint name:** `pk_user_organizationss` _(note: typo in migration, double 's')_

### Full Column Listing

| Column              | Type    | Nullable | Notes                        |
|---------------------|---------|----------|------------------------------|
| `user_id`           | INTEGER | NOT NULL |                              |
| `organization_code` | STRING  | NOT NULL |                              |
| `tenant_code`       | STRING  | NOT NULL | Citus shard key              |
| `created_at`        | DATE    | NOT NULL |                              |
| `updated_at`        | DATE    | NOT NULL |                              |
| `deleted_at`        | DATE    | NULL     | Soft-delete (paranoid mode)  |

### Foreign Keys on `user_organizations`

| Constraint Name                       | Columns                            | References                          | On Delete |
|---------------------------------------|------------------------------------|-------------------------------------|-----------|
| `fk_user_organizations_users`         | `(user_id, tenant_code)`           | `users(id, tenant_code)`            | —         |
| `fk_user_organizations_organizations` | `(organization_code, tenant_code)` | `organizations(code, tenant_code)`  | —         |

### Indexes on `user_organizations`

| Index Name                           | Columns                            |
|--------------------------------------|------------------------------------|
| `idx_user_organizations_tenant_code` | `(tenant_code)`                    |
| `idx_user_organizations_user_tenant` | `(user_id, tenant_code)`           |
| `idx_user_organizations_org_tenant`  | `(organization_code, tenant_code)` |

---

## 6. `entities` Table

Stores entity values scoped to organization and tenant.

### Primary Key

**2-column composite primary key** (added in migration `20250626180045`):

| Column        | Type    |
|---------------|---------|
| `id`          | INTEGER |
| `tenant_code` | STRING  |

**Constraint name:** `entities_pkey`

### Full Column Listing

| Column              | Type    | Nullable | Default    |
|---------------------|---------|----------|------------|
| `id`                | INTEGER | NOT NULL | auto-incr  |
| `entity_type_id`    | INTEGER | NOT NULL | —          |
| `value`             | STRING  | NOT NULL | —          |
| `label`             | STRING  | NOT NULL | —          |
| `status`            | STRING  | NOT NULL | `'ACTIVE'` |
| `type`              | STRING  | NULL     | —          |
| `tenant_code`       | STRING  | NOT NULL | —          |
| `organization_code` | STRING  | NOT NULL | —          |
| `created_by`        | INTEGER | NULL     | —          |
| `updated_by`        | INTEGER | NULL     | —          |
| `created_at`        | DATE    | NOT NULL | —          |
| `updated_at`        | DATE    | NOT NULL | —          |
| `deleted_at`        | DATE    | NULL     | —          |

### Unique Constraints / Indexes on `entities`

_(The standalone `unique_entities_value_type_tenant` constraint was dropped and replaced by FK-backed uniqueness.)_

### Foreign Keys on `entities`

| Constraint Name                        | Columns                                          | References                                      | On Delete |
|----------------------------------------|--------------------------------------------------|-------------------------------------------------|-----------|
| `fk_entities_entity_type`              | `(entity_type_id, tenant_code)`                  | `entity_types(id, tenant_code)`                 | CASCADE   |
| `fk_entities_to_entity_types_composite`| `(entity_type_id, organization_code, tenant_code)` | `entity_types(id, organization_code, tenant_code)` | CASCADE |

> `created_by` and `updated_by` store `users.id` values but have **no enforced FK constraint** (intentionally deferred — see §2).

---

## 7. `entity_types` Table

Defines custom entity type schemas, scoped to organization and tenant.

### Primary Key

**2-column composite primary key** (added in migration `20250505090535`):

| Column        | Type    |
|---------------|---------|
| `tenant_code` | STRING  |
| `id`          | INTEGER |

### Full Column Listing

| Column                  | Type      | Nullable | Default    |
|-------------------------|-----------|----------|------------|
| `id`                    | INTEGER   | NOT NULL | auto-incr  |
| `tenant_code`           | STRING    | NOT NULL | —          |
| `value`                 | STRING    | NOT NULL | —          |
| `label`                 | STRING    | NOT NULL | —          |
| `status`                | STRING    | NOT NULL | `'ACTIVE'` |
| `created_by`            | INTEGER   | NULL     | —          |
| `updated_by`            | INTEGER   | NULL     | —          |
| `allow_filtering`       | BOOLEAN   | NOT NULL | `false`    |
| `data_type`             | STRING    | NOT NULL | `'STRING'` |
| `organization_id`       | INTEGER   | NOT NULL | —          |
| `organization_code`     | STRING    | NOT NULL | —          |
| `parent_id`             | INTEGER   | NULL     | —          |
| `allow_custom_entities` | BOOLEAN   | NOT NULL | `true`     |
| `has_entities`          | BOOLEAN   | NOT NULL | `true`     |
| `model_names`           | STRING[]  | NULL     | —          |
| `required`              | BOOLEAN   | NOT NULL | `false`    |
| `regex`                 | STRING    | NULL     | —          |
| `meta`                  | JSONB     | NULL     | —          |
| `external_entity_type`  | BOOLEAN   | NOT NULL | `false`    |
| `created_at`            | DATE      | NOT NULL | —          |
| `updated_at`            | DATE      | NOT NULL | —          |
| `deleted_at`            | DATE      | NULL     | —          |

### Unique Constraints / Indexes on `entity_types`

| Name                              | Columns / Expression                           | Type                              |
|-----------------------------------|------------------------------------------------|-----------------------------------|
| `unique_value_org_code_tenant_code` | `(value, organization_code, tenant_code) WHERE deleted_at IS NULL` | PARTIAL UNIQUE INDEX |
| `unique_entity_types_id_org_tenant` | `(id, organization_code, tenant_code)`       | UNIQUE constraint                 |

### Foreign Keys on `entity_types`

| Constraint Name                 | Columns                        | References                          | On Delete |
|---------------------------------|--------------------------------|-------------------------------------|-----------|
| `fk_entity_types_organization`  | `(organization_id, tenant_code)` | `organizations(id, tenant_code)`  | CASCADE   |
| `fk_entity_types_parent`        | `(parent_id, tenant_code)`     | `entity_types(id, tenant_code)`     | NO ACTION |
| `fk_entity_types_tenant`        | `(tenant_code)`                | `tenants(code)`                     | CASCADE   |

---

## 8. `notification_templates` Table

Stores email/SMS notification templates, scoped to organization and tenant.

### Primary Key

**2-column composite primary key** (added in migration `20250505090639`):

| Column        | Type    |
|---------------|---------|
| `tenant_code` | STRING  |
| `id`          | INTEGER |

### Full Column Listing

| Column              | Type    | Nullable | Default    | Notes                                   |
|---------------------|---------|----------|------------|-----------------------------------------|
| `id`                | INTEGER | NOT NULL | auto-incr  |                                         |
| `tenant_code`       | STRING  | NOT NULL | —          | Citus shard key                         |
| `organization_code` | STRING  | NOT NULL | —          | Added in `20250710130554`; replaces `organization_id` |
| `type`              | STRING  | NOT NULL | —          |                                         |
| `code`              | STRING  | NOT NULL | —          |                                         |
| `subject`           | STRING  | NULL     | —          |                                         |
| `body`              | TEXT    | NOT NULL | —          |                                         |
| `status`            | STRING  | NOT NULL | `'ACTIVE'` |                                         |
| `email_header`      | STRING  | NULL     | —          |                                         |
| `email_footer`      | STRING  | NULL     | —          |                                         |
| `created_by`        | STRING  | NULL     | —          | Stored as STRING (not INTEGER)          |
| `updated_by`        | INTEGER | NULL     | —          |                                         |
| `created_at`        | DATE    | NOT NULL | —          |                                         |
| `updated_at`        | DATE    | NOT NULL | —          |                                         |
| `deleted_at`        | DATE    | NULL     | —          | Soft-delete (paranoid mode)             |

> **Note:** `organization_id` column was removed in migration `20250710130554`; replaced by `organization_code`.

### Unique Constraints on `notification_templates`

| Constraint Name                             | Columns                                            |
|---------------------------------------------|----------------------------------------------------|
| `unique_type_code_organization_code_tenant_code` | `(type, code, organization_code, tenant_code)` |

### Foreign Keys on `notification_templates`

| Constraint Name                         | Columns                           | References                     | On Delete |
|-----------------------------------------|-----------------------------------|--------------------------------|-----------|
| `fk_notification_templates_organization` | `(organization_id, tenant_code)` | `organizations(id, tenant_code)` | CASCADE |
| `fk_notification_templates_tenant`      | `(tenant_code)`                   | `tenants(code)`                | CASCADE   |

> **⚠️ Note:** The FK `fk_notification_templates_organization` references `organization_id`, but that column was dropped in `20250710130554`. It is possible this FK was also dropped at that time — verify in the live database.

---

## 9. `users_credentials` Table

Stores authentication credentials (email + password). This table is **NOT distributed** by `tenant_code`; it is a cross-tenant global lookup table.

### Primary Key

| Column  | Type   | Notes                                |
|---------|--------|--------------------------------------|
| `email` | STRING | Primary key (unique globally)        |

**Constraint name:** `users_credentials_pkey`

### Full Column Listing

| Column                       | Type    | Nullable | Notes                              |
|------------------------------|---------|----------|------------------------------------|
| `id`                         | INTEGER | NOT NULL | Auto-increment; not part of PK     |
| `email`                      | STRING  | NOT NULL | PK; globally unique across tenants |
| `password`                   | STRING  | NULL     |                                    |
| `organization_id`            | INTEGER | NULL     | Legacy field                       |
| `user_id`                    | INTEGER | NULL     | References `users.id` (no FK enforced) |
| `organization_user_invite_id`| INTEGER | NULL     |                                    |
| `meta`                       | JSONB   | NULL     |                                    |
| `created_at`                 | DATE    | NOT NULL |                                    |
| `updated_at`                 | DATE    | NOT NULL |                                    |
| `deleted_at`                 | DATE    | NULL     | Soft-delete (paranoid mode)        |

### Unique Constraints on `users_credentials`

| Index Name                            | Columns   | Type                                   |
|---------------------------------------|-----------|----------------------------------------|
| _(partial unique index on email)_     | `(email)` | PARTIAL UNIQUE INDEX `WHERE deleted_at IS NULL` |

> **⚠️ Important:** Email is unique **globally** in `users_credentials` — **not per tenant**. This means a user's email cannot be registered under two different tenants simultaneously. This is a critical constraint for any cross-tenant user migration.

---

## 10. `user_sessions` Table

Stores JWT session tokens for active user sessions.

### Primary Key

**3-column composite primary key** (added in migration `20250626180043`):

| Column        | Type    |
|---------------|---------|
| `id`          | INTEGER |
| `user_id`     | INTEGER |
| `tenant_code` | STRING  |

**Constraint name:** `user_sessions_pkey`

### Full Column Listing

| Column          | Type    | Nullable | Default |
|-----------------|---------|----------|---------|
| `id`            | INTEGER | NOT NULL | auto-incr |
| `user_id`       | INTEGER | NOT NULL | —         |
| `tenant_code`   | STRING  | NOT NULL | —         |
| `started_at`    | BIGINT  | NOT NULL | —         |
| `ended_at`      | BIGINT  | NULL     | —         |
| `token`         | TEXT    | NULL     | —         |
| `device_info`   | JSONB   | NULL     | —         |
| `refresh_token` | TEXT    | NULL     | —         |
| `created_at`    | DATE    | NOT NULL | —         |
| `updated_at`    | DATE    | NOT NULL | —         |
| `deleted_at`    | DATE    | NULL     | —         |

### Foreign Keys on `user_sessions`

| Constraint Name          | Columns                  | References              | On Delete |
|--------------------------|--------------------------|-------------------------|-----------|
| `fk_user_sessions_user`  | `(user_id, tenant_code)` | `users(id, tenant_code)` | CASCADE  |

---

## 11. Uniqueness Constraints Summary

Constraints involving `tenant_code` across user-related tables:

| Table                   | Constraint / Index Name                       | Columns                                            | Scope         |
|-------------------------|-----------------------------------------------|----------------------------------------------------|---------------|
| `users`                 | `unique_phone_per_tenant`                     | `(phone, tenant_code)`                             | Per-tenant    |
| `users`                 | `unique_username_per_tenant`                  | `(username, tenant_code)`                          | Per-tenant    |
| `users_credentials`     | _(partial unique index)_                      | `(email) WHERE deleted_at IS NULL`                 | **Global**    |
| `user_roles`            | `unique_title_org_id_tenant_code`             | `(title, organization_id, tenant_code) WHERE deleted_at IS NULL` | Per-tenant + per-org |
| `user_organizations`    | `pk_user_organizationss`                      | `(tenant_code, user_id, organization_code)` — PK  | Per-tenant    |
| `user_organization_roles`| `user_organization_roles_pkey`               | `(tenant_code, user_id, organization_code, role_id)` — PK | Per-tenant |
| `organizations`         | `unique_org_code_per_tenant`                  | `(code, tenant_code)`                              | Per-tenant    |
| `notification_templates`| `unique_type_code_organization_code_tenant_code` | `(type, code, organization_code, tenant_code)` | Per-tenant    |
| `entity_types`          | `unique_value_org_code_tenant_code`           | `(value, organization_code, tenant_code) WHERE deleted_at IS NULL` | Per-tenant + per-org |
| `entity_types`          | `unique_entity_types_id_org_tenant`           | `(id, organization_code, tenant_code)`             | Per-tenant    |

> **Key finding for tenant migration:** Email uniqueness is **global** (enforced via `users_credentials`). A user with email `user@example.com` in Tenant A cannot be re-registered in Tenant B without first removing/modifying the `users_credentials` entry.

---

## 12. Role ID Scoping: Tenant-Scoped vs Global

### Verdict: **Roles are Tenant-Scoped (AND Organization-Scoped)**

Roles in the `user_roles` table are **not global**. They are scoped by both `tenant_code` and `organization_id`:

1. **PK is composite `(tenant_code, id)`** — `id` is only unique within a tenant.
2. **FK from `user_organization_roles`** references `user_roles(id, tenant_code)` — the tenant must match.
3. **Unique constraint** is `(title, organization_id, tenant_code) WHERE deleted_at IS NULL` — a role title is unique per-organization per-tenant.
4. **`organization_id` field** in `user_roles` — each role is owned by a specific organization within a tenant.

### Consequences for Cross-Tenant Migration

| Scenario | Risk |
|----------|------|
| User in Tenant A has `role_id = 5` (`'mentor'`) | The same `role_id = 5` in Tenant B may be a completely different role (e.g., `'admin'`) or may not exist at all |
| Copying `user_organization_roles` rows directly | Will fail or silently corrupt data if `role_id` values are not validated and remapped |
| Role names (`title`) can be matched across tenants | But the integer `role_id` **must be remapped** from source-tenant to target-tenant values |

### Built-in System Roles (Cross-Tenant Consistency via Title)

System roles (seeded via migrations) are created per-tenant with the same `title` value:
- `'admin'`
- `'mentor'`
- `'mentee'`
- `'session_manager'`
- `'public'`
- `'tenant_admin'`

These roles will have **different `id` values** across tenants but the same `title`. **Use `title` (not `id`) for cross-tenant role mapping.**

---

## 13. Citus Distribution Summary

Tables distributed by `tenant_code` (co-located shards — cross-table JOINs supported within same tenant):

| Table                        | Distribution Column |
|------------------------------|---------------------|
| `tenants`                    | `code`              |
| `users`                      | `tenant_code`       |
| `organizations`              | `tenant_code`       |
| `user_organizations`         | `tenant_code`       |
| `user_organization_roles`    | `tenant_code`       |
| `user_roles`                 | `tenant_code`       |
| `user_sessions`              | `tenant_code`       |
| `entity_types`               | `tenant_code`       |
| `entities`                   | `tenant_code`       |
| `notification_templates`     | `tenant_code`       |
| `forms`                      | `tenant_code`       |
| `file_uploads`               | `tenant_code`       |
| `organization_features`      | `tenant_code`       |
| `organization_email_domains` | `tenant_code`       |
| `organization_role_requests` | `tenant_code`       |
| `organization_user_invites`  | `tenant_code`       |
| `invitations`                | `tenant_code`       |
| `feature_role_mapping`       | `tenant_code`       |
| `organization_registration_codes` | `tenant_code`  |
| `features`                   | reference table     |
| `tenant_domains`             | `domain`            |
| `users_credentials`          | **NOT distributed** |

> Tables not in this list (`permissions`, `modules`, `role_permission_mapping`) are likely reference/global tables.

---

## 14. Migration Notes for User Tenant Migration

Based on the schema findings above, a cross-tenant user migration script must handle the following tables and constraints:

### Tables Requiring Direct Row Updates

| Table                  | Action Required                                      | Constraint to Handle                                |
|------------------------|------------------------------------------------------|-----------------------------------------------------|
| `users`                | Update `tenant_code`                                 | Composite PK change; `fk_users_tenant` check        |
| `user_organizations`   | Delete old rows; insert new rows with new `tenant_code` | `pk_user_organizationss` + FK to `users` + FK to `organizations` |
| `user_organization_roles` | Delete old rows; insert new with new `tenant_code` + remapped `role_id` | `user_organization_roles_pkey` + FK to `user_roles` |
| `user_sessions`        | Delete (cascade) or update `tenant_code`             | `fk_user_sessions_user` → CASCADE on user delete   |

### Tables Requiring Application-Level Cleanup (No DB FK)

| Table                        | Column(s) to Review | Notes                                             |
|------------------------------|---------------------|---------------------------------------------------|
| `entities`                   | `created_by`, `updated_by` | No FK; references `users.id` by convention |
| `entity_types`               | `created_by`, `updated_by` | No FK                                      |
| `file_uploads`               | `created_by`, `updated_by` | No FK                                      |
| `invitations`                | `created_by`        | No FK                                             |
| `organization_features`      | `created_by`, `updated_by` | No FK                                      |
| `organization_user_invites`  | `created_by`        | No FK                                             |
| `organizations`              | `created_by`, `updated_by` | No FK                                      |

### Critical Pre-Migration Validations

1. **Email uniqueness check:** Verify no active `users_credentials` entry exists for the target tenant's email (global constraint).
2. **Role mapping:** Build a mapping `{ source_tenant_role_id → target_tenant_role_id }` by matching `role.title` across tenants within the same `organization_code` or default organization.
3. **Organization existence:** Verify the user's organization(s) exist in the target tenant (`organizations` table with `tenant_code = target`).
4. **Tenant existence:** Verify `tenants` table has an active row with `code = target_tenant_code`.
5. **No duplicate user:** Verify no existing `users` row exists with same `id` + `tenant_code = target` (risk of ID collision within same Citus shard).

### Isolation Level Recommendation

Use `SERIALIZABLE` isolation to prevent concurrent writes from interleaving during the multi-table update sequence.
