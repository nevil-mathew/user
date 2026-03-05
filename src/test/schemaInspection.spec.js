'use strict'

const fs = require('fs')
const path = require('path')

const SCHEMA_DOC_PATH = path.resolve(__dirname, '../scripts/schema-inspection.md')

describe('TKT-001 — schema-inspection.md document validation', () => {
	let content

	beforeAll(() => {
		content = fs.readFileSync(SCHEMA_DOC_PATH, 'utf8')
	})

	// ─── File existence ────────────────────────────────────────────────────────

	test('schema-inspection.md exists in scripts/ directory', () => {
		expect(fs.existsSync(SCHEMA_DOC_PATH)).toBe(true)
	})

	test('file is non-empty', () => {
		expect(content.length).toBeGreaterThan(0)
	})

	// ─── Required sections ─────────────────────────────────────────────────────

	test('documents primary key structure of users table', () => {
		expect(content).toMatch(/users.*[Tt]able/i)
		expect(content).toMatch(/[Pp]rimary [Kk]ey/i)
		// Composite PK columns
		expect(content).toMatch(/\bid\b/)
		expect(content).toMatch(/tenant_code/)
	})

	test('explicitly states users PK is composite (id, tenant_code)', () => {
		// Should mention both columns together as the PK
		expect(content).toMatch(/id.*tenant_code|tenant_code.*id/i)
		expect(content).toMatch(/composite/i)
	})

	test('lists tables with foreign keys referencing users.id', () => {
		// The four active FK tables
		expect(content).toMatch(/user_organizations/)
		expect(content).toMatch(/user_sessions/)
		expect(content).toMatch(/organization_role_requests/)
		// FK constraint names
		expect(content).toMatch(/fk_user_organizations_users/)
		expect(content).toMatch(/fk_user_sessions_user/)
		expect(content).toMatch(/fk_org_role_requests_requester/)
		expect(content).toMatch(/fk_org_role_requests_handled_by/)
	})

	test('documents structure of user_organization_roles table', () => {
		expect(content).toMatch(/user_organization_roles/)
		// PK columns
		expect(content).toMatch(/tenant_code/)
		expect(content).toMatch(/user_id/)
		expect(content).toMatch(/organization_code/)
		expect(content).toMatch(/role_id/)
		// FK constraints
		expect(content).toMatch(/fk_user_org_roles_user_organizations/)
		expect(content).toMatch(/fk_user_organization_roles_role_composite/)
	})

	test('documents structure of user_roles (roles) table', () => {
		expect(content).toMatch(/user_roles/)
		// PK
		expect(content).toMatch(/tenant_code.*id|id.*tenant_code/i)
		// Key columns
		expect(content).toMatch(/title/)
		expect(content).toMatch(/organization_id/)
		expect(content).toMatch(/user_type/)
		expect(content).toMatch(/visibility/)
	})

	test('documents uniqueness constraints involving tenant_code', () => {
		expect(content).toMatch(/unique_phone_per_tenant/)
		expect(content).toMatch(/unique_username_per_tenant/)
		expect(content).toMatch(/unique_title_org_id_tenant_code/)
	})

	test('documents uniqueness constraints on users table', () => {
		// phone+tenant uniqueness
		expect(content).toMatch(/phone.*tenant_code|tenant_code.*phone/i)
		// username+tenant uniqueness
		expect(content).toMatch(/username.*tenant_code|tenant_code.*username/i)
	})

	test('clarifies that email uniqueness in users_credentials is global (not per-tenant)', () => {
		expect(content).toMatch(/users_credentials/)
		// Must mention that email is globally unique
		expect(content).toMatch(/global/i)
		expect(content).toMatch(/email/i)
	})

	test('clarifies role ID scoping (tenant-scoped vs global)', () => {
		// Must have a section or statement about role scoping
		expect(content).toMatch(/[Tt]enant-[Ss]cop/i)
		// Must explicitly state roles are NOT global
		expect(content).toMatch(/not global|tenant.scoped/i)
	})

	test('explains role ID mismatch risk across tenants', () => {
		// Must warn that role_id integers differ across tenants
		expect(content).toMatch(/remap|mapping|mismatch/i)
		// Recommend using title for cross-tenant matching
		expect(content).toMatch(/title/i)
	})

	// ─── Additional required tables ────────────────────────────────────────────

	test('documents entities table', () => {
		expect(content).toMatch(/entities/)
		expect(content).toMatch(/entity_type_id/)
	})

	test('documents entity_types table', () => {
		expect(content).toMatch(/entity_types/)
		expect(content).toMatch(/organization_code/)
	})

	test('documents notification_templates table', () => {
		expect(content).toMatch(/notification_templates/)
		expect(content).toMatch(/organization_code/)
	})

	// ─── Citus / distribution information ─────────────────────────────────────

	test('documents Citus distribution information', () => {
		expect(content).toMatch(/[Cc]itus|distributed/i)
		expect(content).toMatch(/tenant_code/)
	})

	// ─── Migration safety notes ────────────────────────────────────────────────

	test('includes migration notes / pre-validation requirements', () => {
		// Should mention pre-migration validations
		expect(content).toMatch(/[Vv]alidat/i)
		// Should mention SERIALIZABLE
		expect(content).toMatch(/SERIALIZABLE/i)
	})

	test('documents commented-out / deferred FK constraints', () => {
		// FKs on created_by / updated_by are not enforced
		expect(content).toMatch(/created_by/i)
		expect(content).toMatch(/commented.out|deferred|not.*enforced|no.*FK/i)
	})
})
