'use strict'

/**
 * move-users-between-tenants.js
 *
 * Production-safe, transactional migration script to move all users that
 * belong to a given organisation (currentOrgId) inside one tenant
 * (currentTenantCode) to a different tenant (newTenantCode).
 *
 * Usage:
 *   node src/scripts/move-users-between-tenants.js \
 *     --currentTenantCode X \
 *     --currentOrgId 123  \
 *     --newTenantCode Y
 *
 * Exit codes:
 *   0 – migration completed successfully
 *   1 – validation failure, migration skipped, or unrecoverable error
 *
 * Design constraints (TKT-002):
 *   - Raw SQL only via sequelize.query() — no ORM models
 *   - SERIALIZABLE transaction isolation
 *   - Pre-migration: count users, check (id, newTenantCode) duplicates
 *   - Post-migration: compare user counts before/after
 *   - Full rollback on any mismatch or error
 *   - No Kafka events / webhook side-effects
 */

// ─── Bootstrap ────────────────────────────────────────────────────────────────
// module-alias is registered only when the file is the entry point so that
// test environments can require the exported helpers without side-effects.
if (require.main === module) {
	require('module-alias/register')
	require('dotenv').config({ path: '../.env' })
}

const minimist = require('minimist')
const { Sequelize, Transaction } = require('sequelize')

// ─── CLI Argument Parsing ─────────────────────────────────────────────────────
const cliArgs = minimist(process.argv.slice(2), {
	string: ['currentTenantCode', 'newTenantCode'],
})

// ─── Structured Logger ────────────────────────────────────────────────────────

/**
 * Emit a structured JSON log line to stdout/stderr.
 *
 * @param {'info'|'warn'|'error'|'debug'} level
 * @param {string} message
 * @param {object|null} [data]
 */
function log(level, message, data = null) {
	const entry = {
		timestamp: new Date().toISOString(),
		level: level.toUpperCase(),
		script: 'move-users-between-tenants',
		message,
	}
	if (data !== null && data !== undefined) {
		entry.data = data
	}
	const line = JSON.stringify(entry)
	if (level === 'error') {
		console.error(line)
	} else {
		console.log(line)
	}
}

// ─── Argument Validation (pure — exported for tests) ─────────────────────────

/**
 * Validate the raw argv object produced by minimist.
 *
 * @param {object} args - Raw minimist output
 * @returns {{ valid: boolean, errors?: string[], params?: object }}
 */
function parseAndValidateArgs(args) {
	const errors = []
	const { currentTenantCode, currentOrgId, newTenantCode } = args

	if (!currentTenantCode || typeof currentTenantCode !== 'string' || !currentTenantCode.trim()) {
		errors.push('--currentTenantCode is required and must be a non-empty string')
	}

	if (currentOrgId === undefined || currentOrgId === null || currentOrgId === '') {
		errors.push('--currentOrgId is required')
	} else {
		const parsed = parseInt(currentOrgId, 10)
		if (isNaN(parsed) || parsed <= 0) {
			errors.push('--currentOrgId must be a positive integer')
		}
	}

	if (!newTenantCode || typeof newTenantCode !== 'string' || !newTenantCode.trim()) {
		errors.push('--newTenantCode is required and must be a non-empty string')
	}

	if (
		currentTenantCode &&
		newTenantCode &&
		typeof currentTenantCode === 'string' &&
		typeof newTenantCode === 'string' &&
		currentTenantCode.trim() === newTenantCode.trim()
	) {
		errors.push('--currentTenantCode and --newTenantCode must be different')
	}

	if (errors.length > 0) {
		return { valid: false, errors }
	}

	return {
		valid: true,
		params: {
			currentTenantCode: currentTenantCode.trim(),
			currentOrgId: parseInt(currentOrgId, 10),
			newTenantCode: newTenantCode.trim(),
		},
	}
}

// ─── Post-migration Count Validator (pure — exported for tests) ───────────────

/**
 * Returns true iff both counts are identical integers.
 *
 * @param {number} preMigrationCount
 * @param {number} postMigrationCount
 * @returns {boolean}
 */
function validateCountMatch(preMigrationCount, postMigrationCount) {
	return (
		typeof preMigrationCount === 'number' &&
		typeof postMigrationCount === 'number' &&
		preMigrationCount === postMigrationCount
	)
}

// ─── Sequelize Factory ────────────────────────────────────────────────────────

/**
 * Build a Sequelize instance from the project's postgres.js config.
 * The logging callback routes to the script logger.
 *
 * @returns {Sequelize}
 */
function createSequelizeInstance() {
	const postgresConfig = require('../configs/postgres.js')
	const nodeEnv = process.env.NODE_ENV || 'development'
	const config = postgresConfig[nodeEnv]

	if (!config || !config.url) {
		throw new Error(`No database URL found for NODE_ENV="${nodeEnv}" in configs/postgres.js`)
	}

	return new Sequelize(config.url, {
		dialect: 'postgres',
		logging: (msg) => log('debug', msg),
		pool: config.pool || {},
		dialectOptions: config.dialectOptions || {},
	})
}

// ─── Raw SQL Helpers ──────────────────────────────────────────────────────────
// All functions below take a live Sequelize instance + transaction object.
// None of them use ORM models.

/**
 * Verify the target tenant exists and is not soft-deleted.
 */
async function validateTargetTenantExists(sequelize, newTenantCode, transaction) {
	const [rows] = await sequelize.query(
		`SELECT code
		   FROM tenants
		  WHERE code = :newTenantCode
		    AND deleted_at IS NULL
		  LIMIT 1`,
		{ replacements: { newTenantCode }, transaction, type: sequelize.QueryTypes.SELECT }
	)
	return Array.isArray(rows) ? rows.length > 0 : !!rows
}

/**
 * Return all distinct users (id, tenant_code) that belong to the given org
 * within the given tenant.  Only non-deleted users are returned.
 */
async function fetchUsersToMigrate(sequelize, { currentTenantCode, currentOrgId }, transaction) {
	const [users] = await sequelize.query(
		`SELECT DISTINCT u.id, u.tenant_code
		   FROM users u
		   JOIN user_organizations uo
		     ON uo.user_id    = u.id
		    AND uo.tenant_code = u.tenant_code
		   JOIN organizations o
		     ON o.code         = uo.organization_code
		    AND o.tenant_code   = uo.tenant_code
		  WHERE u.tenant_code   = :currentTenantCode
		    AND o.id            = :currentOrgId
		    AND u.deleted_at IS NULL`,
		{
			replacements: { currentTenantCode, currentOrgId },
			transaction,
			raw: true,
		}
	)
	return users
}

/**
 * Check whether any of the given user IDs already exist in the target tenant.
 * Returns duplicate rows (id, tenant_code) — empty array means no conflicts.
 */
async function checkDuplicatesInTarget(sequelize, userIds, newTenantCode, transaction) {
	if (!userIds || userIds.length === 0) return []

	const [duplicates] = await sequelize.query(
		`SELECT id, tenant_code
		   FROM users
		  WHERE id         IN (:userIds)
		    AND tenant_code = :newTenantCode`,
		{
			replacements: { userIds, newTenantCode },
			transaction,
			raw: true,
		}
	)
	return duplicates
}

/**
 * Build a { oldRoleId -> newRoleId } mapping by matching role titles across
 * tenants.  user_roles are TENANT-SCOPED so IDs are NOT portable; title is
 * used as the stable key.
 *
 * Unmapped roles (no matching title in target) are omitted from the result —
 * callers must decide what to do with them.
 */
async function buildRoleMapping(sequelize, roleIds, currentTenantCode, newTenantCode, transaction) {
	if (!roleIds || roleIds.length === 0) return {}

	const [currentRoles] = await sequelize.query(
		`SELECT id, title
		   FROM user_roles
		  WHERE id          IN (:roleIds)
		    AND tenant_code  = :currentTenantCode
		    AND deleted_at  IS NULL`,
		{
			replacements: { roleIds, currentTenantCode },
			transaction,
			raw: true,
		}
	)

	if (currentRoles.length === 0) return {}

	const titles = [...new Set(currentRoles.map((r) => r.title))]

	const [targetRoles] = await sequelize.query(
		`SELECT id, title
		   FROM user_roles
		  WHERE title       IN (:titles)
		    AND tenant_code  = :newTenantCode
		    AND deleted_at  IS NULL`,
		{
			replacements: { titles, newTenantCode },
			transaction,
			raw: true,
		}
	)

	const titleToTargetId = {}
	for (const role of targetRoles) {
		titleToTargetId[role.title] = role.id
	}

	const mapping = {}
	for (const role of currentRoles) {
		if (titleToTargetId[role.title] !== undefined) {
			mapping[role.id] = titleToTargetId[role.title]
		}
	}

	return mapping
}

/**
 * INSERT all matching user rows under the newTenantCode, preserving all
 * column values exactly (including soft-delete markers and timestamps).
 */
async function migrateUsers(sequelize, userIds, currentTenantCode, newTenantCode, transaction) {
	await sequelize.query(
		`INSERT INTO users (
		    id, tenant_code, name, email, email_verified, password, status, roles,
		    has_accepted_terms_and_conditions, about, location, languages,
		    preferred_language, share_link, last_logged_in_at, image,
		    custom_entity_text, meta, phone, phone_code, username, configs,
		    created_at, updated_at, deleted_at
		 )
		 SELECT
		    id, :newTenantCode, name, email, email_verified, password, status, roles,
		    has_accepted_terms_and_conditions, about, location, languages,
		    preferred_language, share_link, last_logged_in_at, image,
		    custom_entity_text, meta, phone, phone_code, username, configs,
		    created_at, updated_at, deleted_at
		   FROM users
		  WHERE id         IN (:userIds)
		    AND tenant_code = :currentTenantCode`,
		{
			replacements: { newTenantCode, userIds, currentTenantCode },
			transaction,
			raw: true,
		}
	)
}

/**
 * INSERT user_organizations rows for the migrated users under newTenantCode.
 */
async function migrateUserOrganizations(sequelize, userIds, currentTenantCode, newTenantCode, transaction) {
	await sequelize.query(
		`INSERT INTO user_organizations (user_id, organization_code, tenant_code, created_at, updated_at, deleted_at)
		 SELECT user_id, organization_code, :newTenantCode, created_at, updated_at, deleted_at
		   FROM user_organizations
		  WHERE user_id     IN (:userIds)
		    AND tenant_code  = :currentTenantCode`,
		{
			replacements: { newTenantCode, userIds, currentTenantCode },
			transaction,
			raw: true,
		}
	)
}

/**
 * INSERT user_organization_roles rows with role IDs remapped via roleMapping.
 * Rows whose role_id has no mapping are silently skipped (logged by caller).
 */
async function migrateUserOrganizationRoles(
	sequelize,
	userIds,
	currentTenantCode,
	newTenantCode,
	roleMapping,
	transaction
) {
	const entries = Object.entries(roleMapping)
	if (entries.length === 0) {
		log('warn', 'No role mapping available — skipping user_organization_roles migration')
		return
	}

	// Build an inline CASE expression: CASE role_id WHEN 1 THEN 10 … ELSE NULL END
	const caseExpr = entries.map(([oldId, newId]) => `WHEN ${parseInt(oldId, 10)} THEN ${parseInt(newId, 10)}`).join(' ')

	await sequelize.query(
		`INSERT INTO user_organization_roles
		    (tenant_code, user_id, organization_code, role_id, created_at, updated_at, deleted_at)
		 SELECT
		    :newTenantCode,
		    user_id,
		    organization_code,
		    CASE role_id ${caseExpr} ELSE NULL END,
		    created_at,
		    updated_at,
		    deleted_at
		   FROM user_organization_roles
		  WHERE user_id     IN (:userIds)
		    AND tenant_code  = :currentTenantCode
		    AND (CASE role_id ${caseExpr} ELSE NULL END) IS NOT NULL`,
		{
			replacements: { newTenantCode, userIds, currentTenantCode },
			transaction,
			raw: true,
		}
	)
}

/**
 * INSERT pending (non-deleted) organization_role_requests for the migrated
 * users under newTenantCode, preserving the request payload.
 */
async function migrateOrgRoleRequests(sequelize, userIds, currentTenantCode, newTenantCode, transaction) {
	await sequelize.query(
		`INSERT INTO organization_role_requests
		    (tenant_code, requester_id, role, organization_id, status,
		     handled_by, created_at, updated_at, deleted_at)
		 SELECT
		    :newTenantCode, requester_id, role, organization_id, status,
		    handled_by, created_at, updated_at, deleted_at
		   FROM organization_role_requests
		  WHERE requester_id IN (:userIds)
		    AND tenant_code   = :currentTenantCode
		    AND deleted_at   IS NULL`,
		{
			replacements: { newTenantCode, userIds, currentTenantCode },
			transaction,
			raw: true,
		}
	)
}

/**
 * Nullify handled_by references in the OLD tenant to avoid NO ACTION FK
 * violations when deleting users.  Only rows not already migrated are updated.
 */
async function nullifyHandledByReferences(sequelize, userIds, currentTenantCode, transaction) {
	await sequelize.query(
		`UPDATE organization_role_requests
		    SET handled_by = NULL
		  WHERE handled_by  IN (:userIds)
		    AND tenant_code  = :currentTenantCode`,
		{
			replacements: { userIds, currentTenantCode },
			transaction,
			raw: true,
		}
	)
}

/**
 * Hard-delete old organization_role_requests in the source tenant.
 * (The CASCADE on requester_id FK would handle this when users are deleted,
 * but explicit deletion gives us control and better logging.)
 */
async function deleteOldOrgRoleRequests(sequelize, userIds, currentTenantCode, transaction) {
	await sequelize.query(
		`DELETE FROM organization_role_requests
		  WHERE requester_id IN (:userIds)
		    AND tenant_code   = :currentTenantCode`,
		{
			replacements: { userIds, currentTenantCode },
			transaction,
			raw: true,
		}
	)
}

/**
 * Hard-delete old user_organization_roles rows.
 * Must run BEFORE deleting user_organizations (FK constraint order).
 */
async function deleteOldUserOrganizationRoles(sequelize, userIds, currentTenantCode, transaction) {
	await sequelize.query(
		`DELETE FROM user_organization_roles
		  WHERE user_id     IN (:userIds)
		    AND tenant_code  = :currentTenantCode`,
		{
			replacements: { userIds, currentTenantCode },
			transaction,
			raw: true,
		}
	)
}

/**
 * Hard-delete old user_sessions (users must re-authenticate in the new tenant).
 * CASCADE from users(id, tenant_code) would handle this, but explicit
 * deletion makes the intent clear.
 */
async function deleteOldUserSessions(sequelize, userIds, currentTenantCode, transaction) {
	await sequelize.query(
		`DELETE FROM user_sessions
		  WHERE user_id     IN (:userIds)
		    AND tenant_code  = :currentTenantCode`,
		{
			replacements: { userIds, currentTenantCode },
			transaction,
			raw: true,
		}
	)
}

/**
 * Hard-delete old user_organizations rows.
 * Must run BEFORE deleting users (FK constraint order; no ON DELETE CASCADE).
 */
async function deleteOldUserOrganizations(sequelize, userIds, currentTenantCode, transaction) {
	await sequelize.query(
		`DELETE FROM user_organizations
		  WHERE user_id     IN (:userIds)
		    AND tenant_code  = :currentTenantCode`,
		{
			replacements: { userIds, currentTenantCode },
			transaction,
			raw: true,
		}
	)
}

/**
 * Hard-delete the source user rows.  All FK-dependent rows must already be
 * deleted or NULLified before this call.
 */
async function deleteOldUsers(sequelize, userIds, currentTenantCode, transaction) {
	await sequelize.query(
		`DELETE FROM users
		  WHERE id         IN (:userIds)
		    AND tenant_code = :currentTenantCode`,
		{
			replacements: { userIds, currentTenantCode },
			transaction,
			raw: true,
		}
	)
}

/**
 * Count how many of the given user IDs now exist in newTenantCode.
 * Used for post-migration validation.
 *
 * @returns {number}
 */
async function countUsersInNewTenant(sequelize, userIds, newTenantCode, transaction) {
	const [rows] = await sequelize.query(
		`SELECT COUNT(*) AS count
		   FROM users
		  WHERE id         IN (:userIds)
		    AND tenant_code = :newTenantCode`,
		{
			replacements: { userIds, newTenantCode },
			transaction,
			raw: true,
		}
	)
	return parseInt(rows[0].count, 10)
}

// ─── Core Migration Orchestrator ──────────────────────────────────────────────

/**
 * Execute the full user migration within a single SERIALIZABLE transaction.
 * Rolls back completely on any error.
 *
 * @param {Sequelize} sequelize  - Live Sequelize instance
 * @param {{ currentTenantCode: string, currentOrgId: number, newTenantCode: string }} params
 * @returns {Promise<{ success: boolean, migratedCount?: number, reason?: string }>}
 */
async function run(sequelize, params) {
	const { currentTenantCode, currentOrgId, newTenantCode } = params
	let transaction = null

	try {
		log('info', 'Starting user migration', { currentTenantCode, currentOrgId, newTenantCode })

		// ── Step 1: Open SERIALIZABLE transaction ──────────────────────────────
		transaction = await sequelize.transaction({
			isolationLevel: Transaction.ISOLATION_LEVELS.SERIALIZABLE,
		})
		log('info', 'SERIALIZABLE transaction opened')

		// ── Step 2: Validate target tenant exists ──────────────────────────────
		const targetExists = await validateTargetTenantExists(sequelize, newTenantCode, transaction)
		if (!targetExists) {
			throw new Error(`Target tenant '${newTenantCode}' does not exist or is deleted`)
		}
		log('info', `Target tenant '${newTenantCode}' confirmed`)

		// ── Step 3: Identify users to migrate ─────────────────────────────────
		const usersToMigrate = await fetchUsersToMigrate(sequelize, { currentTenantCode, currentOrgId }, transaction)
		const preMigrationCount = usersToMigrate.length

		if (preMigrationCount === 0) {
			log('warn', 'No users found for the specified tenant/org — aborting', {
				currentTenantCode,
				currentOrgId,
			})
			await transaction.rollback()
			transaction = null
			return { success: false, reason: 'NO_USERS_FOUND' }
		}

		log('info', `Pre-migration user count: ${preMigrationCount}`, { currentTenantCode, currentOrgId })
		const userIds = usersToMigrate.map((u) => u.id)

		// ── Step 4: Pre-migration — check for (id, newTenantCode) duplicates ──
		const duplicates = await checkDuplicatesInTarget(sequelize, userIds, newTenantCode, transaction)
		if (duplicates.length > 0) {
			const duplicateIds = duplicates.map((d) => d.id)
			throw new Error(
				`Pre-migration validation failed: ${duplicates.length} user(s) with ID(s) ` +
					`[${duplicateIds.join(', ')}] already exist in tenant '${newTenantCode}'. ` +
					`Remove or resolve conflicts before migrating.`
			)
		}
		log('info', 'Pre-migration duplicate check passed — no conflicts found in target tenant')

		// ── Step 5: Build role mapping (title-based — roles are tenant-scoped) ─
		const [roleRows] = await sequelize.query(
			`SELECT DISTINCT role_id
			   FROM user_organization_roles
			  WHERE user_id     IN (:userIds)
			    AND tenant_code  = :currentTenantCode
			    AND deleted_at  IS NULL`,
			{ replacements: { userIds, currentTenantCode }, transaction, raw: true }
		)
		const roleIds = roleRows.map((r) => r.role_id)

		let roleMapping = {}
		if (roleIds.length > 0) {
			roleMapping = await buildRoleMapping(sequelize, roleIds, currentTenantCode, newTenantCode, transaction)
			const unmappedCount = roleIds.filter((id) => roleMapping[id] === undefined).length
			if (unmappedCount > 0) {
				log('warn', `${unmappedCount} role(s) have no matching title in target tenant and will be skipped`, {
					unmappedRoleIds: roleIds.filter((id) => roleMapping[id] === undefined),
				})
			}
			log('info', `Role mapping: ${Object.keys(roleMapping).length}/${roleIds.length} roles mapped by title`)
		} else {
			log('info', 'No user_organization_roles found for these users — skipping role mapping')
		}

		// ── Step 6: INSERT users with newTenantCode ────────────────────────────
		await migrateUsers(sequelize, userIds, currentTenantCode, newTenantCode, transaction)
		log('info', `Inserted ${preMigrationCount} user row(s) into tenant '${newTenantCode}'`)

		// ── Step 7: INSERT user_organizations ─────────────────────────────────
		await migrateUserOrganizations(sequelize, userIds, currentTenantCode, newTenantCode, transaction)
		log('info', 'Migrated user_organizations to new tenant')

		// ── Step 8: INSERT user_organization_roles (with remapped role IDs) ───
		await migrateUserOrganizationRoles(sequelize, userIds, currentTenantCode, newTenantCode, roleMapping, transaction)
		log('info', 'Migrated user_organization_roles to new tenant')

		// ── Step 9: INSERT pending org role requests ───────────────────────────
		await migrateOrgRoleRequests(sequelize, userIds, currentTenantCode, newTenantCode, transaction)
		log('info', 'Migrated pending organization_role_requests to new tenant')

		// ── Step 10: Prepare for deletion — nullify handled_by refs (NO ACTION FK)
		await nullifyHandledByReferences(sequelize, userIds, currentTenantCode, transaction)
		log('info', 'Nullified handled_by references in old tenant (NO ACTION FK safety)')

		// ── Step 11: Delete old records (FK-safe order) ────────────────────────
		await deleteOldOrgRoleRequests(sequelize, userIds, currentTenantCode, transaction)
		log('info', 'Deleted old organization_role_requests from source tenant')

		await deleteOldUserOrganizationRoles(sequelize, userIds, currentTenantCode, transaction)
		log('info', 'Deleted old user_organization_roles from source tenant')

		await deleteOldUserSessions(sequelize, userIds, currentTenantCode, transaction)
		log('info', 'Deleted old user_sessions from source tenant (users must re-authenticate)')

		await deleteOldUserOrganizations(sequelize, userIds, currentTenantCode, transaction)
		log('info', 'Deleted old user_organizations from source tenant')

		await deleteOldUsers(sequelize, userIds, currentTenantCode, transaction)
		log('info', `Deleted ${preMigrationCount} user row(s) from source tenant '${currentTenantCode}'`)

		// ── Step 12: Post-migration validation — count match ───────────────────
		const postMigrationCount = await countUsersInNewTenant(sequelize, userIds, newTenantCode, transaction)

		if (!validateCountMatch(preMigrationCount, postMigrationCount)) {
			throw new Error(
				`Post-migration count mismatch: expected ${preMigrationCount} user(s) in ` +
					`'${newTenantCode}', found ${postMigrationCount}. Rolling back.`
			)
		}
		log('info', `Post-migration count validated: ${postMigrationCount} user(s) confirmed in '${newTenantCode}'`)

		// ── Step 13: Commit ────────────────────────────────────────────────────
		await transaction.commit()
		transaction = null
		log('info', 'Transaction committed successfully', {
			migratedUsers: preMigrationCount,
			from: { tenantCode: currentTenantCode, orgId: currentOrgId },
			to: { tenantCode: newTenantCode },
		})

		log(
			'warn',
			'POST-MIGRATION REMINDER: Materialized views (e.g. m_users) referencing ' +
				'user data may need to be manually refreshed.'
		)

		return { success: true, migratedCount: preMigrationCount }
	} catch (err) {
		if (transaction) {
			try {
				await transaction.rollback()
				log('error', 'Transaction rolled back', { reason: err.message })
			} catch (rollbackErr) {
				log('error', 'Rollback itself failed — manual intervention may be required', {
					rollbackError: rollbackErr.message,
				})
			}
		}
		log('error', 'Migration failed', { error: err.message, stack: err.stack })
		throw err
	}
}

// ─── Entry Point ──────────────────────────────────────────────────────────────
if (require.main === module) {
	;(async () => {
		// 1. Validate CLI arguments
		const validation = parseAndValidateArgs(cliArgs)

		if (!validation.valid) {
			for (const errMsg of validation.errors) {
				log('error', errMsg)
			}
			log(
				'error',
				'Usage: node src/scripts/move-users-between-tenants.js ' +
					'--currentTenantCode X --currentOrgId 123 --newTenantCode Y'
			)
			process.exit(1)
		}

		const { params } = validation

		// 2. Validate environment variables
		const environmentData = require('../envVariables')()
		if (!environmentData.success) {
			log('error', 'Not all required environment variables are set — aborting')
			process.exit(1)
		}

		// 3. Connect to database
		let sequelize
		try {
			sequelize = createSequelizeInstance()
			await sequelize.authenticate()
			log('info', 'Database connection established')
		} catch (dbErr) {
			log('error', 'Failed to connect to database', { error: dbErr.message })
			process.exit(1)
		}

		// 4. Run migration
		try {
			const result = await run(sequelize, params)

			if (!result.success) {
				log('warn', `Migration ended without success: ${result.reason}`)
				process.exit(1)
			}

			log(
				'info',
				`Migration complete. ${result.migratedCount} user(s) moved from ` +
					`tenant '${params.currentTenantCode}' (org ${params.currentOrgId}) ` +
					`to tenant '${params.newTenantCode}'.`
			)
			process.exit(0)
		} catch (_err) {
			// error already logged inside run()
			process.exit(1)
		} finally {
			if (sequelize) {
				try {
					await sequelize.close()
				} catch (_) {
					// ignore close errors
				}
			}
		}
	})()
}

// ─── Exports (for unit tests) ─────────────────────────────────────────────────
module.exports = {
	parseAndValidateArgs,
	validateCountMatch,
	buildRoleMapping,
	checkDuplicatesInTarget,
	fetchUsersToMigrate,
	validateTargetTenantExists,
	countUsersInNewTenant,
	migrateUsers,
	migrateUserOrganizations,
	migrateUserOrganizationRoles,
	migrateOrgRoleRequests,
	nullifyHandledByReferences,
	deleteOldOrgRoleRequests,
	deleteOldUserOrganizationRoles,
	deleteOldUserSessions,
	deleteOldUserOrganizations,
	deleteOldUsers,
	run,
	log,
}
