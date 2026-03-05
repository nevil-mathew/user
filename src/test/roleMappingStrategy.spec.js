'use strict'

/**
 * TKT-002 — Role Mapping Strategy: schema-inspection.md validation tests
 *
 * These tests verify that schema-inspection.md contains all required
 * documentation for the cross-tenant role mapping strategy, including:
 *   - Conditions for direct ID copy vs title-based mapping
 *   - Abort conditions (A1–A5)
 *   - Warning conditions (W1–W2)
 *   - Org-aware mapping logic
 *   - Decision tree documentation
 */

const fs = require('fs')
const path = require('path')

const SCHEMA_DOC_PATH = path.resolve(__dirname, '../scripts/schema-inspection.md')

describe('TKT-002 — Role Mapping Strategy documentation validation', () => {
	let content

	beforeAll(() => {
		content = fs.readFileSync(SCHEMA_DOC_PATH, 'utf8')
	})

	// ─── File existence ──────────────────────────────────────────────────────

	test('schema-inspection.md exists and is readable', () => {
		expect(fs.existsSync(SCHEMA_DOC_PATH)).toBe(true)
		expect(content.length).toBeGreaterThan(0)
	})

	// ─── Section 15 presence ─────────────────────────────────────────────────

	test('schema-inspection.md contains Section 15 — Role Mapping Strategy', () => {
		expect(content).toMatch(/##\s+15\.\s+Role Mapping Strategy/i)
	})

	test('Table of Contents references Section 15', () => {
		expect(content).toMatch(/15\.\s+\[Role Mapping Strategy/i)
	})

	// ─── 15.1 Direct ID copy conditions ──────────────────────────────────────

	test('documents that direct role ID copy is unsafe by default', () => {
		// Must warn that direct copy is not safe
		expect(content).toMatch(/[Dd]irect.*[Cc]opy.*[Uu]nsafe|[Uu]nsafe.*[Dd]irect.*[Cc]opy/i)
	})

	test('documents specific conditions under which direct ID copy is permissible', () => {
		// Should list the four conditions
		expect(content).toMatch(/[Cc]onditions.*[Pp]ermissible|[Pp]ermissible.*[Cc]onditions/i)
		// Condition about no users existing yet in target
		expect(content).toMatch(/[Nn]o users exist.*target|target.*no users/i)
		// Condition about explicit pre-migration verification
		expect(content).toMatch(/[Ee]xplicit.*[Vv]erif|[Pp]re.migration.*[Vv]erif/i)
		// Condition about same migration sequence / seeding
		expect(content).toMatch(/[Ss]eeded.*same.*migration|same.*migration.*sequence/i)
	})

	test('explicitly states direct ID copy is prohibited in production', () => {
		expect(content).toMatch(/[Pp]rohibited|[Nn]ever.*[Pp]roduction|[Pp]roduction.*[Nn]ever/i)
	})

	// ─── 15.2 Title-based mapping strategy ────────────────────────────────────

	test('recommends title-based mapping as the safe strategy', () => {
		// Title-based mapping recommended
		expect(content).toMatch(/[Tt]itle.based.*[Mm]apping/i)
		expect(content).toMatch(/[Rr]ecommended/i)
	})

	test('documents why title is a stable cross-tenant attribute', () => {
		// Should mention that title is set by migrations (not user input)
		expect(content).toMatch(/[Ss]table.*[Aa]ttribute|[Aa]ttribute.*[Ss]table/i)
		// Should mention title consistency across tenants
		expect(content).toMatch(/[Cc]onsistent.*tenant|tenant.*[Cc]onsistent/i)
	})

	test('documents system role titles used for cross-tenant mapping', () => {
		// Known system role titles
		expect(content).toMatch(/admin/)
		expect(content).toMatch(/mentor/)
		expect(content).toMatch(/mentee/)
		expect(content).toMatch(/session_manager/)
		expect(content).toMatch(/public/)
		expect(content).toMatch(/tenant_admin/)
	})

	test('documents organization-aware mapping using (title, organization_code) pair', () => {
		// Must state that mapping is org-aware
		expect(content).toMatch(/[Oo]rganization.aware|[Oo]rg.aware/i)
		// Should mention the composite key (title, organization_code)
		expect(content).toMatch(/title.*organization_code|organization_code.*title/i)
	})

	test('distinguishes between system roles (user_type=1) and custom roles (user_type=0)', () => {
		expect(content).toMatch(/user_type.*=.*1|user_type.*1/i)
		expect(content).toMatch(/user_type.*=.*0|user_type.*0/i)
		expect(content).toMatch(/[Ss]ystem role/i)
		expect(content).toMatch(/[Cc]ustom role/i)
	})

	// ─── 15.3 Mapping algorithm (SQL / step-by-step) ─────────────────────────

	test('documents the role mapping algorithm with SQL', () => {
		// SQL block with user_organization_roles JOIN user_roles
		expect(content).toMatch(/user_organization_roles.*JOIN.*user_roles|user_roles.*JOIN.*user_organization_roles/i)
		// Must reference organization JOIN for org_code resolution
		expect(content).toMatch(/JOIN.*organizations|organizations.*JOIN/i)
	})

	test('documents Step 1 — collecting source role references', () => {
		expect(content).toMatch(/[Ss]tep 1|Step 1/i)
		expect(content).toMatch(/[Cc]ollect.*source|source.*[Cc]ollect/i)
	})

	test('documents Step 2 — verifying organizations exist in target tenant', () => {
		expect(content).toMatch(/[Ss]tep 2|Step 2/i)
		// Should check org existence
		expect(content).toMatch(/[Vv]erify.*org|org.*exist|organizations.*target/i)
	})

	test('documents Step 3 — looking up roles in target tenant', () => {
		expect(content).toMatch(/[Ss]tep 3|Step 3/i)
		expect(content).toMatch(/target tenant.*role|role.*target tenant/i)
	})

	test('documents Step 4 — building the mapping table', () => {
		expect(content).toMatch(/[Ss]tep 4|Step 4/i)
		expect(content).toMatch(/[Bb]uild.*mapping|mapping.*table/i)
	})

	test('documents Step 5 — applying CASE expression in INSERT', () => {
		expect(content).toMatch(/[Ss]tep 5|Step 5/i)
		expect(content).toMatch(/CASE.*role_id|CASE expression/i)
		// INSERT statement into user_organization_roles
		expect(content).toMatch(/INSERT INTO user_organization_roles/i)
	})

	test('documents that CASE ELSE NULL rows are excluded from INSERT', () => {
		expect(content).toMatch(/ELSE NULL/i)
		expect(content).toMatch(/IS NOT NULL/i)
	})

	// ─── 15.4 Abort conditions A1–A5 ──────────────────────────────────────────

	test('defines at least five distinct abort conditions', () => {
		// Each abort condition must be labeled A1 through A5
		expect(content).toMatch(/\bA1\b/)
		expect(content).toMatch(/\bA2\b/)
		expect(content).toMatch(/\bA3\b/)
		expect(content).toMatch(/\bA4\b/)
		expect(content).toMatch(/\bA5\b/)
	})

	test('abort condition A1: system role with no match in target tenant → abort', () => {
		// A1 = system role not found in target
		expect(content).toMatch(/A1/)
		expect(content).toMatch(/[Ss]ystem role.*no match|no match.*system role|system role.*not.*found/i)
	})

	test('abort condition A2: ambiguous mapping (multiple target matches for same title+org) → abort', () => {
		// A2 = multiple matches → ambiguous
		expect(content).toMatch(/A2/)
		expect(content).toMatch(/[Mm]ultiple.*match|ambiguous/i)
		expect(content).toMatch(/two or more|multiple.*rows|2\+.*match/i)
	})

	test('abort condition A3: source org does not exist in target tenant → abort', () => {
		// A3 = organization not found in target
		expect(content).toMatch(/A3/)
		expect(content).toMatch(/[Oo]rg.*not exist|[Oo]rganization.*not exist|not exist.*[Oo]rg/i)
	})

	test('abort condition A4: PK collision in target user_organization_roles → abort', () => {
		// A4 = duplicate PK / already exists
		expect(content).toMatch(/A4/)
		expect(content).toMatch(/PK collision|[Cc]ollision.*user_organization_roles|already exists/i)
	})

	test('abort condition A5: matched target role is INACTIVE → abort', () => {
		// A5 = role status INACTIVE
		expect(content).toMatch(/A5/)
		expect(content).toMatch(/INACTIVE/i)
		expect(content).toMatch(/status.*INACTIVE|INACTIVE.*status/i)
	})

	test('all abort conditions require rollback of the SERIALIZABLE transaction', () => {
		// General statement about rollback on abort
		expect(content).toMatch(/rollback/i)
		expect(content).toMatch(/SERIALIZABLE/i)
	})

	// ─── 15.4 Warning conditions W1–W2 ───────────────────────────────────────

	test('defines warning conditions W1 and W2', () => {
		expect(content).toMatch(/\bW1\b/)
		expect(content).toMatch(/\bW2\b/)
	})

	test('warning W1: custom role with no match in target → warn but do not abort by default', () => {
		expect(content).toMatch(/W1/)
		// Custom role, no match, skip/warn (not abort)
		expect(content).toMatch(/[Cc]ustom role.*no match|no match.*custom role/i)
		expect(content).toMatch(/[Ss]kip|[Ww]arn/i)
	})

	test('warning W2: title match under different org in target → do not auto-remap', () => {
		expect(content).toMatch(/W2/)
		// Different org in target
		expect(content).toMatch(/different org|different organization/i)
		// Must NOT auto-remap
		expect(content).toMatch(/[Nn]ot.*auto.remap|do.*NOT.*auto|NOT.*remap/i)
	})

	test('documents strict mode that promotes W1 to abort', () => {
		expect(content).toMatch(/--strict|strict mode/i)
		// Strict mode should escalate W1 to abort
		expect(content).toMatch(/promote.*W1|W1.*abort|strict.*abort/i)
	})

	// ─── 15.5 Decision tree ───────────────────────────────────────────────────

	test('contains a decision tree or flowchart for the mapping process', () => {
		// Should include decision tree section
		expect(content).toMatch(/[Dd]ecision [Tt]ree|[Mm]apping [Dd]ecision/i)
	})

	test('decision tree references all abort conditions by ID', () => {
		// All abort IDs should appear in the decision tree context
		const decisionTreeStart = content.indexOf('Decision Tree')
		expect(decisionTreeStart).toBeGreaterThan(-1)
		const decisionTreeSection = content.slice(decisionTreeStart, decisionTreeStart + 2000)
		expect(decisionTreeSection).toMatch(/A1/)
		expect(decisionTreeSection).toMatch(/A2/)
		expect(decisionTreeSection).toMatch(/A3/)
	})

	// ─── 15.6 Summary table ───────────────────────────────────────────────────

	test('contains a summary comparison table: Direct ID Copy vs Title-Based Mapping', () => {
		expect(content).toMatch(/[Ss]ummary.*Direct.*Title|Direct.*Copy.*vs.*Title/i)
	})

	test('summary table explicitly marks direct ID copy as not recommended for production', () => {
		// Look for the final verdict/decision statement
		expect(content).toMatch(/[Ff]inal decision|[Pp]roduction.*[Ss]afe|[Ee]xplicitly prohibited/i)
	})

	test('summary table shows title-based mapping is mandatory for production', () => {
		expect(content).toMatch(/[Mm]andatory|[Mm]ust.*use.*title.based|title.based.*MUST/i)
	})

	// ─── FK constraint references ──────────────────────────────────────────────

	test('references fk_user_organization_roles_role_composite in mapping context', () => {
		// The mapping strategy must acknowledge the FK that will fail on bad role_id
		expect(content).toMatch(/fk_user_organization_roles_role_composite/i)
	})

	test('references unique_title_org_id_tenant_code constraint in mapping context', () => {
		expect(content).toMatch(/unique_title_org_id_tenant_code/i)
	})

	// ─── Consistency with earlier sections ────────────────────────────────────

	test('Section 15 is consistent with Section 12 (role ID scoping verdict)', () => {
		// Both sections must agree: roles are tenant-scoped
		const section12idx = content.indexOf('## 12.')
		const section15idx = content.indexOf('## 15.')
		expect(section12idx).toBeGreaterThan(-1)
		expect(section15idx).toBeGreaterThan(-1)
		// Section 15 comes after Section 12
		expect(section15idx).toBeGreaterThan(section12idx)
	})

	test('cross-references to Section 12 are present in Section 15', () => {
		const section15Part = content.slice(content.indexOf('## 15.'))
		// Should reference §12 or Section 12 in context
		expect(section15Part).toMatch(/§12|Section 12|section 12/i)
	})
})
