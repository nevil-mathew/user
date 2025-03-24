'use strict'
const crypto = require('crypto')
const axios = require('axios')
const tough = require('tough-cookie')
const { wrapper } = require('axios-cookiejar-support')

// Environment variables for configuration
const MOODLE_URL = process.env.MOODLE_URL || 'http://localhost:8080'
const USERNAME_HASH_SALT = process.env.USERNAME_HASH_SALT
const PASSWORD_HASH_SALT = process.env.PASSWORD_HASH_SALT
const USERNAME_HASH_LENGTH = parseInt(process.env.USERNAME_HASH_LENGTH, 10) || 8
const PASSWORD_HASH_LENGTH = parseInt(process.env.PASSWORD_HASH_LENGTH, 10) || 8

// Create axios instance for Moodle API
const moodleAxios = axios.create({
	baseURL: MOODLE_URL + '/webservice/rest/server.php',
	headers: {
		'Content-Type': 'application/x-www-form-urlencoded',
	},
})

/* ================= HASHING FUNCTIONS ================= */

/**
 * Generates a hashed username using the shake256 algorithm.
 * @param {string} string - The input string (username) to hash.
 * @returns {string} - The hashed username in hexadecimal format.
 */
const usernameHash = (string) => {
	try {
		return crypto
			.createHash('shake256', { outputLength: USERNAME_HASH_LENGTH })
			.update(USERNAME_HASH_SALT + string)
			.digest('hex')
	} catch (error) {
		throw error
	}
}

/**
 * Generates a hashed password using the shake256 algorithm.
 * @param {string} string - The input string (password) to hash.
 * @returns {string} - The hashed password in hexadecimal format.
 */
const passwordHash = (string) => {
	try {
		return crypto
			.createHash('shake256', { outputLength: PASSWORD_HASH_LENGTH })
			.update(PASSWORD_HASH_SALT + string)
			.digest('hex')
	} catch (error) {
		throw error
	}
}

/* ================= USER MANAGEMENT FUNCTIONS ================= */

/**
 * Builds the payload for creating a user in Moodle
 */
const buildCreateUserPayload = (
	username,
	password,
	firstname,
	lastname = firstname, // Use firstname as default lastname if none provided
	email,
	auth = 'manual',
	lang = 'en'
) => {
	return {
		'users[0][username]': username,
		'users[0][password]': password,
		'users[0][firstname]': firstname,
		'users[0][lastname]': lastname,
		'users[0][email]': email,
		'users[0][auth]': auth,
		'users[0][lang]': lang,
	}
}

/**
 * Common error handler for Moodle API calls
 */
const handleError = (error) => {
	if (error.response) {
		if (error.response.status === 401) {
			console.log('Unauthorized access - check your wstoken', error.message)
			throw new Error('unauthorized')
		}
		if (error.response.status === 400) {
			console.log('Bad request - check your parameters', error.response.data)
			throw new Error('invalid-parameters')
		}
	} else {
		console.log('Error occurred in Moodle API call::', error.message)
		throw error
	}
}

/**
 * Creates a new user in Moodle
 */
const createUser = async (username, password, firstname, lastname, email, auth = 'manual', lang = 'en') => {
	try {
		const params = new URLSearchParams({
			wstoken: process.env.MOODLE_WS_TOKEN,
			wsfunction: 'core_user_create_users',
			moodlewsrestformat: 'json',
		})

		const payload = buildCreateUserPayload(username, password, firstname, lastname, email, auth, lang)
		console.log('Payload:::', payload)
		const payloadParams = new URLSearchParams(payload)

		const response = await moodleAxios.post(
			`/webservice/rest/server.php?${params.toString()}`,
			payloadParams.toString()
		)

		console.log('Response::::', response.data)

		return {
			user_id: response.data[0].id,
			username: response.data[0].username,
		}
	} catch (error) {
		return handleError(error)
	}
}

/**
 * Creates a new user with hashed credentials
 */
const createHashedUser = async (username, password, firstname, lastname, email, auth = 'manual', lang = 'en') => {
	try {
		const hashedUsername = usernameHash(username)
		const hashedPassword = passwordHash(password)

		return await createUser(hashedUsername, hashedPassword, firstname, lastname, email, auth, lang)
	} catch (error) {
		return handleError(error)
	}
}

/* ================= LOGIN FUNCTIONS ================= */

/**
 * Login to Moodle and get session cookie
 */
const login = async (username, password, options = {}) => {
	const LOGIN_URL = `https://learn.tunerlabs.com/learn/login/index.php`
	const DASHBOARD_URL = `https://learn.tunerlabs.com/my/`

	try {
		// Create a cookie jar to persist session cookies
		const cookieJar = new tough.CookieJar()
		const client = wrapper(axios.create({ jar: cookieJar, withCredentials: true }))

		// Step 1: Get the login page to fetch token
		const loginPage = await client.get(LOGIN_URL)
		const loginTokenMatch = loginPage.data.match(/logintoken" value="(.+?)"/i)
		const loginToken = loginTokenMatch ? loginTokenMatch[1] : null

		if (!loginToken) {
			console.error('Could not fetch Moodle login token')
			throw new Error('login_token_not_found')
		}

		// Step 2: Submit login credentials
		await client.post(
			LOGIN_URL,
			new URLSearchParams({
				username: username,
				password: password,
				logintoken: loginToken,
			}).toString(),
			{
				headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
				maxRedirects: 5,
			}
		)

		// Step 3: Check if login was successful
		const dashboardResponse = await client.get(DASHBOARD_URL)

		if (dashboardResponse.data.includes('login/index.php') && dashboardResponse.data.includes('loginform')) {
			console.error('Login failed - redirected back to login page')
			throw new Error('invalid_credentials')
		}

		// Step 4: Extract the session cookie
		const cookies = await cookieJar.getCookies(MOODLE_URL)
		const sessionCookie = cookies.find((c) => c.key === 'MoodleSession')

		if (!sessionCookie) {
			console.error('Login failed - Moodle session not found')
			throw new Error('session_not_found')
		}

		return options.returnFullCookie ? sessionCookie : sessionCookie.value
	} catch (error) {
		console.error('Error during Moodle login:', error.message)
		throw error
	}
}

/**
 * Login with hashed credentials
 */
const loginWithHashedCredentials = async (originalUsername, originalPassword, options = {}) => {
	const hashedUsername = usernameHash(originalUsername)
	const hashedPassword = passwordHash(originalPassword)

	return await login(hashedUsername, hashedPassword, options)
}

/* ================= MODULE EXPORTS ================= */

module.exports = {
	// Hashing functions
	usernameHash,
	passwordHash,

	// User management
	createUser,
	createHashedUser,

	// Session management
	login,
	loginWithHashedCredentials,

	// Expose individual components for custom integrations
	buildCreateUserPayload,
	handleError,
}
