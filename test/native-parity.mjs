import assert from 'node:assert/strict'
import { randomBytes } from 'node:crypto'

const originalGetBuiltinModule = process.getBuiltinModule

if (typeof originalGetBuiltinModule !== 'function') {
	console.log('process.getBuiltinModule no existe en esta version de Node: no hay via nativa que comparar')
	process.exit(0)
}

const importVariant = async (variant, provider) => {
	const calls = []
	process.getBuiltinModule = id => {
		const found = provider(id)
		calls.push({ id, found: found !== undefined && found !== null })
		return found
	}

	try {
		const mod = await import(new URL(`../lib-esm/index.js?variant=${variant}`, import.meta.url).href)
		return { mod, calls }
	} finally {
		process.getBuiltinModule = originalGetBuiltinModule
	}
}

const native = await importVariant('native', id => originalGetBuiltinModule.call(process, id))
const pure = await importVariant('pure', () => undefined)

assert.equal(native.calls.length, 1)
assert.equal(native.calls[0].found, true)
assert.equal(pure.calls.length, 1)
assert.equal(pure.calls[0].found, false)

const hex = value => Uint8Array.from(Buffer.from(value, 'hex'))
const toHex = value => Buffer.from(value).toString('hex')

const outcome = fn => {
	try {
		return { ok: toHex(fn()) }
	} catch (error) {
		return { error: `${error.constructor.name}: ${error.message}` }
	}
}

const variants = [
	['nativo', native.mod],
	['js puro', pure.mod]
]

let passed = 0
const step = (name, fn) => {
	fn()
	passed++
	console.log(`ok  ${name}`)
}

step('RFC 7748 5.2 vector 1 y 2', () => {
	for (const [, lib] of variants) {
		assert.equal(
			toHex(
				lib.sharedKey(
					hex('a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4'),
					hex('e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c')
				)
			),
			'c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552'
		)
		assert.equal(
			toHex(
				lib.sharedKey(
					hex('4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d'),
					hex('e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493')
				)
			),
			'95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957'
		)
	}
})

step('RFC 7748 6.1 Diffie-Hellman y claves publicas', () => {
	const alicePriv = hex('77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a')
	const alicePub = '8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a'
	const bobPriv = hex('5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb')
	const bobPub = 'de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f'
	const shared = '4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742'

	for (const [, lib] of variants) {
		assert.equal(toHex(lib.generateKeyPair(alicePriv).public), alicePub)
		assert.equal(toHex(lib.generateKeyPair(bobPriv).public), bobPub)
		assert.equal(toHex(lib.sharedKey(alicePriv, hex(bobPub))), shared)
		assert.equal(toHex(lib.sharedKey(bobPriv, hex(alicePub))), shared)
	}
})

step('RFC 7748 5.2 iteraciones 1 y 1000', () => {
	for (const [, lib] of variants) {
		let k = hex('0900000000000000000000000000000000000000000000000000000000000000')
		let u = hex('0900000000000000000000000000000000000000000000000000000000000000')
		for (let i = 1; i <= 1000; i++) {
			const next = lib.sharedKey(k, u)
			u = k
			k = next
			if (i === 1) {
				assert.equal(toHex(k), '422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079')
			}
		}

		assert.equal(toHex(k), '684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51')
	}
})

step('puntos de orden bajo y no canonicos: mismo resultado y mismo error', () => {
	const points = [
		'0000000000000000000000000000000000000000000000000000000000000000',
		'0100000000000000000000000000000000000000000000000000000000000000',
		'e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800',
		'5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157',
		'ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f',
		'edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f',
		'eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f',
		'0000000000000000000000000000000000000000000000000000000000000080',
		'0100000000000000000000000000000000000000000000000000000000000080'
	]

	for (const point of points) {
		const secret = randomBytes(32)
		const a = outcome(() => native.mod.sharedKey(Uint8Array.from(secret), hex(point)))
		const b = outcome(() => pure.mod.sharedKey(Uint8Array.from(secret), hex(point)))
		assert.deepEqual(a, b, `difieren para ${point}`)
		assert.equal(a.error, 'Error: invalid public key (low-order point)', `no lanzo error para ${point}`)
	}
})

step('300 pares aleatorios coinciden en sharedKey y generateKeyPair', () => {
	for (let i = 0; i < 300; i++) {
		const secret = Uint8Array.from(randomBytes(32))
		const point = Uint8Array.from(randomBytes(32))
		assert.equal(toHex(native.mod.sharedKey(secret, point)), toHex(pure.mod.sharedKey(secret, point)))

		const a = native.mod.generateKeyPair(secret)
		const b = pure.mod.generateKeyPair(secret)
		assert.equal(toHex(a.public), toHex(b.public))
		assert.equal(toHex(a.private), toHex(b.private))
	}
})

step('tipo de retorno, longitud y entradas sin mutar', () => {
	for (const [, lib] of variants) {
		const secret = Uint8Array.from(randomBytes(32))
		const point = Uint8Array.from(randomBytes(32))
		const secretBefore = toHex(secret)
		const pointBefore = toHex(point)

		const shared = lib.sharedKey(secret, point)
		assert.equal(Object.getPrototypeOf(shared), Uint8Array.prototype)
		assert.equal(shared.length, 32)

		const pair = lib.generateKeyPair(secret)
		assert.equal(Object.getPrototypeOf(pair.public), Uint8Array.prototype)
		assert.equal(Object.getPrototypeOf(pair.private), Uint8Array.prototype)
		assert.equal(pair.public.length, 32)
		assert.equal(pair.private.length, 32)
		assert.equal(pair.public[31] & 128, 0)
		assert.equal(pair.private[0] & 7, 0)
		assert.equal(pair.private[31] & 192, 64)

		assert.equal(toHex(secret), secretBefore)
		assert.equal(toHex(point), pointBefore)
	}
})

step('validacion de entradas identica', () => {
	const cases = [
		lib => lib.sharedKey(new Uint8Array(31), new Uint8Array(32)),
		lib => lib.sharedKey(new Uint8Array(32), new Uint8Array(33)),
		lib => lib.sharedKey([1, 2, 3], new Uint8Array(32)),
		lib => lib.generateKeyPair(new Uint8Array(31)),
		lib => lib.generateKeyPair('x')
	]

	for (const run of cases) {
		assert.deepEqual(
			outcome(() => run(native.mod)),
			outcome(() => run(pure.mod))
		)
		assert.ok(outcome(() => run(native.mod)).error)
	}
})

step('firmas: sign y verify cruzados entre variantes', () => {
	const pair = native.mod.generateKeyPair(Uint8Array.from(randomBytes(32)))
	const message = Uint8Array.from(randomBytes(120))

	const fromNative = native.mod.sign(pair.private, message)
	const fromPure = pure.mod.sign(pair.private, message)

	assert.equal(native.mod.verify(pair.public, message, fromPure), true)
	assert.equal(pure.mod.verify(pair.public, message, fromNative), true)
	assert.equal(native.mod.verify(pair.public, message, fromNative), true)

	const tampered = Uint8Array.from(message)
	tampered[0] ^= 1
	assert.equal(native.mod.verify(pair.public, tampered, fromNative), false)
})

const time = (lib, count) => {
	const secret = Uint8Array.from(randomBytes(32))
	const point = Uint8Array.from(randomBytes(32))
	lib.sharedKey(secret, point)
	const start = process.hrtime.bigint()
	for (let i = 0; i < count; i++) {
		lib.sharedKey(secret, point)
		lib.generateKeyPair(secret)
	}

	return Number(process.hrtime.bigint() - start) / count / 1000
}

const nativeMicros = time(native.mod, 300)
const pureMicros = time(pure.mod, 100)

console.log(`${passed} pruebas ok`)
console.log(`sharedKey + generateKeyPair: nativo ${nativeMicros.toFixed(0)} us, js puro ${pureMicros.toFixed(0)} us, mejora x${(pureMicros / nativeMicros).toFixed(1)}`)
