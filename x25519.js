// X25519 Implementation - Joey Innes inneslabs.uk

function gf(init) {
    let r = new Float64Array(16)
    if (init) for (let i = 0; i < init.length; i++) r[i] = init[i]
    return r
}
  
function pack(o, n) {
    let b = gf(), m = gf(), t = gf()
    for (let i = 0; i < 16; i++) t[i] = n[i]
    carry(t)
    carry(t)
    carry(t)
    for (let j = 0; j < 2; j++) {
        m[0] = t[0] - 0xffed
        for (let i = 1; i < 15; i++) {
            m[i] = t[i] - 0xffff - ((m[i-1]>>16) & 1)
            m[i-1] &= 0xffff
        }
        m[15] = t[15] - 0x7fff - ((m[14]>>16) & 1)
        b[0] = (m[0]>>16) & 1
        for (let i = 1; i < 16; i++) {
            m[i-1] &= 0xffff
            b[i] = (m[i]>>16) & 1
        }
        m[15] &= 0xffff
        mul(t, m, gf([0xdb41, 1]))
        add(t, t, b)
    }
    for (let i = 0; i < 16; i++) {
        o[2*i] = t[i] & 0xff
        o[2*i+1] = t[i]>>8
    }
}
  
function unpack(o, n) {
    for (let i = 0; i < 16; i++) o[i] = n[2*i] + (n[2*i+1] << 8)
    o[15] &= 0x7fff
}
  
function add(o, a, b) {
    for (let i = 0; i < 16; i++) o[i] = (a[i] + b[i]) | 0
}
  
function sub(o, a, b) {
    for (let i = 0; i < 16; i++) o[i] = (a[i] - b[i]) | 0
}

function mul(o, a, b) {
    let t = new Float64Array(31)
    for (let i = 0; i < 16; i++) {
        for (let j = 0; j < 16; j++) t[i+j] += a[i] * b[j]
    }
    for (let i = 0; i < 16; i++) t[i] += 38 * t[i+16]
    for (let i = 0; i < 16; i++) o[i] = t[i]
    carry(o)
}

function carry(o) {
    let c
    for (let i = 0; i < 16; i++) {
        c = Math.floor(o[i] / 65536)
        o[(i+1)*(i<15?1:0)] += c
        o[i] -= c * 65536
    }
}
  
function cswap(p, q, b) {
    let t, c = ~(b-1)
    for (let i = 0; i < 16; i++) {
        t = c & (p[i] ^ q[i])
        p[i] ^= t
        q[i] ^= t
    }
}
  
function scalarMult(n, p) {
    let z = new Uint8Array(32)
    let x = new Float64Array(80), r, a = gf(), b = gf(), c = gf(), d = gf(), e = gf(), f = gf()
    for (let i = 0; i < 31; i++) z[i] = n[i]
    z[31] = (n[31] & 127) | 64
    z[0] &= 248
    unpack(x, p)
    for (let i = 0; i < 16; i++) {
        b[i] = x[i]
        d[i] = a[i] = c[i] = 0
    }
    a[0] = d[0] = 1
    for (let i = 254; i >= 0; --i) {
        r = (z[i>>>3] >>> (i & 7)) & 1
        cswap(a, b, r)
        cswap(c, d, r)
        add(e, a, c)
        sub(a, a, c)
        add(c, b, d)
        sub(b, b, d)
        mul(d, e, e)
        mul(f, a, a)
        mul(a, c, a)
        mul(c, b, e)
        add(e, a, c)
        sub(a, a, c)
        mul(b, a, a)
        sub(c, d, f)
        mul(a, c, gf([0x19]))
        add(a, a, d)
        mul(c, c, a)
        mul(a, d, f)
        mul(d, b, x)
        mul(b, e, e)
        cswap(a, b, r)
        cswap(c, d, r)
    }
    invert(c, c)
    mul(a, a, c)
    pack(z, a)
    return z
}
  
function scalarMultBase(n) {
    return scalarMult(n, [0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
}
  
function invert(o, i) {
    let c = gf()
    for (let a = 0; a < 16; a++) c[a] = i[a]
    for (let a = 253; a >= 0; a--) {
        mul(c, c, c)
        if (a%2 === 1 || a === 8) mul(c, c, i)
    }
    for (let a = 0; a < 16; a++) o[a] = c[a]
}

export function generateKeyPair(seed) {
    if (seed.length !== 32) throw new Error("Invalid seed length")
    let secretKey = new Uint8Array(32)
    let publicKey = new Uint8Array(32)
    for (let i = 0; i < 32; i++) secretKey[i] = seed[i]
    publicKey = scalarMultBase(secretKey)
    return {secretKey, publicKey}
}
  
export function sharedKey(secretKey, publicKey) {
    if (secretKey.length !== 32) throw new Error("Invalid secret key length")
    if (publicKey.length !== 32) throw new Error("Invalid public key length")
    return scalarMult(secretKey, publicKey)
}
