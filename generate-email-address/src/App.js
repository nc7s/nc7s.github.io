import React from 'react'
import { Buffer } from 'buffer/'
import { SHA3 } from 'sha3'
import b32 from 'base32.js'
import chacha20 from 'chacha20'
import 'milligram'
import './App.css'


function sha3512(data) {
	return new SHA3(512).update(data).digest()
}

function calculateKey(clearKey) {
	let hash = sha3512(clearKey)
	return {
		key: hash.slice(24, 56),
		iv: hash.slice(12, 24)
	}
}

function encrypt(clearKey, name) {
	let {key, iv} = calculateKey(clearKey)
	return chacha20.encrypt(key, iv, Buffer.from(name))
}

function decrypt(clearKey, ciphertext) {
	let {key, iv} = calculateKey(clearKey)
	return chacha20.decrypt(key, iv, Buffer.from(ciphertext)).toString()
}

const	REVERSE_MARK_BITS = 8,
		REVERSE_SHIFT = 5,
		MAX_REVERSE_START = 2 ^ (REVERSE_MARK_BITS - REVERSE_SHIFT),
		MAX_REVERSE_LENGTH = 2 ^ REVERSE_SHIFT
function b32encode(data) {
	data = Buffer.from(data)
	let buffer = new Uint8Array(data.byteLength + 1),
		sha = sha3512(data),
		reverseStart = (parseInt((sha[0] << 8) + sha[1], 16) % MAX_REVERSE_START) % data.byteLength,
		reverseLength = (parseInt((sha[2] << 8) + sha[3], 16) % MAX_REVERSE_LENGTH) % (data.byteLength - reverseStart),
		mark,
		rounds = mark = (reverseStart << REVERSE_SHIFT) + reverseLength
	for(let i = 0; i < rounds; i++) {
		data.set(data.slice(reverseStart, reverseStart + reverseLength).reverse(), reverseStart)
		data = data.reverse()
	}
	buffer.set(data, 0)
	buffer.set([mark], buffer.byteLength - 1)
	return b32.encode(buffer, { type: 'crockford', lc: true })
}
window.sha = sha3512
window.b32en = b32encode
window.b32de = b32decode
window.b32 = b32
window.enc = encrypt
window.dec = decrypt
window.c20 = chacha20
window.cK = calculateKey
window.Buffer = Buffer

function b32decode(data) {
	let buffer = Buffer.from(b32.decode(data, { type: 'crockford' })),
		rounds,
		mark = rounds = buffer[buffer.byteLength - 1],
		reverseStart = mark >> REVERSE_SHIFT,
		reverseLength = mark & MAX_REVERSE_LENGTH
	buffer = buffer.slice(0, buffer.byteLength - 1)
	for(let i = 0; i < rounds; i++) {
		buffer = buffer.reverse()
		buffer.set(buffer.slice(reverseStart, reverseStart + reverseLength).reverse(), reverseStart)
	}
	return buffer.toString().replace(/\0/g, '')
}

function pad(text) {
	let byteLength = Buffer.from(text).byteLength + REVERSE_MARK_BITS / 8, /* consider reverse mark */
		padded = text + ''
	for(let l = 5;; l += 5) {
		if(byteLength < l) {
			for(let i = byteLength; i < l; i++) {
				padded += '\0'
			}
			return padded
		}
	}
}

class App extends React.Component {
	constructor(props) {
		super(props)
		this.state = {
			key: '',
			domain: '',
			name: '',
			base32: '',
			hex: ''
		}
		window._App = this
		this.clear = this.clear.bind(this)
		this.recalculate = this.recalculate.bind(this)
		this.decryptBase32 = this.decryptBase32.bind(this)
		this.decryptHex = this.decryptHex.bind(this)
	}

	componentDidMount() {
		this.load()
	}


	load() {
		let key = localStorage.getItem('key')
		if(typeof key === 'string' && key.length !== 0) {
			this.setState({ key })
		}
		let domain = localStorage.getItem('domain')
		if(typeof domain === 'string' && domain.length !== 0) {
			this.setState({ domain })
		}
	}

	saveKey(key) {
		localStorage.setItem('key', key)
	}

	saveDomain(domain) {
		localStorage.setItem('domain', domain)
	}

	recalculate(name, key) {
		let ciphertext = encrypt(key || this.state.key, pad(name))
		this.setState({
			name,
			base32: b32encode(ciphertext),
			hex: ciphertext.toString('hex')
		})
	}

	updateKey(key) {
		this.setState({ key })
		this.saveKey(key)
	}

	updateDomain(domain) {
		this.saveDomain(domain)
		this.setState({ domain })
	}

	decryptBase32(c) {
		c = c + ''
		if(c.includes('@')) {
			c = c.split('@')[0]
		}
	}


	decryptHex(c) {}

	copy(what, full) {
		navigator.clipboard.writeText(this.state[what] + (full ? '@' + this.state.domain : ''))
	}

	clear() {
		this.setState({
			name: '',
			base32: '',
			hex: ''
		})
	}

	render() {
		return (
			<div className="container">
				<hr/>
				<h2>Generate email addresses unrecognizable by providers</h2>
				<div className="row">
					<div className="column">
						<label className="">key</label>
						<input onChange={e => {this.updateKey(e.currentTarget.value); this.recalculate(this.state.name, e.currentTarget.value)} } value={this.state.key}></input>
					</div>
					<div className="column float-right">
						<label className="">domain</label>
						<input onChange={e => this.updateDomain(e.currentTarget.value)} value={this.state.domain}></input>
					</div>
				</div>
				<div className="">
					<label className="">name</label>
					<div>
						<button onClick={() => this.copy('name') } className="button">copy</button>
						<button onClick={this.clear} className="button button-clear">clear</button>
					</div>
					<input onChange={e => this.recalculate(e.currentTarget.value)} value={this.state.name}></input>
				</div>
				<div className="">
					<label className="">base32</label>
					<div className="">
						<button onClick={() => this.copy('base32')} className="button">copy</button>
						<button onClick={() => this.copy('base32', true)} className="button button-outline">copy full addr</button>
					<button onClick={this.clear} className="button button-clear">clear</button>
					</div>
					<input onChange={e => this.decryptBase32(e.currentTarget.value)} value={this.state.base32 + (this.state.domain ? '@' + this.state.domain : '')}></input>
				</div>
				<div className="">
					<label className="">hex</label>
					<div>
						<button onClick={() => this.copy('hex')} className="button">copy</button>
						<button onClick={() => this.copy('hex', true)} className="button button-outline">copy full addr</button>
						<button onClick={this.clear} className="button button-clear">clear</button>
					</div>
					<input onChange={e => this.decryptHex(e.currentTarget.value)} value={this.state.hex + (this.state.domain ? '@' + this.state.domain : '')}></input>
				</div>
			</div>
		)
	}
}

export default App;
