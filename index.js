'use strict';

process.setMaxListeners(0);

const dnsd = require('./dnsd/named');
const randomCase = require('random-case');
const randomstring = require('randomstring');
const spdy = require('spdy');
const url = require('url');
const forwardUrl = 'https://dns.google.com:443/resolve';
const resolver = url.parse(forwardUrl);

const request = require('request').defaults({
	agent: spdy.createAgent({
		host: resolver.hostname,
		port: resolver.port,
		family: process.argv[4] || 0
	}).once('error', (err) => {
		console.error('agent error: %s', err);
	}),
	json: true
});
const Constants = require('./dnsd/constants');
const ip6 = require('ip6');

const subnet = process.argv[5];
const SupportTypes = ['A', 'MX', 'CNAME', 'TXT', 'PTR', 'AAAA', 'NS'];

const server = dnsd.createServer((req, res) => {
	
	let question = req.question[0], 
	/*
	 * Use 0x20-encoded random bits in the query to foil spoof attempts. This
	 * perturbs the lowercase and uppercase of query names sent to authority
	 * servers and checks if the reply still has the correct casing. This
	 * feature is an Experimental implementation of draft dns-0x20.
	 */ 
	hostname = randomCase(question.name);
	let timeStamp = `[${req.id}/${req.connection.type}] ${req.opcode} ${hostname} ${question.class} ${question.type}`;
	console.time(timeStamp);	

	// TODO unsupported due to dnsd's broken implementation.
	if (SupportTypes.indexOf(question.type) === -1) {
		console.timeEnd(timeStamp);
		return res.end();
	} else 	if (req.question[0].type == 'A' && question.name!=resolver.hostname) {
			question.type = 'AAAA';
			let timeStamp6 = `[${req.id}/${req.connection.type}] Preference ${req.opcode} ${hostname} ${question.class} ${question.type}`;
			console.time(timeStamp6); 
			console.log('Testing %s for %s', question.type,hostname);
			// API clients concerned about possible side-channel privacy attacks
			// using the packet sizes of HTTPS GET requests can use this to make
			// all
			// requests exactly the same size by padding requests with random
			// data.
			let padding = randomstring.generate({
				// maximum dnslength+type.length (longest possible Type 5
				// digits)
				// minus current To make always equal query lenght url
				length: 258 - question.name.length - Constants.type_to_number(question.type).toString().length,
				// safe but can be more extended chars-_
				charset: 'alphanumeric'
			}); let query = {
					name: hostname,
					type: Constants.type_to_number(question.type),
					random_padding: padding
			}

			if (subnet) {
				query.edns_client_subnet = subnet;
			}

			request({
				url: forwardUrl,
				qs: query,
				gzip: true
			}, (err, response, output) => {
				if (typeof output.Authority !== 'undefined' || output.Status == 2) {
					// fix A Query blocking
					// Reset Back to and for Original query Type fallback
					question.type = 'A';
					let padding = randomstring.generate({
						// maximum dnslength+type.length (longest possible Type
						// 5 digits)
						// minus current To make always equal query lenght url
						length: 257 - question.name.length ,
						// safe but can be more extended chars-_
						charset: 'alphanumeric'
					})
					let query = {
						name: hostname,
						type: 1,
						random_padding: padding
					}

					if (subnet) {
						query.edns_client_subnet = subnet;
					}

					request({
						url: forwardUrl,
						qs: query,
						gzip: true
					}, (err, response, output) => {
						if (output && output.Answer) {
							res.answer = output.Answer.map(rec => {
								rec.ttl = rec.TTL;
								rec.type = Constants.type_to_label(rec.type);
								return rec;
							});
						} else if (err) {
							console.error('request error %s', err);
						}
						if (typeof output.Comment !== 'undefined'){
							// Resolvercomment "Response from x.x.x.x"
							process.stdout.write(output.Comment)
						}
						console.timeEnd(timeStamp);
						res.end();
					});
				}
				else if (typeof output.Answer !== 'undefined') {
					if (output && output.Answer && output.Question[0]['type'] === 28 ) {
						res.answer = output.Answer.map(rec => {
							rec.ttl = rec.TTL;
							rec.type = Constants.type_to_label(rec.type);
							// CNAME
							if (rec.type === 'AAAA') { 
								// dnsd is expecting long IP Version 6 format
								rec.data = ip6.normalize(rec.data); 
							}
							return rec;
						});
					} else if (err) {
						console.error('request error %s', err);
					}
					if (typeof output.Comment !== 'undefined'){
						// Resolvercomment "Response from x.x.x.x"
						process.stdout.write(output.Comment)
					}
					console.timeEnd(timeStamp6);
					res.end();
				}
			});}
		else {
			// Original Query
			// API clients concerned about possible side-channel privacy attacks
			// using the packet sizes of HTTPS GET requests can use this to make
			// all
			// requests exactly the same size by padding requests with random
			// data.
			let padding = randomstring.generate({
				// maximum dnslength+type.length (longest possible Type 5
				// digits)
				// minus current To make always equal query lenght url
				length: 258 - question.name.length - Constants.type_to_number(question.type).toString().length,
				// safe but can be more extended chars-_
				charset: 'alphanumeric'
			});

			let query = {
					name: hostname,
					type: Constants.type_to_number(question.type),
					random_padding: padding
			}

			if (subnet) {
				query.edns_client_subnet = subnet;
			}

			request({
				url: forwardUrl,
				qs: query,
				gzip: true
			}, (err, response, output) => {				
				if (output && output.Answer) {
					res.answer = output.Answer.map(rec => {
						// TODO 0x20 rec.name=rec.name.toLowerCase;
						rec.ttl = rec.TTL;
						rec.type = Constants.type_to_label(rec.type);
						switch (rec.type) {
						case 'MX':
							rec.data = rec.data.split(/\s+/);
							break;
						case 'TXT':
						case 'SPF':
							rec.data = rec.data.slice(1, -1);
							break;
						case 'AAAA':
							// dnsd is expecting long IPVersion 6 format
							rec.data = ip6.normalize(rec.data);
							break;
						}						
						return rec;						
					});
				} else if (err) {
					console.error('request error %s', err);
				}
				if (typeof output.Comment !== 'undefined'){
					// Resolvercomment "Response from x.x.x.x"
					process.stdout.write(output.Comment)
				}
				console.timeEnd(timeStamp);
				res.end();
			});
	}		
});


server.on('error', err => {
	console.error('dnsd error: %s', err);
	if (err.code == 'EADDRINUSE') {
	    console.log('Address in use, retrying...');
	    setTimeout(() => {
	      server.close();
	      server.listen(process.argv[2] || 6666, process.argv[3] || '127.0.0.1');
	    }, 1000);
	  }
	//server.removeAllListeners('error')
});

const devnull = require('dev-null');
setInterval(() => {
	let ping = forwardUrl + '?name=' + resolver.hostname;
	request(ping).pipe(devnull());
}, 60 * 1000);


server.listen(process.argv[2] || 6666, process.argv[3] || '127.0.0.1');