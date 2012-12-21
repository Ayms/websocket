//Copyright 2012 Ayms - MIT License
//Inspired for encode/decode from http://stackoverflow.com/questions/8125507/how-can-i-send-and-receive-websocket-messages-on-the-server-side and the official RFC

var crypto = require('crypto'),
	net = require('net'),
	WS_port=8500;

Buffer.prototype.readUInt=function() {
	switch (this.length) {
		case 1 : return this[0];
		case 2 : return this.readUInt16BE(0);
		case 4 : return this.readUInt32BE(0);
		case 8 : return parseInt(this.toString('hex'),16);
		return 0;
	};
};

Array.prototype.concatBuffers = function() { //TODO optimize - slow
	var str=[];
	this.forEach(function(val) {
		if (Buffer.isBuffer(val)) {
			str.push(val.toString('hex'));
		};
	});
	return new Buffer(str.join(''),'hex');
};

var simpleParser=function(data) {
	var res={};
	var i=0;
	data=data.split('\r\n');
	data.forEach(function(val,j) {
		val=val.split(':');
		if ((val.length>1)&&(j!=0)) {
			var p=val[0];
			val=val.map(function(v) {return v.trim()});
			val.shift();
			val=val.join(':');
			res[p]=val;
		} else {
			res[i+'a']=val.join(':'); //v8 wrong enumeration order bug #2353
			i++;
		};
	});
	return res;
};

var wsdecode=function(data,b) {
	var b=b||(new Buffer(0));
	var tlength=data.length;
	var length=0;
	var index=0;
	var tlength=data.length;
	var payload;
	var type=data[0];
	var mask=data[1]&0x80;
	var length_=data[1]&0x7f;
	if (length_===0x7E) {
		length=(data.slice(2,4)).readUInt();
		mask=mask&&data.slice(4,8);
		index=mask?8:4;
		payload=mask?data.slice(8,8+length):data.slice(4,4+length);
	} else if (length_===0x7F) {
		length=(data.slice(2,10)).readUInt();
		mask=mask&&data.slice(10,14);
		payload=mask?data.slice(14,14+length):data.slice(10,10+length);
		index=mask?14:10;
	} else {
		length=length_;
		mask=mask&&data.slice(2,6);
		payload=mask?data.slice(6,6+length):data.slice(2,2+length);
		index=mask?6:2;
	};

	if (mask) {
		var n=payload.length;
		for (var i=0;i<n;i++) {
			payload[i]=payload[i]^mask[i%4];
		};
	};
	
	payload=[b,payload].concatBuffers();
	
	if (tlength-index>n) {
		return wsdecode(data.slice(n+index),payload);
	} else {
		if (type&0x01) { //string
			return payload.toString('utf8');
		};

		if (type&0x02) { //buffer
			return payload;
		};
	};
};

var wsencode=function(data,type,mask) {
	var l=data.length;
	var Bytes=[];
	mask=mask?crypto.randomBytes(4):mask;
	Bytes.push(type===1?0x81:0x82);
	if (l<0x7E) {
		Bytes.push(mask?(l|0x80):l);
	} else if (l>=0x7E && l<=0xFFFF) {
		Bytes.push(mask?0xFE:0x7E);
		Bytes.push((l>> 8)&0xFF);
		Bytes.push(l&0xFF);
	} else {
		Bytes.push(mask?0xFF:0x7F);
		Bytes.push((l>> 56)&0xFF);
		Bytes.push((l>> 48)&0xFF);
		Bytes.push((l>> 40)&0xFF);
		Bytes.push((l>> 32)&0xFF);
		Bytes.push((l>> 24)&0xFF);
		Bytes.push((l>> 16)&0xFF);
		Bytes.push((l>> 8)&0xFF);
		Bytes.push(l&0xFF);
	};
	var bytes=new Buffer(Bytes.length);
	Bytes.forEach(function(val,i) {bytes[i]=val});
	if (mask) {
		var n=data.length;
		var payload=new Buffer(n);
		for (var i=0;i<n;i++) {
			payload[i]=data[i]^mask[i%4];
		};
	};
	return [bytes,mask,payload].concatBuffers();
};

var websocket_answer=function(res,request) {
	var key=res['Sec-WebSocket-Key'];
	var H = crypto.createHash('sha1');
	H.update(key+'258EAFA5-E914-47DA-95CA-C5AB0DC85B11');
	var hash=H.digest('base64');
	var resp='HTTP/1.1 101 WebSocket Protocol Handshake\r\n';
	resp +='Upgrade: websocket\r\n';
	resp +='Connection: Upgrade\r\n';
	resp +='Sec-WebSocket-Accept:'+hash+'\r\n';
	resp +='Access-Control-Allow-Origin:'+res['Origin']+'\r\n';
	resp +='\r\n';
	return resp;
};

var handleRequest = function (request) {
	request.on('data', function(data) {
		if (request.connected_) {
			data=wsdecode(data);
			console.log('Server receive : '+(Buffer.isBuffer(data)?(data.toString('hex')):data));
			request.write(wsencode(new Buffer('Hello client'),0x01,false));
		} else {
			request.write(websocket_answer(simpleParser(data.toString('utf8'))));
			request.connected_=true;
		};
	});
	request.on('end', function() {});
	request.on('error', function() {});
};

var launchServer = function(port) {
	net.createServer(handleRequest).listen(port,function() {console.log('WS SERVER')});
};

launchServer(WS_port);

var client=new net.Socket();

client.on('connect',function() {
	client.key_=crypto.randomBytes(16).toString('base64');
	var hs='GET / HTTP/1.1\r\n';
	hs +='Host: 213.246.53.127:8002\r\n';
	hs +='User-Agent: Mozilla/5.0 (Windows NT 6.0; WOW64; rv:17.0) Gecko/20100101 Firefox/17.0\r\n';
	hs +='Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n';
	hs +='Accept-Language: en-us,en;q=0.5\r\n';
	hs +='Accept-Encoding: gzip, deflate\r\n';
	hs +='Connection: keep-alive, Upgrade\r\n';
	hs +='Sec-WebSocket-Version: 13\r\n';
	hs +='Origin: http://ianonym.com\r\n';
	hs +='Sec-WebSocket-Key: '+client.key_+'\r\n';
	hs +='Pragma: no-cache\r\n';
	hs +='Cache-Control: no-cache\r\n';
	hs +='Upgrade: websocket\r\n';
	hs +='\r\n';
	client.write(hs);
});

client.on('data',function(data) {
	if (!client.connected_) {
		var res=simpleParser(data.toString('utf8'));
		var key=res['Sec-WebSocket-Accept'];
		if (key) {
			var H = crypto.createHash('sha1');
			H.update(client.key_+'258EAFA5-E914-47DA-95CA-C5AB0DC85B11');
			var hash=H.digest('base64');
			if (key===hash) {
				console.log('Client says : Handshake successfull');
				client.write(wsencode(new Buffer('Hello websocket server','utf8'),0x1,true));
			};
			client.connected_=true;
		};
	} else {
		console.log('Client receive :');
		var rec=wsdecode(data);
		console.log(Buffer.isBuffer(rec)?(rec.toString('hex')):rec);
	};
});

client.connect(WS_port);

//TESTS

//console.log(wsdecode(new Buffer('8287995dc2c0994ce0f3dd08a4','hex')));

//var a=wsencode(new Buffer('00112233445566','hex'),0x2,false);

//console.log(a);

//console.log(wsdecode(a));


