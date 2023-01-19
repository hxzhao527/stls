package stls

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"sync/atomic"
	"time"
)

func (c *Conn) marshalRecord(typ recordType, data []byte) ([]byte, error) {
	var buf bytes.Buffer

	var n int
	for len(data) > 0 {
		m := len(data)
		if maxPayload := c.maxPayloadSizeForWrite(typ); m > maxPayload {
			m = maxPayload
		}

		var outBuf [recordHeaderLen]byte

		outBuf[0] = byte(typ)
		vers := c.vers
		if vers == 0 {
			// Some TLS servers fail if the record version is
			// greater than TLS 1.0 for the initial ClientHello.
			vers = VersionTLS10
		} else if vers == VersionTLS13 {
			// TLS 1.3 froze the record layer version to 1.2.
			// See RFC 8446, Section 5.1.
			vers = VersionTLS12
		}
		outBuf[1] = byte(vers >> 8)
		outBuf[2] = byte(vers)
		outBuf[3] = byte(m >> 8)
		outBuf[4] = byte(m)

		var err error
		_outBuf, err := c.out.encrypt(outBuf[:], data[:m], c.config.rand())
		if err != nil {
			// MAYBUG: 能发多少, 发多少
			return buf.Bytes(), err
		}
		// 单步的write失败, 不能影响之前已经序列化好的数据
		if _, err := buf.Write(_outBuf); err != nil {
			return buf.Bytes(), err
		}
		n += m
		data = data[m:]
	}

	if typ == recordTypeChangeCipherSpec && c.vers != VersionTLS13 {
		if err := c.out.changeCipherSpec(); err != nil {
			// 检验不过, 也需要将之前已经序列化好的数据先发送
			// 这个alert排在后面
			if _, err := buf.Write(c.sendAlert2(err.(alert))); err != nil {
				return buf.Bytes(), err
			}
			return buf.Bytes(), c.in.setErrorLocked(&net.OpError{Op: "local error", Err: err})
		}
	}

	return buf.Bytes(), nil
}

func (c *Conn) alertRecord(err alert) []byte {
	switch err {
	case alertNoRenegotiation, alertCloseNotify:
		c.tmp[0] = alertLevelWarning
	default:
		c.tmp[0] = alertLevelError
	}
	c.tmp[1] = byte(err)

	data, _ := c.marshalRecord(recordTypeAlert, c.tmp[0:2])
	return data
}

func (c *Conn) writeRecord2(writer io.Writer, typ recordType, data []byte) error {
	bs, err := c.marshalRecord(typ, data)
	if err != nil {
		return err
	}
	_, err = writer.Write(bs)
	return err
}

/*
1. 给out上锁
2. 设置error
3. 序列化aler并返回
*/
func (c *Conn) sendAlert2(err alert) []byte {
	c.out.Lock()
	defer c.out.Unlock()

	_ = c.out.setErrorLocked(&net.OpError{Op: "local error", Err: err})
	return c.alertRecord(err)
}

func (c *Conn) Reset() {
	// 重试firstRecord和rawInput
}

func (c *Conn) resetFirstRecord() {
	c.firstRecord.typ = 0
	c.firstRecord.n = 0
	c.firstRecord.parsed.Store(false)
}

/*
数据输入只有两个出向, 一个是作为握手输入写入hand中, 一个是作为应用数据通过got返回
其他直接skip即可

	// TODO 需要锁
	// TODO 需要检查之前的error
	// TODO 前置读取失败的err, 直接处理, 不再进入状态机, 对应 net.Error
	// FIXME: err不为空, send为空时, 生成兜底send
*/
func (c *Conn) Eat(payload []byte) (got []byte, send []byte, err error) {

	if err = c.in.err; err != nil {
		return
	}

	_, err = c.rawInput.Write(payload)
	if err != nil {
		return nil, c.sendAlert2(alertInternalError), err
	}

	return c.tryProcessNextOneRecord()
}

func (c *Conn) tryProcessNextOneRecord() (got, send []byte, err error) {
	// 重试次数在processOneRecord里, 偶尔加一下
	if c.retryCount > maxUselessRecords {
		return nil, c.sendAlert2(alertUnexpectedMessage), c.in.setErrorLocked(errors.New("tls: too many ignored records"))
	}

	var gotB bytes.Buffer
	var sendB bytes.Buffer

	for c.rawInput.Len() > 0 {
		if c.rawInput.Len() < recordHeaderLen {
			// 连record-header都不够
			break
		}
		if send, err = c.parseFirstRecordHeader(); err != nil {
			return
		}
		n := c.firstRecord.n
		if c.rawInput.Len() < recordHeaderLen+n {
			// 不够一个record
			break
		}
		g, s, e := c.processOneRecord()
		if e != nil {
			return g, s, e
		}

		if _, err = gotB.Write(g); err != nil {
			return
		}
		if _, err = sendB.Write(s); err != nil {
			return
		}

	}

	return gotB.Bytes(), sendB.Bytes(), nil
}

func (c *Conn) processOneRecord() (got, send []byte, err error) {
	handshakeComplete := c.handshakeComplete()
	n := c.firstRecord.n

	// Process message.
	record := c.rawInput.Next(recordHeaderLen + n) // 含record长度的完整记录
	// record被切走了
	c.resetFirstRecord()

	data, typ, err := c.in.decrypt(record)
	if err != nil {
		return nil, c.sendAlert2(err.(alert)), c.in.setErrorLocked(&net.OpError{Op: "local error", Err: err})
	}

	if len(data) > maxPlaintext {
		return nil, c.sendAlert2(alertRecordOverflow), c.in.setErrorLocked(&net.OpError{Op: "local error", Err: alertRecordOverflow})
	}

	// Application Data messages are always protected.
	if c.in.cipher == nil && typ == recordTypeApplicationData {
		return nil, c.sendAlert2(alertUnexpectedMessage), c.in.setErrorLocked(&net.OpError{Op: "local error", Err: alertUnexpectedMessage})
	}

	if typ != recordTypeAlert && typ != recordTypeChangeCipherSpec && len(data) > 0 {
		// This is a state-advancing message: reset the retry count.
		c.retryCount = 0
	}

	// Handshake messages MUST NOT be interleaved with other record types in TLS 1.3.
	if c.vers == VersionTLS13 && typ != recordTypeHandshake && c.hand.Len() > 0 {
		return nil, c.sendAlert2(alertUnexpectedMessage), c.in.setErrorLocked(&net.OpError{Op: "local error", Err: alertUnexpectedMessage})
	}

	// MAYBUG: 非1.3部分是这个参数在readfinsh时会变为true, 即允许收到 CCS record
	// var expectChangeCipherSpec = (c.vers != VersionTLS13) && c.handshakeServer != nil && (c.handshakeServer.stage == ReadClientFinished1 || c.handshakeServer.stage == ReadClientFinished2)
	var expectChangeCipherSpec = atomic.SwapInt32(&c.expectChangeCipherSpec, 0) > 0

	switch typ {
	default:
		return nil, c.sendAlert2(alertUnexpectedMessage), c.in.setErrorLocked(&net.OpError{Op: "local error", Err: alertUnexpectedMessage})

	case recordTypeAlert:
		if len(data) != 2 {
			return nil, c.sendAlert2(alertUnexpectedMessage), c.in.setErrorLocked(&net.OpError{Op: "local error", Err: alertUnexpectedMessage})
		}
		if alert(data[1]) == alertCloseNotify {
			return nil, nil, c.in.setErrorLocked(io.EOF)
		}
		if c.vers == VersionTLS13 {
			return nil, nil, c.in.setErrorLocked(&net.OpError{Op: "remote error", Err: alert(data[1])})
		}
		switch data[0] {
		case alertLevelWarning:
			// Drop the record on the floor and retry.
			c.retryCount++
			return c.tryProcessNextOneRecord()
		case alertLevelError:
			return nil, nil, c.in.setErrorLocked(&net.OpError{Op: "remote error", Err: alert(data[1])})
		default:
			return nil, c.sendAlert2(alertUnexpectedMessage), c.in.setErrorLocked(&net.OpError{Op: "local error", Err: alertUnexpectedMessage})
		}

	case recordTypeChangeCipherSpec:
		if len(data) != 1 || data[0] != 1 {
			return nil, c.sendAlert2(alertDecodeError), c.in.setErrorLocked(&net.OpError{Op: "local error", Err: alertDecodeError})
		}
		// Handshake messages are not allowed to fragment across the CCS.
		if c.hand.Len() > 0 {
			return nil, c.sendAlert2(alertUnexpectedMessage), c.in.setErrorLocked(&net.OpError{Op: "local error", Err: alertUnexpectedMessage})
		}
		// In TLS 1.3, change_cipher_spec records are ignored until the
		// Finished. See RFC 8446, Appendix D.4. Note that according to Section
		// 5, a server can send a ChangeCipherSpec before its ServerHello, when
		// c.vers is still unset. That's not useful though and suspicious if the
		// server then selects a lower protocol version, so don't allow that.
		if c.vers == VersionTLS13 {
			c.retryCount++
			return c.tryProcessNextOneRecord()
		}
		if !expectChangeCipherSpec {
			return nil, c.sendAlert2(alertUnexpectedMessage), c.in.setErrorLocked(&net.OpError{Op: "local error", Err: alertUnexpectedMessage})
		}
		if err := c.in.changeCipherSpec(); err != nil {
			return nil, c.sendAlert2(err.(alert)), c.in.setErrorLocked(&net.OpError{Op: "local error", Err: err})
		}

	case recordTypeApplicationData:
		if !handshakeComplete || expectChangeCipherSpec {
			return nil, c.sendAlert2(alertUnexpectedMessage), c.in.setErrorLocked(&net.OpError{Op: "local error", Err: alertUnexpectedMessage})
		}
		// Some OpenSSL servers send empty records in order to randomize the
		// CBC IV. Ignore a limited number of empty records.
		if len(data) == 0 {
			c.retryCount++
			return c.tryProcessNextOneRecord()
		}
		// Note that data is owned by c.rawInput, following the Next call above,
		// to avoid copying the plaintext. This is safe because c.rawInput is
		// not read from or written to until c.input is drained.
		//c.input.Reset(data)
		return data, nil, nil // application数据直接返回给上层

	case recordTypeHandshake:
		if len(data) == 0 || expectChangeCipherSpec {
			return nil, c.sendAlert2(alertUnexpectedMessage), c.in.setErrorLocked(&net.OpError{Op: "local error", Err: alertUnexpectedMessage})
		}
		_, err := c.hand.Write(data) // 握手数据写入, 没有record的头
		if err != nil {
			return nil, c.sendAlert2(alertInternalError), c.in.setErrorLocked(&net.OpError{Op: "local error", Err: alertInternalError})
		}
		return c.tryHandleHandshake2()
	}

	return
}

func (c *Conn) parseFirstRecordHeader() (send []byte, err error) {
	if c.firstRecord.parsed.Load() {
		// 解析过了, 不用重复
		// 如果有误, 前面已经把err返回了, 再调用eat
		// 如果有效, 不用再校验
		// 切走第一个record之后重置
		return
	}

	handshakeComplete := c.handshakeComplete()

	hdr := c.rawInput.Bytes()[:recordHeaderLen]
	typ := recordType(hdr[0])

	// No valid TLS record has a type of 0x80, however SSLv2 handshakes
	// start with a uint16 length where the MSB is set and the first record
	// is always < 256 bytes long. Therefore typ == 0x80 strongly suggests
	// an SSLv2 client.
	if !handshakeComplete && typ == 0x80 {
		return c.sendAlert2(alertProtocolVersion), c.in.setErrorLocked(c.newRecordHeaderError(nil, "unsupported SSLv2 handshake received"))
	}

	vers := uint16(hdr[1])<<8 | uint16(hdr[2])
	n := int(hdr[3])<<8 | int(hdr[4])

	if c.haveVers && c.vers != VersionTLS13 && vers != c.vers {
		msg := fmt.Sprintf("received record with version %x when expecting version %x", vers, c.vers)
		return c.sendAlert2(alertProtocolVersion), c.in.setErrorLocked(c.newRecordHeaderError(nil, msg))
	}
	if !c.haveVers {
		// First message, be extra suspicious: this might not be a TLS
		// client. Bail out before reading a full 'body', if possible.
		// The current max version is 3.3 so if the version is >= 16.0,
		// it's probably not real.
		if (typ != recordTypeAlert && typ != recordTypeHandshake) || vers >= 0x1000 {
			return nil, c.in.setErrorLocked(c.newRecordHeaderError(c.conn, "first record does not look like a TLS handshake"))
		}
	}
	if c.vers == VersionTLS13 && n > maxCiphertextTLS13 || n > maxCiphertext {
		msg := fmt.Sprintf("oversized record received with length %d", n)
		return c.sendAlert2(alertRecordOverflow), c.in.setErrorLocked(c.newRecordHeaderError(nil, msg))
	}

	c.firstRecord.typ = typ
	c.firstRecord.n = n
	c.firstRecord.parsed.Store(true)
	return
}

func (c *Conn) tryHandleHandshake2() (got []byte, send []byte, err error) {
	var gotB bytes.Buffer
	var sendB bytes.Buffer

	// 有多少处理多少
	for c.hand.Len() > 0 {
		if c.hand.Len() < 4 {
			// msg的头不够
			break
		}

		data := c.hand.Bytes()
		n := int(data[1])<<16 | int(data[2])<<8 | int(data[3]) // uint24 表示这个msg的长度. 一个msg可能拆成多个record
		if n > maxHandshake {
			return nil, c.sendAlert2(alertInternalError), c.in.setErrorLocked(fmt.Errorf("tls: handshake message of length %d bytes exceeds maximum of %d bytes", n, maxHandshake))
		}

		if c.hand.Len() < 4+n {
			// 不是一个完成的 handshake-msg
			break
		}

		g, s, e := c.handleHandshake2(n)
		if e != nil {
			return g, s, e
		}
		if _, err = gotB.Write(g); err != nil {
			// NOTICE: 所有的内部错误, 都统一返回alertInternalError
			return nil, c.sendAlert2(alertInternalError), err
		}
		if _, err = sendB.Write(s); err != nil {
			return nil, c.sendAlert2(alertInternalError), err
		}
	}
	return gotB.Bytes(), sendB.Bytes(), nil
}

func (c *Conn) handleHandshake2(n int) (got []byte, send []byte, err error) {

	data := c.hand.Next(4 + n) // header: typ(1B) + length(3B); 加数据(n)
	var m handshakeMessage
	switch data[0] {
	case typeHelloRequest:
		m = new(helloRequestMsg)
	case typeClientHello:
		m = new(clientHelloMsg)
	case typeServerHello:
		m = new(serverHelloMsg)
	case typeNewSessionTicket:
		if c.vers == VersionTLS13 {
			m = new(newSessionTicketMsgTLS13)
		} else {
			m = new(newSessionTicketMsg)
		}
	case typeCertificate:
		if c.vers == VersionTLS13 {
			m = new(certificateMsgTLS13)
		} else {
			m = new(certificateMsg)
		}
	case typeCertificateRequest:
		if c.vers == VersionTLS13 {
			m = new(certificateRequestMsgTLS13)
		} else {
			m = &certificateRequestMsg{
				hasSignatureAlgorithm: c.vers >= VersionTLS12,
			}
		}
	case typeCertificateStatus:
		m = new(certificateStatusMsg)
	case typeServerKeyExchange:
		m = new(serverKeyExchangeMsg)
	case typeServerHelloDone:
		m = new(serverHelloDoneMsg)
	case typeClientKeyExchange:
		m = new(clientKeyExchangeMsg)
	case typeCertificateVerify:
		m = &certificateVerifyMsg{
			hasSignatureAlgorithm: c.vers >= VersionTLS12,
		}
	case typeFinished:
		m = new(finishedMsg)
	case typeEncryptedExtensions:
		m = new(encryptedExtensionsMsg)
	case typeEndOfEarlyData:
		m = new(endOfEarlyDataMsg)
	case typeKeyUpdate:
		m = new(keyUpdateMsg)
	default:
		return nil, c.sendAlert2(alertUnexpectedMessage), c.in.setErrorLocked(&net.OpError{Op: "local error", Err: alertUnexpectedMessage})
	}

	// The handshake message unmarshalers
	// expect to be able to keep references to data,
	// so pass in a fresh copy that won't be overwritten.
	// ~~MAYBUG: 数据不再拷贝, 因为是一个函数处理过程, 前面已经写到buf中, 数据所有权就在这个状态机内部~~
	// WARN: 这个地方不copy, 会导致client-hello, 尤其是random值发生变化. 因此必须copy
	data = append([]byte(nil), data...)

	if !m.unmarshal(data) {
		return nil, c.sendAlert2(alertUnexpectedMessage), c.in.setErrorLocked(&net.OpError{Op: "local error", Err: alertUnexpectedMessage})
	}
	// 拿到 完整 msg, 开始握手
	return c.doHandshake2(m)
}

func (c *Conn) doHandshake2(msg any) (got []byte, send []byte, err error) {
	switch c.stage {
	case ReadClientHello:
		{
			clientHello, ok := msg.(*clientHelloMsg)
			if !ok {
				return nil, c.sendAlert2(alertUnexpectedMessage), unexpectedMessageError(clientHello, msg)
			}
			send, err = c.processClientHello2(clientHello)
			if err != nil {
				return
			}
			if c.vers == VersionTLS13 {
				c.handshakeServerTLS13 = &serverHandshakeStateTLS13{
					c:           c,
					clientHello: clientHello,

					stage: ProcessClientHello,
				}
				c.stage = PostReadClientHelloTLS13
				return c.doHandshake2(msg)
			} else {
				c.handshakeServer = &serverHandshakeState{
					c:           c,
					clientHello: clientHello,
					stage:       ProcessClientHello,
				}

				c.stage = PostReadClientHello
				return c.doHandshake2(msg)
			}
		}
	case PostReadClientHelloTLS13:
		{
			return c.handshakeServerTLS13.handshake2(msg)
		}
	case PostReadClientHello:
		{
			return c.handshakeServer.handshake2(msg)
		}
	default:
		panic("unreachable")
	}
}

func (c *Conn) processClientHello2(msg *clientHelloMsg) (send []byte, err error) {
	var configForClient *Config
	originalConfig := c.config
	if c.config.GetConfigForClient != nil {
		// chi := clientHelloInfo(ctx, c, clientHello)
		// if configForClient, err = c.config.GetConfigForClient(chi); err != nil {
		// 	c.sendAlert(alertInternalError)
		// 	return nil, err
		// } else if configForClient != nil {
		// 	c.config = configForClient
		// }
	}
	c.ticketKeys = originalConfig.ticketKeys(configForClient)

	clientVersions := msg.supportedVersions
	if len(msg.supportedVersions) == 0 {
		clientVersions = supportedVersionsFromMax(msg.vers)
	}
	var ok bool
	c.vers, ok = c.config.mutualVersion(roleServer, clientVersions)
	if !ok {
		return c.sendAlert2(alertProtocolVersion), fmt.Errorf("tls: client offered only unsupported versions: %x", clientVersions)
	}
	c.haveVers = true
	c.in.version = c.vers
	c.out.version = c.vers
	return nil, nil
}

func (c *Conn) Out(b []byte) (send []byte, err error) {
	c.out.Lock()
	defer c.out.Unlock()

	if err := c.out.err; err != nil {
		return nil, err
	}

	if !c.handshakeComplete() {
		return nil, alertInternalError
	}

	if c.closeNotifySent {
		return nil, errShutdown
	}

	// var m int
	if len(b) > 1 && c.vers == VersionTLS10 {
		// if _, ok := c.out.cipher.(cipher.BlockMode); ok {
		// 	n, err := c.writeRecordLocked(recordTypeApplicationData, b[:1])
		// 	if err != nil {
		// 		return n, c.out.setErrorLocked(err)
		// 	}
		// 	m, b = 1, b[1:]
		// }
	}
	return c.marshalRecord(recordTypeApplicationData, b)
}

func (c *Conn) handleNewSessionTicket2(msg *newSessionTicketMsgTLS13) (send []byte, err error) {
	// 鸡肋
	if !c.isClient {
		return c.sendAlert2(alertUnexpectedMessage), errors.New("tls: received new session ticket from a client")
	}

	if c.config.SessionTicketsDisabled || c.config.ClientSessionCache == nil {
		return nil, nil
	}

	// See RFC 8446, Section 4.6.1.
	if msg.lifetime == 0 {
		return nil, nil
	}
	lifetime := time.Duration(msg.lifetime) * time.Second
	if lifetime > maxSessionTicketLifetime {

		return c.sendAlert2(alertIllegalParameter), errors.New("tls: received a session ticket with invalid lifetime")
	}

	cipherSuite := cipherSuiteTLS13ByID(c.cipherSuite)
	if cipherSuite == nil || c.resumptionSecret == nil {
		return c.sendAlert2(alertInternalError), c.out.setErrorLocked(&net.OpError{Op: "local error", Err: err})
	}

	// Save the resumption_master_secret and nonce instead of deriving the PSK
	// to do the least amount of work on NewSessionTicket messages before we
	// know if the ticket will be used. Forward secrecy of resumed connections
	// is guaranteed by the requirement for pskModeDHE.
	session := &ClientSessionState{
		sessionTicket:      msg.label,
		vers:               c.vers,
		cipherSuite:        c.cipherSuite,
		masterSecret:       c.resumptionSecret,
		serverCertificates: c.peerCertificates,
		verifiedChains:     c.verifiedChains,
		receivedAt:         c.config.time(),
		nonce:              msg.nonce,
		useBy:              c.config.time().Add(lifetime),
		ageAdd:             msg.ageAdd,
		ocspResponse:       c.ocspResponse,
		scts:               c.scts,
	}

	cacheKey := clientSessionCacheKey(c.conn.RemoteAddr(), c.config)
	c.config.ClientSessionCache.Put(cacheKey, session)

	return nil, nil
}

func (c *Conn) handleKeyUpdate2(keyUpdate *keyUpdateMsg) (send []byte, err error) {
	cipherSuite := cipherSuiteTLS13ByID(c.cipherSuite)
	if cipherSuite == nil {
		return c.sendAlert2(alertInternalError), c.in.setErrorLocked(&net.OpError{Op: "local error", Err: alertInternalError})
	}

	newSecret := cipherSuite.nextTrafficSecret(c.in.trafficSecret)
	c.in.setTrafficSecret(cipherSuite, newSecret)

	if keyUpdate.updateRequested {
		c.out.Lock()
		defer c.out.Unlock()

		msg := &keyUpdateMsg{}
		send, err = c.marshalRecord(recordTypeHandshake, msg.marshal())
		if err != nil {
			// Surface the error at the next write.
			c.out.setErrorLocked(err)
			return
		}

		newSecret := cipherSuite.nextTrafficSecret(c.out.trafficSecret)
		c.out.setTrafficSecret(cipherSuite, newSecret)
	}

	return
}

// handleRenegotiation processes a HelloRequest handshake message.
func (c *Conn) handleRenegotiation2(msg any) (send []byte, err error) {
	if c.vers == VersionTLS13 {
		return nil, errors.New("tls: internal error: unexpected renegotiation")
	}

	helloReq, ok := msg.(*helloRequestMsg)
	if !ok {

		return c.sendAlert2(alertUnexpectedMessage), unexpectedMessageError(helloReq, msg)
	}

	if !c.isClient {
		return c.sendAlert2(alertNoRenegotiation), &net.OpError{Op: "local error", Err: alertNoRenegotiation}
	}

	// 2023-01-17 只是实现了server的tls
	// 后面的代码暂时执行不到
	panic("unreachable")

	switch c.config.Renegotiation {
	case RenegotiateNever:
		return c.sendAlert2(alertNoRenegotiation), &net.OpError{Op: "local error", Err: alertNoRenegotiation}
	case RenegotiateOnceAsClient:
		if c.handshakes > 1 {
			return c.sendAlert2(alertNoRenegotiation), &net.OpError{Op: "local error", Err: alertNoRenegotiation}
		}
	case RenegotiateFreelyAsClient:
		// Ok.
	default:

		return c.sendAlert2(alertInternalError), errors.New("tls: unknown Renegotiation value")
	}

	c.handshakeMutex.Lock()
	defer c.handshakeMutex.Unlock()

	atomic.StoreUint32(&c.handshakeStatus, 0)
	if c.handshakeErr = c.clientHandshake(context.Background()); c.handshakeErr == nil {
		c.handshakes++
	}
	return
}

func (c *Conn) processCertsFromClient2(certificate Certificate) ([]byte, error) {
	certificates := certificate.Certificate
	certs := make([]*x509.Certificate, len(certificates))
	var err error
	for i, asn1Data := range certificates {
		if certs[i], err = x509.ParseCertificate(asn1Data); err != nil {
			return c.sendAlert2(alertBadCertificate), errors.New("tls: failed to parse client certificate: " + err.Error())
		}
	}

	if len(certs) == 0 && requiresClientCert(c.config.ClientAuth) {
		return c.sendAlert2(alertBadCertificate), errors.New("tls: client didn't provide a certificate")
	}

	if c.config.ClientAuth >= VerifyClientCertIfGiven && len(certs) > 0 {
		opts := x509.VerifyOptions{
			Roots:         c.config.ClientCAs,
			CurrentTime:   c.config.time(),
			Intermediates: x509.NewCertPool(),
			KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		}

		for _, cert := range certs[1:] {
			opts.Intermediates.AddCert(cert)
		}

		chains, err := certs[0].Verify(opts)
		if err != nil {
			return c.sendAlert2(alertBadCertificate), errors.New("tls: failed to verify client certificate: " + err.Error())
		}

		c.verifiedChains = chains
	}

	c.peerCertificates = certs
	c.ocspResponse = certificate.OCSPStaple
	c.scts = certificate.SignedCertificateTimestamps

	if len(certs) > 0 {
		switch certs[0].PublicKey.(type) {
		case *ecdsa.PublicKey, *rsa.PublicKey, ed25519.PublicKey:
		default:
			return c.sendAlert2(alertUnsupportedCertificate), fmt.Errorf("tls: client certificate contains an unsupported public key of type %T", certs[0].PublicKey)
		}
	}

	if c.config.VerifyPeerCertificate != nil {
		if err := c.config.VerifyPeerCertificate(certificates, c.verifiedChains); err != nil {
			return c.sendAlert2(alertBadCertificate), err
		}
	}

	return nil, nil
}
