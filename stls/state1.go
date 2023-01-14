package stls

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
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
			return nil, err
		}

		if _, err := buf.Write(_outBuf); err != nil {
			return nil, err
		}
		n += m
		data = data[m:]
	}

	if typ == recordTypeChangeCipherSpec && c.vers != VersionTLS13 {
		if err := c.out.changeCipherSpec(); err != nil {
			return c.AlertRecord(err.(alert)), c.in.setErrorLocked(&net.OpError{Op: "local error", Err: err})
		}
	}

	return buf.Bytes(), nil
}

func (c *Conn) AlertRecord(err alert) []byte {
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

/*
1. 给out上锁
2. 设置error
3. 序列化aler并返回
*/
func (c *Conn) sendAlert2(err alert) []byte {
	c.out.Lock()
	defer c.out.Unlock()

	_ = c.out.setErrorLocked(&net.OpError{Op: "local error", Err: err})
	return c.AlertRecord(err)
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

	return c.tryProcessOneRecord()
}

func (c *Conn) tryProcessOneRecord() (got, send []byte, err error) {
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

	// MAYBUG
	var expectChangeCipherSpec = (c.vers != VersionTLS13) && (c.handshakeServer != nil && c.handshakeServer.stage == ReadClientFinished)

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
			return c.tryProcessOneRecord()
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
			return c.tryProcessOneRecord()
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
			return c.tryProcessOneRecord()
		}
		// Note that data is owned by c.rawInput, following the Next call above,
		// to avoid copying the plaintext. This is safe because c.rawInput is
		// not read from or written to until c.input is drained.
		//c.input.Reset(data)
		return data, nil, nil

	case recordTypeHandshake:
		if len(data) == 0 || expectChangeCipherSpec {
			return nil, c.sendAlert2(alertUnexpectedMessage), c.in.setErrorLocked(&net.OpError{Op: "local error", Err: alertUnexpectedMessage})
		}
		c.hand.Write(data) // 握手数据写入, 没有record的头
		return c.tryHandleHandshake2()
	}

	return
}

func (c *Conn) parseFirstRecordHeader() (send []byte, err error) {
	if c.firstRecord.parsed.Load() {
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
			return
		}
		if _, err = sendB.Write(s); err != nil {
			return
		}
	}
	return gotB.Bytes(), sendB.Bytes(), nil
}

func (c *Conn) handleHandshake2(n int) (got []byte, send []byte, err error) {

	data := c.hand.Next(4 + n) // header: typ(1B) + length(3B)
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
				send, err = c.handshakeServerTLS13.processClientHelloPart1()
			} else {
				// c.handshakeServer = &SSS10{
				// 	inner: &serverHandshakeState{
				// 		c:           c,
				// 		clientHello: clientHello,
				// 	},
				// 	stage:  ProcessClientHello,
				// 	parent: s3,
				// }
				c.stage = PostReadClientHello
			}
			return
		}
	case PostReadClientHelloTLS13:
		{
			return c.handshakeServerTLS13.dohHandshake(msg)
		}
	case PostReadClientHello:
		{
			// return c.handshakeServer.dohHandshake(msg)
			return
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
		return c.AlertRecord(alertProtocolVersion), fmt.Errorf("tls: client offered only unsupported versions: %x", clientVersions)
	}
	c.haveVers = true
	c.in.version = c.vers
	c.out.version = c.vers
	return nil, nil
}

func (hs *serverHandshakeStateTLS13) processClientHelloPart1() (send []byte, err error) {

	hs.hello = new(serverHelloMsg)

	// TLS 1.3 froze the ServerHello.legacy_version field, and uses
	// supported_versions instead. See RFC 8446, sections 4.1.3 and 4.2.1.
	hs.hello.vers = VersionTLS12
	hs.hello.supportedVersion = hs.c.vers

	if len(hs.clientHello.supportedVersions) == 0 {
		return hs.c.sendAlert2(alertIllegalParameter), errors.New("tls: client used the legacy version field to negotiate TLS 1.3")
	}

	// Abort if the client is doing a fallback and landing lower than what we
	// support. See RFC 7507, which however does not specify the interaction
	// with supported_versions. The only difference is that with
	// supported_versions a client has a chance to attempt a [TLS 1.2, TLS 1.4]
	// handshake in case TLS 1.3 is broken but 1.2 is not. Alas, in that case,
	// it will have to drop the TLS_FALLBACK_SCSV protection if it falls back to
	// TLS 1.2, because a TLS 1.3 server would abort here. The situation before
	// supported_versions was not better because there was just no way to do a
	// TLS 1.4 handshake without risking the server selecting TLS 1.3.
	for _, id := range hs.clientHello.cipherSuites {
		if id == TLS_FALLBACK_SCSV {
			// Use c.vers instead of max(supported_versions) because an attacker
			// could defeat this by adding an arbitrary high version otherwise.
			if hs.c.vers < hs.c.config.maxSupportedVersion(roleServer) {
				return hs.c.sendAlert2(alertInappropriateFallback), errors.New("tls: client using inappropriate protocol fallback")
			}
			break
		}
	}

	if len(hs.clientHello.compressionMethods) != 1 ||
		hs.clientHello.compressionMethods[0] != compressionNone {
		return hs.c.sendAlert2(alertIllegalParameter), errors.New("tls: TLS 1.3 client supports illegal compression methods")
	}

	hs.hello.random = make([]byte, 32)
	if _, err := io.ReadFull(hs.c.config.rand(), hs.hello.random); err != nil {
		return hs.c.sendAlert2(alertInternalError), err
	}

	if len(hs.clientHello.secureRenegotiation) != 0 {
		return hs.c.sendAlert2(alertHandshakeFailure), errors.New("tls: initial handshake had non-empty renegotiation extension")
	}

	if hs.clientHello.earlyData {
		// See RFC 8446, Section 4.2.10 for the complicated behavior required
		// here. The scenario is that a different server at our address offered
		// to accept early data in the past, which we can't handle. For now, all
		// 0-RTT enabled session tickets need to expire before a Go server can
		// replace a server or join a pool. That's the same requirement that
		// applies to mixing or replacing with any TLS 1.2 server.
		return hs.c.sendAlert2(alertUnsupportedExtension), errors.New("tls: client sent unexpected early data")
	}

	hs.hello.sessionId = hs.clientHello.sessionId
	hs.hello.compressionMethod = compressionNone

	preferenceList := defaultCipherSuitesTLS13
	if !hasAESGCMHardwareSupport || !aesgcmPreferred(hs.clientHello.cipherSuites) {
		preferenceList = defaultCipherSuitesTLS13NoAES
	}
	for _, suiteID := range preferenceList {
		hs.suite = mutualCipherSuiteTLS13(hs.clientHello.cipherSuites, suiteID)
		if hs.suite != nil {
			break
		}
	}
	if hs.suite == nil {
		return hs.c.sendAlert2(alertHandshakeFailure), errors.New("tls: no cipher suite supported by both client and server")
	}
	hs.c.cipherSuite = hs.suite.id
	hs.hello.cipherSuite = hs.suite.id
	hs.transcript = hs.suite.hash.New()

	// Pick the ECDHE group in server preference order, but give priority to
	// groups with a key share, to avoid a HelloRetryRequest round-trip.
	var selectedGroup CurveID
	var clientKeyShare *keyShare
GroupSelection:
	for _, preferredGroup := range hs.c.config.curvePreferences() {
		for _, ks := range hs.clientHello.keyShares {
			if ks.group == preferredGroup {
				selectedGroup = ks.group
				clientKeyShare = &ks
				break GroupSelection
			}
		}
		if selectedGroup != 0 {
			continue
		}
		for _, group := range hs.clientHello.supportedCurves {
			if group == preferredGroup {
				selectedGroup = group
				break
			}
		}
	}
	if selectedGroup == 0 {
		return hs.c.sendAlert2(alertHandshakeFailure), errors.New("tls: no ECDHE curve supported by both client and server")
	}
	if clientKeyShare == nil {
		hs.preSelectedGroup = selectedGroup

		send, err = hs.doHelloRetryRequest2(selectedGroup)
		hs.stage = ReadSecondClientHello
		return
	}

	if _, ok := curveForCurveID(selectedGroup); selectedGroup != X25519 && !ok {
		return hs.c.sendAlert2(alertInternalError), errors.New("tls: CurvePreferences includes unsupported curve")
	}
	params, err := generateECDHEParameters(hs.c.config.rand(), selectedGroup)
	if err != nil {
		return hs.c.sendAlert2(alertInternalError), err
	}
	hs.hello.serverShare = keyShare{group: selectedGroup, data: params.PublicKey()}
	hs.sharedKey = params.SharedKey(clientKeyShare.data)
	if hs.sharedKey == nil {
		return hs.c.sendAlert2(alertIllegalParameter), errors.New("tls: invalid client key share")
	}

	hs.c.serverName = hs.clientHello.serverName
	return hs.postProcessClientHello()
}

func (hs *serverHandshakeStateTLS13) processClientHelloPart2(msg any) (send []byte, err error) {
	clientHello, ok := msg.(*clientHelloMsg)
	if !ok {
		return hs.c.sendAlert2(alertUnexpectedMessage), unexpectedMessageError(clientHello, msg)
	}

	if len(clientHello.keyShares) != 1 || clientHello.keyShares[0].group != hs.preSelectedGroup {
		return hs.c.sendAlert2(alertIllegalParameter), errors.New("tls: client sent invalid key share in second ClientHello")
	}

	if clientHello.earlyData {
		return hs.c.sendAlert2(alertIllegalParameter), errors.New("tls: client indicated early data in second ClientHello")
	}

	if illegalClientHelloChange(clientHello, hs.clientHello) {
		return hs.c.sendAlert2(alertIllegalParameter), errors.New("tls: client illegally modified second ClientHello")
	}

	hs.clientHello = clientHello

	// ---
	clientKeyShare := &hs.clientHello.keyShares[0]
	if _, ok := curveForCurveID(hs.preSelectedGroup); hs.preSelectedGroup != X25519 && !ok {
		return hs.c.sendAlert2(alertInternalError), errors.New("tls: CurvePreferences includes unsupported curve")
	}
	params, err := generateECDHEParameters(hs.c.config.rand(), hs.preSelectedGroup)
	if err != nil {
		return hs.c.sendAlert2(alertInternalError), err
	}
	hs.hello.serverShare = keyShare{group: hs.preSelectedGroup, data: params.PublicKey()}
	hs.sharedKey = params.SharedKey(clientKeyShare.data)
	if hs.sharedKey == nil {
		return hs.c.sendAlert2(alertIllegalParameter), errors.New("tls: invalid client key share")
	}
	hs.c.serverName = hs.clientHello.serverName
	// ---
	return hs.postProcessClientHello()
}

func (hs *serverHandshakeStateTLS13) postProcessClientHello() (send []byte, err error) {
	if send, err = hs.checkForResumption2(); err != nil {
		return
	}
	if send, err = hs.pickCertificate2(); err != nil {
		return
	}
	hs.c.buffering = true

	// 生成server端参数, 准备发送
	// MAYBUG 吃内存
	var buf bytes.Buffer

	part1, err := hs.sendServerParameters2()
	if err != nil {
		return part1, err
	}
	_, err = buf.Write(part1)
	if err != nil {
		return nil, err
	}
	part2, err := hs.sendServerCertificate2()
	if err != nil {
		return part2, err
	}
	_, err = buf.Write(part2)
	if err != nil {
		return nil, err
	}
	part3, err := hs.sendServerFinished2()
	if err != nil {
		return part3, err
	}
	_, err = buf.Write(part3)
	if err != nil {
		return nil, err
	}

	hs.stage = PostProcessClientHello
	return buf.Bytes(), nil
}

func (hs *serverHandshakeStateTLS13) dohHandshake(msg any) (got []byte, send []byte, err error) {

	switch hs.stage {
	case ProcessClientHello:
		send, err = hs.processClientHelloPart1()
	case ReadSecondClientHello:
		send, err = hs.processClientHelloPart2(msg)
	// -------
	case PostProcessClientHello:
		if !hs.requestClientCert() {
			// Make sure the connection is still being verified whether or not
			// the server requested a client certificate.
			if hs.c.config.VerifyConnection != nil {
				if err := hs.c.config.VerifyConnection(hs.c.connectionStateLocked()); err != nil {
					return nil, hs.c.sendAlert2(alertBadCertificate), err
				}
			}
			hs.stage = ReadClientFinished
			return hs.dohHandshake(msg) // 这时的msg是finishedMsg
		}
		send, err = hs.processClientCertificatePart1(msg)
	case ReadClientCertificateVerify:
		send, err = hs.readClientCertificatePart2(msg)
	case ReadClientFinished:
		send, err = hs.processClientFinished(msg)
	case HandshakeFinished:
		fmt.Println("按理说走不到这个, 漏了post处理")
		fallthrough
	default:
		return nil, hs.c.sendAlert2(alertUnexpectedMessage), errors.New("内部状态不太对")
	}
	return
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
