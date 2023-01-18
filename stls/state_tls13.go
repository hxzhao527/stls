package stls

import (
	"bytes"
	"crypto"
	"crypto/hmac"
	"crypto/rsa"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync/atomic"
	"time"
)

/*
1.3 握手入口

吃一个msg, 如果是client-hello, 在初始化时其实已经赋值, 这个函数内部不再赋值, 直接引用取值
其他msg会解析处理
*/
func (hs *serverHandshakeStateTLS13) handshake2(msg any) (got []byte, send []byte, err error) {

	// 因为注掉了boring, 所以这个检查也可以暂时注掉
	// if needFIPS() {
	// 	return nil, nil, errors.New("tls: internal error: TLS 1.3 reached in FIPS mode")
	// }

	switch hs.stage {
	case ProcessClientHello:
		send, err = hs.processClientHelloPart1()
	case ReadSecondClientHello:
		send, err = hs.processClientHelloPart2(msg)
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
			// msg还要塞回去, 否则会丢数据
			return hs.handshake2(msg)
		}
		send, err = hs.processClientCertificatePart1(msg)
	case ReadClientCertificateVerify:
		send, err = hs.readClientCertificatePart2(msg)
	case ReadClientFinished:
		send, err = hs.processClientFinished(msg)
	case HandshakeFinished:
		send, err = hs.handlePostHandshakeMessage2(msg)
	default:
		return nil, hs.c.sendAlert2(alertUnexpectedMessage), errors.New("内部状态不太对")
	}
	return
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

	hs.preSelectedGroup = selectedGroup // 暂存
	hs.preKeyShare = clientKeyShare
	if clientKeyShare == nil {
		send, err = hs.writeHelloRetryRequest2(selectedGroup)
		hs.stage = ReadSecondClientHello
		return
	}

	return hs.processClientHelloPart3()
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

	hs.clientHello = clientHello //更新client-hello
	hs.preKeyShare = &hs.clientHello.keyShares[0]
	return hs.processClientHelloPart3()
}

func (hs *serverHandshakeStateTLS13) processClientHelloPart3() (send []byte, err error) {
	clientKeyShare := hs.preKeyShare
	selectedGroup := hs.preSelectedGroup
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

func (hs *serverHandshakeStateTLS13) postProcessClientHello() (send []byte, err error) {
	if send, err = hs.checkForResumption2(); err != nil {
		return
	}
	if send, err = hs.pickCertificate2(); err != nil {
		return
	}
	hs.c.buffering = true

	// 生成server端参数, 准备发送
	// MAYBUG: 吃内存
	// MAYBUG: 部分处理成功, 部分处理失败时返回值, 要不要包含前面已经处理成功的部分的返回数据
	var buf bytes.Buffer

	part, err := hs.sendServerParameters2()
	if err != nil {
		return part, err
	}
	_, err = buf.Write(part)
	if err != nil {
		return hs.c.sendAlert2(alertInternalError), err
	}
	part, err = hs.sendServerCertificate2()
	if err != nil {
		return part, err
	}
	_, err = buf.Write(part)
	if err != nil {
		return hs.c.sendAlert2(alertInternalError), err
	}
	part3, err := hs.sendServerFinished2()
	if err != nil {
		return part3, err
	}
	_, err = buf.Write(part3)
	if err != nil {
		return hs.c.sendAlert2(alertInternalError), err
	}

	hs.stage = PostProcessClientHello
	return buf.Bytes(), nil
}

func (hs *serverHandshakeStateTLS13) sendSessionTickets2() ([]byte, error) {
	c := hs.c

	hs.clientFinished = hs.suite.finishedHash(c.in.trafficSecret, hs.transcript)
	finishedMsg := &finishedMsg{
		verifyData: hs.clientFinished,
	}
	hs.transcript.Write(finishedMsg.marshal())

	if !hs.shouldSendSessionTickets() {
		return nil, nil
	}

	resumptionSecret := hs.suite.deriveSecret(hs.masterSecret,
		resumptionLabel, hs.transcript)

	m := new(newSessionTicketMsgTLS13)

	var certsFromClient [][]byte
	for _, cert := range c.peerCertificates {
		certsFromClient = append(certsFromClient, cert.Raw)
	}
	state := sessionStateTLS13{
		cipherSuite:      hs.suite.id,
		createdAt:        uint64(c.config.time().Unix()),
		resumptionSecret: resumptionSecret,
		certificate: Certificate{
			Certificate:                 certsFromClient,
			OCSPStaple:                  c.ocspResponse,
			SignedCertificateTimestamps: c.scts,
		},
	}
	var err error
	m.label, err = c.encryptTicket(state.marshal())
	if err != nil {
		return nil, err
	}
	m.lifetime = uint32(maxSessionTicketLifetime / time.Second)

	// ticket_age_add is a random 32-bit value. See RFC 8446, section 4.6.1
	// The value is not stored anywhere; we never need to check the ticket age
	// because 0-RTT is not supported.
	ageAdd := make([]byte, 4)
	_, err = hs.c.config.rand().Read(ageAdd)
	if err != nil {
		return nil, err
	}
	m.ageAdd = binary.LittleEndian.Uint32(ageAdd)

	// ticket_nonce, which must be unique per connection, is always left at
	// zero because we only ever send one ticket per connection.

	return c.marshalRecord(recordTypeHandshake, m.marshal())
}

func (hs *serverHandshakeStateTLS13) processClientCertificatePart1(msg any) ([]byte, error) {
	c := hs.c

	// If we requested a client certificate, then the client must send a
	// certificate message. If it's empty, no CertificateVerify is sent.

	certMsg, ok := msg.(*certificateMsgTLS13)
	if !ok {
		return c.sendAlert2(alertUnexpectedMessage), unexpectedMessageError(certMsg, msg)
	}
	hs.transcript.Write(certMsg.marshal())

	if send, err := c.processCertsFromClient2(certMsg.certificate); err != nil {
		return send, err
	}

	// if c.config.VerifyConnection != nil {
	// 	if err := c.config.VerifyConnection(c.connectionStateLocked()); err != nil {
	// 		return c.sendAlert2(alertBadCertificate), err
	// 	}
	// }

	if len(certMsg.certificate.Certificate) != 0 {
		hs.stage = ReadClientCertificateVerify
		return nil, nil
	}

	// If we waited until the client certificates to send session tickets, we
	// are ready to do it now.
	hs.stage = ReadClientFinished
	return hs.sendSessionTickets2()
}

func (hs *serverHandshakeStateTLS13) readClientCertificatePart2(msg any) ([]byte, error) {
	c := hs.c
	certVerify, ok := msg.(*certificateVerifyMsg)
	if !ok {
		return c.sendAlert2(alertUnexpectedMessage), unexpectedMessageError(certVerify, msg)
	}

	// See RFC 8446, Section 4.4.3.
	if !isSupportedSignatureAlgorithm(certVerify.signatureAlgorithm, supportedSignatureAlgorithms()) {
		return c.sendAlert2(alertIllegalParameter), errors.New("tls: client certificate used with invalid signature algorithm")
	}

	sigType, sigHash, err := typeAndHashFromSignatureScheme(certVerify.signatureAlgorithm)
	if err != nil {
		return c.sendAlert2(alertInternalError), &net.OpError{Op: "local error", Err: err} // TODO: err还是用alertInternalError?
	}
	if sigType == signaturePKCS1v15 || sigHash == crypto.SHA1 {
		return c.sendAlert2(alertIllegalParameter), errors.New("tls: client certificate used with invalid signature algorithm")
	}
	signed := signedMessage(sigHash, clientSignatureContext, hs.transcript)
	if err := verifyHandshakeSignature(sigType, c.peerCertificates[0].PublicKey,
		sigHash, signed, certVerify.signature); err != nil {
		return c.sendAlert2(alertDecryptError), errors.New("tls: invalid signature by the client certificate: " + err.Error())
	}

	hs.transcript.Write(certVerify.marshal())

	hs.stage = ReadClientFinished
	return hs.sendSessionTickets2()
}

func (hs *serverHandshakeStateTLS13) processClientFinished(msg any) ([]byte, error) {
	c := hs.c

	finished, ok := msg.(*finishedMsg)
	if !ok {
		return c.sendAlert2(alertUnexpectedMessage), unexpectedMessageError(finished, msg)
	}

	if !hmac.Equal(hs.clientFinished, finished.verifyData) {
		return c.sendAlert2(alertDecryptError), errors.New("tls: invalid client finished hash")
	}

	c.in.setTrafficSecret(hs.suite, hs.trafficSecret)
	hs.stage = HandshakeFinished
	atomic.StoreUint32(&c.handshakeStatus, 1)
	return nil, nil
}
func (hs *serverHandshakeStateTLS13) sendServerFinished2() ([]byte, error) {
	c := hs.c
	var buf bytes.Buffer

	finished := &finishedMsg{
		verifyData: hs.suite.finishedHash(c.out.trafficSecret, hs.transcript),
	}

	hs.transcript.Write(finished.marshal())
	if err := c.writeRecord2(&buf, recordTypeHandshake, finished.marshal()); err != nil {
		return buf.Bytes(), err
	}

	// Derive secrets that take context through the server Finished.

	hs.masterSecret = hs.suite.extract(nil,
		hs.suite.deriveSecret(hs.handshakeSecret, "derived", nil))

	hs.trafficSecret = hs.suite.deriveSecret(hs.masterSecret,
		clientApplicationTrafficLabel, hs.transcript)
	serverSecret := hs.suite.deriveSecret(hs.masterSecret,
		serverApplicationTrafficLabel, hs.transcript)
	c.out.setTrafficSecret(hs.suite, serverSecret)

	err := c.config.writeKeyLog(keyLogLabelClientTraffic, hs.clientHello.random, hs.trafficSecret)
	if err != nil {
		return c.sendAlert2(alertInternalError), err
	}
	err = c.config.writeKeyLog(keyLogLabelServerTraffic, hs.clientHello.random, serverSecret)
	if err != nil {
		return c.sendAlert2(alertInternalError), err
	}

	c.ekm = hs.suite.exportKeyingMaterial(hs.masterSecret, hs.transcript)

	// If we did not request client certificates, at this point we can
	// precompute the client finished and roll the transcript forward to send
	// session tickets in our first flight.
	if !hs.requestClientCert() {
		part, err := hs.sendSessionTickets2() //TODO
		if err != nil {
			return nil, err
		}
		if _, err := buf.Write(part); err != nil {
			return buf.Bytes(), err
		}
	}

	return buf.Bytes(), nil
}

func (hs *serverHandshakeStateTLS13) sendServerCertificate2() ([]byte, error) {
	c := hs.c

	// Only one of PSK and certificates are used at a time.
	if hs.usingPSK {
		return nil, nil
	}

	var buf bytes.Buffer

	if hs.requestClientCert() {
		// Request a client certificate
		certReq := new(certificateRequestMsgTLS13)
		certReq.ocspStapling = true
		certReq.scts = true
		certReq.supportedSignatureAlgorithms = supportedSignatureAlgorithms()
		if c.config.ClientCAs != nil {
			certReq.certificateAuthorities = c.config.ClientCAs.Subjects()
		}

		hs.transcript.Write(certReq.marshal())
		if err := c.writeRecord2(&buf, recordTypeHandshake, certReq.marshal()); err != nil {
			// MAYBUG: 可能会漏一个error
			return buf.Bytes(), err
		}
	}

	certMsg := new(certificateMsgTLS13)

	certMsg.certificate = *hs.cert
	certMsg.scts = hs.clientHello.scts && len(hs.cert.SignedCertificateTimestamps) > 0
	certMsg.ocspStapling = hs.clientHello.ocspStapling && len(hs.cert.OCSPStaple) > 0

	hs.transcript.Write(certMsg.marshal())
	if err := c.writeRecord2(&buf, recordTypeHandshake, certMsg.marshal()); err != nil {
		return buf.Bytes(), err
	}

	certVerifyMsg := new(certificateVerifyMsg)
	certVerifyMsg.hasSignatureAlgorithm = true
	certVerifyMsg.signatureAlgorithm = hs.sigAlg

	sigType, sigHash, err := typeAndHashFromSignatureScheme(hs.sigAlg)
	if err != nil {
		// MAYBUG 这个alert会不会丢
		return c.sendAlert2(alertInternalError), err
	}

	signed := signedMessage(sigHash, serverSignatureContext, hs.transcript)
	signOpts := crypto.SignerOpts(sigHash)
	if sigType == signatureRSAPSS {
		signOpts = &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: sigHash}
	}
	sig, err := hs.cert.PrivateKey.(crypto.Signer).Sign(c.config.rand(), signed, signOpts)
	if err != nil {
		public := hs.cert.PrivateKey.(crypto.Signer).Public()
		if rsaKey, ok := public.(*rsa.PublicKey); ok && sigType == signatureRSAPSS &&
			rsaKey.N.BitLen()/8 < sigHash.Size()*2+2 { // key too small for RSA-PSS
			return c.sendAlert2(alertHandshakeFailure), errors.New("tls: failed to sign handshake: " + err.Error())
		} else {
			return c.sendAlert2(alertInternalError), errors.New("tls: failed to sign handshake: " + err.Error())
		}
	}
	certVerifyMsg.signature = sig

	hs.transcript.Write(certVerifyMsg.marshal())

	if err := c.writeRecord2(&buf, recordTypeHandshake, certVerifyMsg.marshal()); err != nil {
		return buf.Bytes(), err
	}

	return buf.Bytes(), nil
}

func (hs *serverHandshakeStateTLS13) sendServerParameters2() ([]byte, error) {
	c := hs.c
	var buf bytes.Buffer

	hs.transcript.Write(hs.clientHello.marshal())
	hs.transcript.Write(hs.hello.marshal())

	err := hs.c.writeRecord2(&buf, recordTypeHandshake, hs.hello.marshal())
	if err != nil {
		return buf.Bytes(), err
	}

	part, err := hs.sendDummyChangeCipherSpec2()
	if err != nil {
		return part, err
	}
	if _, err := buf.Write(part); err != nil {
		return nil, err
	}

	earlySecret := hs.earlySecret
	if earlySecret == nil {
		earlySecret = hs.suite.extract(nil, nil)
	}
	hs.handshakeSecret = hs.suite.extract(hs.sharedKey,
		hs.suite.deriveSecret(earlySecret, "derived", nil))

	clientSecret := hs.suite.deriveSecret(hs.handshakeSecret,
		clientHandshakeTrafficLabel, hs.transcript)
	c.in.setTrafficSecret(hs.suite, clientSecret)
	serverSecret := hs.suite.deriveSecret(hs.handshakeSecret,
		serverHandshakeTrafficLabel, hs.transcript)
	c.out.setTrafficSecret(hs.suite, serverSecret)

	err = c.config.writeKeyLog(keyLogLabelClientHandshake, hs.clientHello.random, clientSecret)
	if err != nil {
		return c.sendAlert2(alertInternalError), err
	}
	err = c.config.writeKeyLog(keyLogLabelServerHandshake, hs.clientHello.random, serverSecret)
	if err != nil {
		return c.sendAlert2(alertInternalError), err
	}

	encryptedExtensions := new(encryptedExtensionsMsg)

	selectedProto, err := negotiateALPN(c.config.NextProtos, hs.clientHello.alpnProtocols)
	if err != nil {
		return c.sendAlert2(alertNoApplicationProtocol), err
	}
	encryptedExtensions.alpnProtocol = selectedProto
	c.clientProtocol = selectedProto

	hs.transcript.Write(encryptedExtensions.marshal())

	if err := c.writeRecord2(&buf, recordTypeHandshake, encryptedExtensions.marshal()); err != nil {
		return buf.Bytes(), err
	}

	return buf.Bytes(), nil
}

func (hs *serverHandshakeStateTLS13) sendDummyChangeCipherSpec2() ([]byte, error) {
	if hs.sentDummyCCS {
		return nil, nil
	}
	hs.sentDummyCCS = true
	return hs.c.marshalRecord(recordTypeChangeCipherSpec, []byte{1})
}

func (hs *serverHandshakeStateTLS13) pickCertificate2() ([]byte, error) {
	c := hs.c

	// Only one of PSK and certificates are used at a time.
	if hs.usingPSK {
		return nil, nil
	}

	// signature_algorithms is required in TLS 1.3. See RFC 8446, Section 4.2.3.
	if len(hs.clientHello.supportedSignatureAlgorithms) == 0 {
		return c.sendAlert2(alertMissingExtension), &net.OpError{Op: "local error", Err: alertMissingExtension}
	}

	certificate, err := c.config.getCertificate(clientHelloInfo(hs.ctx, c, hs.clientHello))
	if err != nil {
		if err == errNoCertificates {
			return c.sendAlert2(alertUnrecognizedName), err
		} else {
			return c.sendAlert2(alertInternalError), err
		}
	}
	hs.sigAlg, err = selectSignatureScheme(c.vers, certificate, hs.clientHello.supportedSignatureAlgorithms)
	if err != nil {
		// getCertificate returned a certificate that is unsupported or
		// incompatible with the client's signature algorithms.

		return c.sendAlert2(alertHandshakeFailure), err
	}
	hs.cert = certificate

	return nil, nil
}

func (hs *serverHandshakeStateTLS13) writeHelloRetryRequest2(selectedGroup CurveID) ([]byte, error) {
	var buf bytes.Buffer

	// The first ClientHello gets double-hashed into the transcript upon a
	// HelloRetryRequest. See RFC 8446, Section 4.4.1.
	hs.transcript.Write(hs.clientHello.marshal())
	chHash := hs.transcript.Sum(nil)
	hs.transcript.Reset()
	hs.transcript.Write([]byte{typeMessageHash, 0, 0, uint8(len(chHash))})
	hs.transcript.Write(chHash)

	helloRetryRequest := &serverHelloMsg{
		vers:              hs.hello.vers,
		random:            helloRetryRequestRandom,
		sessionId:         hs.hello.sessionId,
		cipherSuite:       hs.hello.cipherSuite,
		compressionMethod: hs.hello.compressionMethod,
		supportedVersion:  hs.hello.supportedVersion,
		selectedGroup:     selectedGroup,
	}

	hs.transcript.Write(helloRetryRequest.marshal())

	err := hs.c.writeRecord2(&buf, recordTypeHandshake, helloRetryRequest.marshal())
	if err != nil {
		return buf.Bytes(), err
	}

	part2, err := hs.sendDummyChangeCipherSpec2()
	if err != nil {
		return part2, err
	}
	if _, err := buf.Write(part2); err != nil {
		// MAYBUG: 后面会返回alertInternalError, 那前面的数据还关键吗?
		return hs.c.sendAlert2(alertInternalError), err
	}
	return buf.Bytes(), nil
}

func (hs *serverHandshakeStateTLS13) checkForResumption2() ([]byte, error) {
	c := hs.c

	if c.config.SessionTicketsDisabled {
		return nil, nil
	}

	modeOK := false
	for _, mode := range hs.clientHello.pskModes {
		if mode == pskModeDHE {
			modeOK = true
			break
		}
	}
	if !modeOK {
		return nil, nil
	}

	if len(hs.clientHello.pskIdentities) != len(hs.clientHello.pskBinders) {
		return c.sendAlert2(alertIllegalParameter), errors.New("tls: invalid or missing PSK binders")
	}
	if len(hs.clientHello.pskIdentities) == 0 {
		return nil, nil
	}

	for i, identity := range hs.clientHello.pskIdentities {
		if i >= maxClientPSKIdentities {
			break
		}

		plaintext, _ := c.decryptTicket(identity.label)
		if plaintext == nil {
			continue
		}
		sessionState := new(sessionStateTLS13)
		if ok := sessionState.unmarshal(plaintext); !ok {
			continue
		}

		createdAt := time.Unix(int64(sessionState.createdAt), 0)
		if c.config.time().Sub(createdAt) > maxSessionTicketLifetime {
			continue
		}

		// We don't check the obfuscated ticket age because it's affected by
		// clock skew and it's only a freshness signal useful for shrinking the
		// window for replay attacks, which don't affect us as we don't do 0-RTT.

		pskSuite := cipherSuiteTLS13ByID(sessionState.cipherSuite)
		if pskSuite == nil || pskSuite.hash != hs.suite.hash {
			continue
		}

		// PSK connections don't re-establish client certificates, but carry
		// them over in the session ticket. Ensure the presence of client certs
		// in the ticket is consistent with the configured requirements.
		sessionHasClientCerts := len(sessionState.certificate.Certificate) != 0
		needClientCerts := requiresClientCert(c.config.ClientAuth)
		if needClientCerts && !sessionHasClientCerts {
			continue
		}
		if sessionHasClientCerts && c.config.ClientAuth == NoClientCert {
			continue
		}

		psk := hs.suite.expandLabel(sessionState.resumptionSecret, "resumption",
			nil, hs.suite.hash.Size())
		hs.earlySecret = hs.suite.extract(psk, nil)
		binderKey := hs.suite.deriveSecret(hs.earlySecret, resumptionBinderLabel, nil)
		// Clone the transcript in case a HelloRetryRequest was recorded.
		transcript := cloneHash(hs.transcript, hs.suite.hash)
		if transcript == nil {
			return c.sendAlert2(alertInternalError), errors.New("tls: internal error: failed to clone hash")
		}
		transcript.Write(hs.clientHello.marshalWithoutBinders())
		pskBinder := hs.suite.finishedHash(binderKey, transcript)
		if !hmac.Equal(hs.clientHello.pskBinders[i], pskBinder) {
			return c.sendAlert2(alertDecryptError), errors.New("tls: invalid PSK binder")
		}

		c.didResume = true
		send, err := c.processCertsFromClient2(sessionState.certificate)
		if err != nil {
			return send, err
		}

		hs.hello.selectedIdentityPresent = true
		hs.hello.selectedIdentity = uint16(i)
		hs.usingPSK = true
		return nil, nil
	}

	return nil, nil
}

func (hs *serverHandshakeStateTLS13) handlePostHandshakeMessage2(msg any) (send []byte, err error) {
	c := hs.c

	if c.vers != VersionTLS13 {
		return c.handleRenegotiation2(msg)
	}

	c.retryCount++
	if c.retryCount > maxUselessRecords {
		return c.sendAlert2(alertUnexpectedMessage), c.in.setErrorLocked(errors.New("tls: too many non-advancing records"))
	}

	switch msg := msg.(type) {
	case *newSessionTicketMsgTLS13:
		return c.handleNewSessionTicket2(msg)
	case *keyUpdateMsg:
		return c.handleKeyUpdate2(msg)
	default:

		return c.sendAlert2(alertUnexpectedMessage), fmt.Errorf("tls: received unexpected handshake message of type %T", msg)
	}
}
