package stls

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"sync/atomic"
)

func (hs *serverHandshakeState) handshake2(msg any) (got, send []byte, err error) {
	c := hs.c
	switch hs.stage {
	case ProcessClientHello:
		send, err = hs.processClientHello2()
	case PostWriteServerHelloDone:
		if c.config.ClientAuth >= RequestClientCert {
			send, err = hs.postWriteServerHelloDonePart1(msg)
		} else {
			send, err = hs.postWriteServerHelloDonePart2(msg)
		}
	case PostProcessClientCert:
		send, err = hs.postWriteServerHelloDonePart2(msg)
	case PostParseMasterSecret:
		send, err = hs.postMasterSecretWhenHavePeerCert(msg)
	case ReadClientFinished1:
		send, err = hs.processClientFinished1(msg, nil)
		if err != nil {
			hs.endHandshake()
		}
	case ReadClientFinished2:
		send, err = hs.processClientFinished2(msg, c.clientFinished[:])
	case HandshakeFinished:
		send, err = hs.handlePostHandshakeMessage2(msg)
	}

	return
}

func (hs *serverHandshakeState) handlePostHandshakeMessage2(msg any) (send []byte, err error) {
	c := hs.c

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

func (hs *serverHandshakeState) processClientHello2() (send []byte, err error) {
	if send, err = hs.processClientHelloPart1(); err != nil {
		return
	}

	c := hs.c

	var buf bytes.Buffer
	var part []byte

	// For an overview of TLS handshaking, see RFC 5246, Section 7.3.
	c.buffering = true
	if hs.checkForResumption() {
		// The client has included a session ticket and so we do an abbreviated handshake.
		part, err = hs.doResumptionPart1()
		if err != nil {
			return part, err
		}
		hs.stage = ReadClientFinished1
	} else {
		// The client didn't include a session ticket, or it wasn't
		// valid so we do a full handshake.
		if part, err = hs.pickCipherSuite2(); err != nil {
			return part, err
		}
		if _, err = buf.Write(part); err != nil {
			return c.sendAlert2(alertInternalError), err
		}

		if part, err = hs.writeServerHello2(); err != nil {
			return part, err
		}
		if _, err = buf.Write(part); err != nil {
			return c.sendAlert2(alertInternalError), err
		}
		hs.stage = PostWriteServerHelloDone
	}

	// c.ekm = ekmFromMasterSecret(c.vers, hs.suite, hs.masterSecret, hs.clientHello.random, hs.hello.random)
	// atomic.StoreUint32(&c.handshakeStatus, 1)

	return buf.Bytes(), nil
}

func (hs *serverHandshakeState) processClientHelloPart1() (send []byte, err error) {
	c := hs.c

	hs.hello = new(serverHelloMsg)
	hs.hello.vers = c.vers

	foundCompression := false
	// We only support null compression, so check that the client offered it.
	for _, compression := range hs.clientHello.compressionMethods {
		if compression == compressionNone {
			foundCompression = true
			break
		}
	}

	if !foundCompression {
		return c.sendAlert2(alertHandshakeFailure), errors.New("tls: client does not support uncompressed connections")
	}

	hs.hello.random = make([]byte, 32)
	serverRandom := hs.hello.random
	// Downgrade protection canaries. See RFC 8446, Section 4.1.3.
	maxVers := c.config.maxSupportedVersion(roleServer)
	if maxVers >= VersionTLS12 && c.vers < maxVers || testingOnlyForceDowngradeCanary {
		if c.vers == VersionTLS12 {
			copy(serverRandom[24:], downgradeCanaryTLS12)
		} else {
			copy(serverRandom[24:], downgradeCanaryTLS11)
		}
		serverRandom = serverRandom[:24]
	}
	_, err = io.ReadFull(c.config.rand(), serverRandom)
	if err != nil {
		return c.sendAlert2(alertInternalError), err
	}

	if len(hs.clientHello.secureRenegotiation) != 0 {
		return c.sendAlert2(alertHandshakeFailure), errors.New("tls: initial handshake had non-empty renegotiation extension")
	}

	hs.hello.secureRenegotiationSupported = hs.clientHello.secureRenegotiationSupported
	hs.hello.compressionMethod = compressionNone
	if len(hs.clientHello.serverName) > 0 {
		c.serverName = hs.clientHello.serverName
	}

	selectedProto, err := negotiateALPN(c.config.NextProtos, hs.clientHello.alpnProtocols)
	if err != nil {
		return c.sendAlert2(alertNoApplicationProtocol), err
	}
	hs.hello.alpnProtocol = selectedProto
	c.clientProtocol = selectedProto

	hs.cert, err = c.config.getCertificate(clientHelloInfo(hs.ctx, c, hs.clientHello))
	if err != nil {
		if err == errNoCertificates {
			return c.sendAlert2(alertUnrecognizedName), err
		} else {
			return c.sendAlert2(alertInternalError), err
		}
	}
	if hs.clientHello.scts {
		hs.hello.scts = hs.cert.SignedCertificateTimestamps
	}

	hs.ecdheOk = supportsECDHE(c.config, hs.clientHello.supportedCurves, hs.clientHello.supportedPoints)

	if hs.ecdheOk && len(hs.clientHello.supportedPoints) > 0 {
		// Although omitting the ec_point_formats extension is permitted, some
		// old OpenSSL version will refuse to handshake if not present.
		//
		// Per RFC 4492, section 5.1.2, implementations MUST support the
		// uncompressed point format. See golang.org/issue/31943.
		hs.hello.supportedPoints = []uint8{pointFormatUncompressed}
	}

	if priv, ok := hs.cert.PrivateKey.(crypto.Signer); ok {
		switch priv.Public().(type) {
		case *ecdsa.PublicKey:
			hs.ecSignOk = true
		case ed25519.PublicKey:
			hs.ecSignOk = true
		case *rsa.PublicKey:
			hs.rsaSignOk = true
		default:

			return c.sendAlert2(alertInternalError), fmt.Errorf("tls: unsupported signing key type (%T)", priv.Public())
		}
	}
	if priv, ok := hs.cert.PrivateKey.(crypto.Decrypter); ok {
		switch priv.Public().(type) {
		case *rsa.PublicKey:
			hs.rsaDecryptOk = true
		default:

			return c.sendAlert2(alertInternalError), fmt.Errorf("tls: unsupported decryption key type (%T)", priv.Public())
		}
	}

	return nil, nil
}

func (hs *serverHandshakeState) doResumptionPart1() (send []byte, err error) {
	c := hs.c

	var part []byte
	var buf bytes.Buffer

	// The client has included a session ticket and so we do an abbreviated handshake.
	c.didResume = true
	if part, err = hs.doResumeHandshake2(); err != nil {
		return part, err
	}
	if _, err = buf.Write(part); err != nil {
		return c.sendAlert2(alertInternalError), err
	}
	if err := hs.establishKeys(); err != nil {
		return c.sendAlert2(alertInternalError), err
	}
	if part, err = hs.sendSessionTicket2(); err != nil {
		return part, err
	}
	if part, err = hs.sendFinished2(c.serverFinished[:]); err != nil {
		return part, err
	}
	c.clientFinishedIsFirst = false
	return buf.Bytes(), nil
}

func (hs *serverHandshakeState) doResumeHandshake2() (send []byte, err error) {
	c := hs.c
	var buf bytes.Buffer

	hs.hello.cipherSuite = hs.suite.id
	c.cipherSuite = hs.suite.id
	// We echo the client's session ID in the ServerHello to let it know
	// that we're doing a resumption.
	hs.hello.sessionId = hs.clientHello.sessionId
	hs.hello.ticketSupported = hs.sessionState.usedOldKey
	hs.finishedHash = newFinishedHash(c.vers, hs.suite)
	hs.finishedHash.discardHandshakeBuffer()
	hs.finishedHash.Write(hs.clientHello.marshal())
	hs.finishedHash.Write(hs.hello.marshal())
	if err := c.writeRecord2(&buf, recordTypeHandshake, hs.hello.marshal()); err != nil {
		return buf.Bytes(), err
	}

	if send, err = c.processCertsFromClient2(Certificate{
		Certificate: hs.sessionState.certificates,
	}); err != nil {
		return
	}

	if c.config.VerifyConnection != nil {
		if err := c.config.VerifyConnection(c.connectionStateLocked()); err != nil {
			return c.sendAlert2(alertBadCertificate), err
		}
	}

	hs.masterSecret = hs.sessionState.masterSecret

	return
}

func (hs *serverHandshakeState) processClientFinished1(msg any, out []byte) (send []byte, err error) {
	c := hs.c

	clientFinished, ok := msg.(*finishedMsg)
	if !ok {
		return c.sendAlert2(alertUnexpectedMessage), unexpectedMessageError(clientFinished, msg)
	}

	verify := hs.finishedHash.clientSum(hs.masterSecret)
	if len(verify) != len(clientFinished.verifyData) ||
		subtle.ConstantTimeCompare(verify, clientFinished.verifyData) != 1 {
		return c.sendAlert2(alertHandshakeFailure), errors.New("tls: client's Finished message is incorrect")
	}

	hs.finishedHash.Write(clientFinished.marshal())
	copy(out, verify)
	return nil, nil
}

func (hs *serverHandshakeState) processClientFinished2(msg any, out []byte) (send []byte, err error) {
	send, err = hs.processClientFinished1(msg, out)
	if err != nil {
		return
	}
	hs.c.clientFinishedIsFirst = true
	hs.c.buffering = true

	var buf bytes.Buffer
	var part []byte

	if part, err = hs.sendSessionTicket2(); err != nil {
		return part, err
	}
	if _, err = buf.Write(part); err != nil {
		return hs.c.sendAlert2(alertInternalError), err
	}
	if part, err = hs.sendFinished2(nil); err != nil {
		return part, err
	}
	if _, err = buf.Write(part); err != nil {
		return hs.c.sendAlert2(alertInternalError), err
	}

	hs.endHandshake()
	return buf.Bytes(), nil
}

func (hs *serverHandshakeState) endHandshake() {
	hs.c.ekm = ekmFromMasterSecret(hs.c.vers, hs.suite, hs.masterSecret, hs.clientHello.random, hs.hello.random)
	atomic.StoreUint32(&hs.c.handshakeStatus, 1)
	hs.stage = HandshakeFinished
}

func (hs *serverHandshakeState) sendSessionTicket2() (send []byte, err error) {
	// ticketSupported is set in a resumption handshake if the
	// ticket from the client was encrypted with an old session
	// ticket key and thus a refreshed ticket should be sent.
	if !hs.hello.ticketSupported {
		return nil, nil
	}

	c := hs.c
	m := new(newSessionTicketMsg)

	createdAt := uint64(c.config.time().Unix())
	if hs.sessionState != nil {
		// If this is re-wrapping an old key, then keep
		// the original time it was created.
		createdAt = hs.sessionState.createdAt
	}

	var certsFromClient [][]byte
	for _, cert := range c.peerCertificates {
		certsFromClient = append(certsFromClient, cert.Raw)
	}
	state := sessionState{
		vers:         c.vers,
		cipherSuite:  hs.suite.id,
		createdAt:    createdAt,
		masterSecret: hs.masterSecret,
		certificates: certsFromClient,
	}
	m.ticket, err = c.encryptTicket(state.marshal())
	if err != nil {
		return nil, err
	}

	hs.finishedHash.Write(m.marshal())

	return c.marshalRecord(recordTypeHandshake, m.marshal())
}

func (hs *serverHandshakeState) sendFinished2(out []byte) (send []byte, err error) {
	c := hs.c
	var buf bytes.Buffer

	if err := c.writeRecord2(&buf, recordTypeChangeCipherSpec, []byte{1}); err != nil {
		return buf.Bytes(), err
	}

	finished := new(finishedMsg)
	finished.verifyData = hs.finishedHash.serverSum(hs.masterSecret)
	hs.finishedHash.Write(finished.marshal())
	if err := c.writeRecord2(&buf, recordTypeHandshake, finished.marshal()); err != nil {
		return buf.Bytes(), err
	}

	copy(out, finished.verifyData) // ??

	return buf.Bytes(), nil
}
func (hs *serverHandshakeState) pickCipherSuite2() (send []byte, err error) {
	c := hs.c

	preferenceOrder := cipherSuitesPreferenceOrder
	if !hasAESGCMHardwareSupport || !aesgcmPreferred(hs.clientHello.cipherSuites) {
		preferenceOrder = cipherSuitesPreferenceOrderNoAES
	}

	configCipherSuites := c.config.cipherSuites()
	preferenceList := make([]uint16, 0, len(configCipherSuites))
	for _, suiteID := range preferenceOrder {
		for _, id := range configCipherSuites {
			if id == suiteID {
				preferenceList = append(preferenceList, id)
				break
			}
		}
	}

	hs.suite = selectCipherSuite(preferenceList, hs.clientHello.cipherSuites, hs.cipherSuiteOk)
	if hs.suite == nil {
		return c.sendAlert2(alertHandshakeFailure), errors.New("tls: no cipher suite supported by both client and server")
	}
	c.cipherSuite = hs.suite.id

	for _, id := range hs.clientHello.cipherSuites {
		if id == TLS_FALLBACK_SCSV {
			// The client is doing a fallback connection. See RFC 7507.
			if hs.clientHello.vers < c.config.maxSupportedVersion(roleServer) {
				return c.sendAlert2(alertInappropriateFallback), errors.New("tls: client using inappropriate protocol fallback")
			}
			break
		}
	}

	return
}

func (hs *serverHandshakeState) writeServerHello2() (send []byte, err error) {
	c := hs.c
	var buf bytes.Buffer

	if hs.clientHello.ocspStapling && len(hs.cert.OCSPStaple) > 0 {
		hs.hello.ocspStapling = true
	}

	hs.hello.ticketSupported = hs.clientHello.ticketSupported && !c.config.SessionTicketsDisabled
	hs.hello.cipherSuite = hs.suite.id

	hs.finishedHash = newFinishedHash(hs.c.vers, hs.suite)
	if c.config.ClientAuth == NoClientCert {
		// No need to keep a full record of the handshake if client
		// certificates won't be used.
		hs.finishedHash.discardHandshakeBuffer()
	}
	hs.finishedHash.Write(hs.clientHello.marshal())
	hs.finishedHash.Write(hs.hello.marshal())
	if err := c.writeRecord2(&buf, recordTypeHandshake, hs.hello.marshal()); err != nil {
		return buf.Bytes(), err
	}

	certMsg := new(certificateMsg)
	certMsg.certificates = hs.cert.Certificate
	hs.finishedHash.Write(certMsg.marshal())
	if err := c.writeRecord2(&buf, recordTypeHandshake, certMsg.marshal()); err != nil {
		return buf.Bytes(), err
	}

	if hs.hello.ocspStapling {
		certStatus := new(certificateStatusMsg)
		certStatus.response = hs.cert.OCSPStaple
		hs.finishedHash.Write(certStatus.marshal())
		if err = c.writeRecord2(&buf, recordTypeHandshake, certStatus.marshal()); err != nil {
			return buf.Bytes(), nil
		}
	}

	hs.preKeyAgreement = hs.suite.ka(c.vers)
	skx, err := hs.preKeyAgreement.generateServerKeyExchange(c.config, hs.cert, hs.clientHello, hs.hello)
	if err != nil {
		buf.Write(c.sendAlert2(alertHandshakeFailure))
		return buf.Bytes(), nil
	}
	if skx != nil {
		hs.finishedHash.Write(skx.marshal())
		if err := c.writeRecord2(&buf, recordTypeHandshake, skx.marshal()); err != nil {
			return buf.Bytes(), nil
		}
	}

	var certReq *certificateRequestMsg
	if c.config.ClientAuth >= RequestClientCert {
		// Request a client certificate
		certReq = new(certificateRequestMsg)
		certReq.certificateTypes = []byte{
			byte(certTypeRSASign),
			byte(certTypeECDSASign),
		}
		if c.vers >= VersionTLS12 {
			certReq.hasSignatureAlgorithm = true
			certReq.supportedSignatureAlgorithms = supportedSignatureAlgorithms()
		}

		// An empty list of certificateAuthorities signals to
		// the client that it may send any certificate in response
		// to our request. When we know the CAs we trust, then
		// we can send them down, so that the client can choose
		// an appropriate certificate to give to us.
		if c.config.ClientCAs != nil {
			certReq.certificateAuthorities = c.config.ClientCAs.Subjects()
		}
		hs.finishedHash.Write(certReq.marshal())
		if err := c.writeRecord2(&buf, recordTypeHandshake, certReq.marshal()); err != nil {
			return buf.Bytes(), nil
		}
	}
	hs.preCertReq = certReq

	helloDone := new(serverHelloDoneMsg)
	hs.finishedHash.Write(helloDone.marshal())
	if err := c.writeRecord2(&buf, recordTypeHandshake, helloDone.marshal()); err != nil {
		return buf.Bytes(), nil
	}
	return buf.Bytes(), nil
}
func (hs *serverHandshakeState) postWriteServerHelloDonePart1(msg any) (send []byte, err error) {
	c := hs.c

	certMsg, ok := msg.(*certificateMsg)
	if !ok {
		return c.sendAlert2(alertUnexpectedMessage), unexpectedMessageError(certMsg, msg)
	}
	hs.finishedHash.Write(certMsg.marshal())

	if send, err := c.processCertsFromClient2(Certificate{
		Certificate: certMsg.certificates,
	}); err != nil {
		return send, err
	}
	if len(certMsg.certificates) != 0 {
		hs.prePubKey = c.peerCertificates[0].PublicKey
	}

	hs.stage = PostProcessClientCert
	return
}

func (hs *serverHandshakeState) postWriteServerHelloDonePart2(msg any) (send []byte, err error) {
	c := hs.c
	if c.config.VerifyConnection != nil {
		if err := c.config.VerifyConnection(c.connectionStateLocked()); err != nil {
			return c.sendAlert2(alertBadCertificate), err
		}
	}

	// Get client key exchange
	ckx, ok := msg.(*clientKeyExchangeMsg)
	if !ok {
		return c.sendAlert2(alertUnexpectedMessage), unexpectedMessageError(ckx, msg)
	}
	hs.finishedHash.Write(ckx.marshal())

	preMasterSecret, err := hs.preKeyAgreement.processClientKeyExchange(c.config, hs.cert, ckx, c.vers)
	if err != nil {
		return c.sendAlert2(alertHandshakeFailure), err
	}
	hs.masterSecret = masterFromPreMasterSecret(c.vers, hs.suite, preMasterSecret, hs.clientHello.random, hs.hello.random)
	if err := c.config.writeKeyLog(keyLogLabelTLS12, hs.clientHello.random, hs.masterSecret); err != nil {
		return c.sendAlert2(alertInternalError), err
	}
	if len(c.peerCertificates) > 0 {
		hs.stage = PostParseMasterSecret
		return
	}
	return hs.beforeClientFinish()
}

func (hs *serverHandshakeState) postMasterSecretWhenHavePeerCert(msg any) (send []byte, err error) {
	c := hs.c
	pub := hs.prePubKey
	certReq := hs.preCertReq

	certVerify, ok := msg.(*certificateVerifyMsg)
	if !ok {

		return c.sendAlert2(alertUnexpectedMessage), unexpectedMessageError(certVerify, msg)
	}

	var sigType uint8
	var sigHash crypto.Hash
	if c.vers >= VersionTLS12 {
		if !isSupportedSignatureAlgorithm(certVerify.signatureAlgorithm, certReq.supportedSignatureAlgorithms) {

			return c.sendAlert2(alertIllegalParameter), errors.New("tls: client certificate used with invalid signature algorithm")
		}
		sigType, sigHash, err = typeAndHashFromSignatureScheme(certVerify.signatureAlgorithm)
		if err != nil {
			return c.sendAlert2(alertInternalError), err
		}
	} else {
		sigType, sigHash, err = legacyTypeAndHashFromPublicKey(pub)
		if err != nil {

			return c.sendAlert2(alertIllegalParameter), err
		}
	}

	signed := hs.finishedHash.hashForClientCertificate(sigType, sigHash, hs.masterSecret)
	if err := verifyHandshakeSignature(sigType, pub, sigHash, signed, certVerify.signature); err != nil {

		return c.sendAlert2(alertDecryptError), errors.New("tls: invalid signature by the client certificate: " + err.Error())
	}

	hs.finishedHash.Write(certVerify.marshal())

	return hs.beforeClientFinish()
}

func (hs *serverHandshakeState) beforeClientFinish() (send []byte, err error) {
	hs.finishedHash.discardHandshakeBuffer()

	if err := hs.establishKeys(); err != nil {
		return hs.c.sendAlert2(alertInternalError), err
	}
	hs.stage = ReadClientFinished2
	hs.c.expectChangeCipherSpec = 1
	return nil, nil
}
