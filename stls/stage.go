package stls

const (
	PreHandshake = iota

	/* client */
	WriteClientHello
	ReadHelloRetryRequest
	PostReadHelloRetryRequest
	PostReadHelloRetryRequestTLS13
	ProcessHelloRetryRequest
	WriteSecondClientHello
	ReadServerHello
	ProcessServerHello
	ReadEncryptedExtensions
	ReadCertificateRequest
	ReadServerCertificate
	ProcessServerCertificate
	ReadServerCertificateVerify
	ReadServerFinished
	WriteClientCertificate
	WriteClientCertificateVerify
	WriteClientFinished

	/* server */
	/*
		外层状态, 用来决策走哪个版本的tls
	*/
	ReadClientHello
	PostReadClientHello
	PostReadClientHelloTLS13

	/*
		内部最开始的状态ProcessClientHello
		必须先处理client-hello
		可能直接到PostProcessClientHello, 也可能到ReadSecondClientHello

		ReadSecondClientHello之后还要再收到一个msg, 再处理一次, 最终到PostProcessClientHello
	*/
	ProcessClientHello
	ReadSecondClientHello //
	ProcessSecondClientHello
	/*
		PostProcessClientHello, 表示client-hello已经处理
		这时该发送的数据已经生成并返回.

		同时可以开始处理client发来的整数和finish
	*/
	PostProcessClientHello

	ReadClientCertificateVerify
	ReadClientFinished

	/* both */
	HandshakeFinished
	UndefinedHandshakeState
)
