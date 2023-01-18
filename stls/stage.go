package stls

const (
	_ = iota

	/* server */
	/*
		外层状态, 用来决策走哪个版本的tls
		ReadClientHello: 准备接收client的第一个包, 初始状态
		PostReadClientHello: 收到非1.3版本的client-hello, 之后使用这一套握手流程, 所有的数据包转到serverHandshake中
		PostReadClientHelloTLS13: 收到1.3版本的client-hello, 之后使用这一套握手流程, 所有数据包转到serverHandshakeStateTLS13
	*/
	ReadClientHello
	PostReadClientHello
	PostReadClientHelloTLS13

	/*
		内部最开始的状态ProcessClientHello
		必须先处理client-hello
		可能直接到PostProcessClientHello, 也可能到ReadSecondClientHello

		一些情况需要收第二个client-hello-msg, 准备接收, 也就是对应ReadSecondClientHello

		最终到PostProcessClientHello
	*/
	ProcessClientHello
	ReadSecondClientHello
	/*
		PostProcessClientHello, 表示client-hello已经处理
		这时该发送的数据已经生成并返回.

		同时可以开始处理client发来的整数和finish
	*/
	PostProcessClientHello

	/*
		准备接收客户端证书, 如果需要
	*/
	ReadClientCertificateVerify
	/*
		准备接收client-finish
	*/
	ReadClientFinished

	/*
		非1.3存在在变种两个
	*/
	ReadClientFinished1
	ReadClientFinished2
	/*
		正常握手流程已经跑完了, 不过还是可能进行 re-renegotiation
	*/
	HandshakeFinished

	/* 非1.3的太啰唆了*/
	// 收到client-hello之后, 部分情况需要读取client证书
	// 也可能读取到其他msg, 所以这里只能用 Post 标识
	/*
		PostWriteServerHelloDone 标识 server-helllo已经发送
		在这之前可能还已经发送了 cer-request
	*/
	PostWriteServerHelloDone

	/*
		处理客户端证书之后
	*/
	PostProcessClientCert

	/*
		设置masrer-secret之后
	*/
	PostParseMasterSecret
)
