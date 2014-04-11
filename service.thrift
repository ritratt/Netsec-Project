service RPCClientServer
{
   string sendCert(),
   void receiveReq(1:string a),
   string receiveCACert()
}

service NodeChatter
{
	void verify(1:string a),
}
