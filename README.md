# TcpSocket
A functional Windows TCP socket class with optional SSL support

## Configuration
```cpp
#define SSL_ENABLED // Comment this line to disable SSL support
#define SSL_CERT_FILE "cert.pem" // Path to the certificate file
#define SSL_KEY_FILE "key.pem" // Path to the key file
```

## Client
```cpp
	// Create a TCPSocket object
	TCPSocket* Socket = TCPSocket::Create();

	// Connect to the server
	if (!Socket->Connect("127.0.0.1", 8880))
	{
		...
	}

	// Send a message to the server
	char Data[] = "Hello, world!";
	SIZE_T Sent = Socket->Send(Data, sizeof(Data));
	if (!Sent)
	{
		...
	}

	Socket->Disconnect();
```
## Server
```cpp
	TCPSocket* socket = TCPSocket::Create();
	if (!socket->Bind("127.0.0.1", 8880))
	{
		...
	}

	SOCKET client = socket->Accept();
	if (client == INVALID_SOCKET)
	{
		...
	}

	BYTE buffer[14];
	memset(buffer, 0, sizeof(buffer));
	if (socket->Recv(client, buffer, sizeof(buffer)) == 0)
	{
		...
	}

	printf("Received: %s\n", buffer);

	socket->Disconnect();
```
