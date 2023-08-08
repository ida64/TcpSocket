#include "TcpSocket.h"

TCPSocket* TCPSocket::Create()
{
	WSADATA wsaData{};
	if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
	{
		return nullptr;
	}
	return new TCPSocket();
}

bool TCPSocket::Connect(const char* ip, int port)
{
	if(m_Socket != INVALID_SOCKET)
	{
		return false;
	}

	m_Socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (m_Socket == INVALID_SOCKET)
	{
		return false;
	}

	sockaddr_in addr{};
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	inet_pton(AF_INET, ip, &addr.sin_addr);

	if (connect(m_Socket, (sockaddr*) &addr, sizeof(addr)) == SOCKET_ERROR)
	{
		return false;
	}

#ifdef SSL_ENABLED
	SSL_library_init();
	OpenSSL_add_all_algorithms();
	SSL_load_error_strings();

	m_CTX = SSL_CTX_new(TLS_client_method());
	if (m_CTX == nullptr)
	{
		return false;
	}

	m_SSL = SSL_new(m_CTX);
	if (m_SSL == nullptr)
	{
		return false;
	}

	if (SSL_set_fd(m_SSL, (int) m_Socket) == 0)
	{
		return false;
	}

	if (SSL_connect(m_SSL) != 1)
	{
		return false;
	}

	m_SocketToSSLMap[m_Socket] = m_SSL;
#endif
	return true;
}

void TCPSocket::Disconnect()
{

#ifdef SSL_ENABLED
	//
	// I'm not sure if OpenSSL frees these since they have internal ref counts..?
	//

	SSL_CTX_free(m_CTX);
	for (auto& pair : m_SocketToSSLMap)
	{
		SSL_shutdown(pair.second);
		SSL_free(pair.second);
	}

	m_SocketToSSLMap.clear();

	m_CTX = nullptr;
	m_SSL = nullptr;
#else
	closesocket(m_Socket);
#endif
	m_Socket = INVALID_SOCKET;
}

bool TCPSocket::Bind(const char* ip, int port)
{
	m_Socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (m_Socket == INVALID_SOCKET)
	{
		return false;
	}

	sockaddr_in addr{};
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	inet_pton(AF_INET, ip, &addr.sin_addr);

#ifdef SSL_ENABLED
	SSL_library_init();
	OpenSSL_add_all_algorithms();
	SSL_load_error_strings();

	m_CTX = SSL_CTX_new(TLS_server_method());
	if (m_CTX == nullptr)
	{
		return false;
	}

	if (SSL_CTX_use_certificate_file(m_CTX, SSL_CERT_FILE, SSL_FILETYPE_PEM) <= 0)
	{
		return false;
	}

	if (SSL_CTX_use_PrivateKey_file(m_CTX, SSL_KEY_FILE, SSL_FILETYPE_PEM) <= 0)
	{
		return false;
	}

	if (SSL_CTX_check_private_key(m_CTX) != 1)
	{
		return false;
	}
#endif

	if (bind(m_Socket, (sockaddr*) &addr, sizeof(addr)) == SOCKET_ERROR)
	{
		return false;
	}
	if (listen(m_Socket, SOMAXCONN) == SOCKET_ERROR)
	{
		return false;
	}
	return true;
}

SOCKET TCPSocket::Accept()
{
	SOCKET client = accept(m_Socket, nullptr, nullptr);
	if (client == INVALID_SOCKET)
	{
		return INVALID_SOCKET;
	}

#ifdef SSL_ENABLED
	SSL* ssl = SSL_new(m_CTX);
	if (ssl == nullptr)
	{
		return INVALID_SOCKET;
	}

	if (SSL_set_fd(ssl, (int) client) == 0)
	{
		return INVALID_SOCKET;
	}

	if (SSL_accept(ssl) != 1)
	{
		return INVALID_SOCKET;
	}

	m_SocketToSSLMap[client] = ssl;
#endif
	return client;
}

SIZE_T TCPSocket::Send(std::string& buffer)
{
	return Send(reinterpret_cast<BYTE*>(buffer.data()), buffer.size());
}

SIZE_T TCPSocket::Send(void* data, SIZE_T size)
{
	std::lock_guard<std::mutex> lock(m_SocketLock);
	return Send(m_Socket, reinterpret_cast<BYTE*>(data), size);
}

SIZE_T TCPSocket::Recv(BYTE* data, SIZE_T size)
{
	std::lock_guard<std::mutex> lock(m_SocketLock);
	return Recv(m_Socket, data, size);
}

SIZE_T TCPSocket::Send(SOCKET socket, std::string& buffer)
{
	return Send(socket, reinterpret_cast<BYTE*>(buffer.data()), buffer.size());
}

SIZE_T TCPSocket::Send(SOCKET socket, BYTE* data, SIZE_T size)
{
#ifdef SSL_ENABLED
	//
	// Find the SSL object associated with the socket
	//

	auto iter = m_SocketToSSLMap.find(socket);
	if (iter == m_SocketToSSLMap.end())
	{
		return -1;
	}

	SSL* ssl = iter->second;
#endif
	SIZE_T sent = 0;
	while (sent < size)
	{
#ifdef SSL_ENABLED
		int ret = SSL_write(ssl, reinterpret_cast<char*>(data) + sent, size - sent);
#else
		int ret = send(socket, reinterpret_cast<char*>(data) + sent, size - sent, 0);
#endif
		if (ret <= 0)
		{
			//
			// If the SSL connection was closed, remove the socket from the map
			//

#ifdef SSL_ENABLED
			int err = SSL_get_error(ssl, ret);
			if (err == SSL_ERROR_ZERO_RETURN)
			{
				m_SocketToSSLMap.erase(socket);
			}
#endif
			return ret;
		}
		sent += ret;
	}
	return sent;
}

SIZE_T TCPSocket::Recv(SOCKET socket, BYTE* data, SIZE_T size)
{
#ifdef SSL_ENABLED
	//
	// Find the SSL object associated with the socket
	//

	auto iter = m_SocketToSSLMap.find(socket);
	if (iter == m_SocketToSSLMap.end())
	{
		return -1;
	}

	SSL* ssl = iter->second;
#endif
	SIZE_T received = 0;
	while (received < size)
	{
#ifdef SSL_ENABLED
		int ret = SSL_read(ssl, reinterpret_cast<char*>(data) + received, size - received);
#else
		int ret = recv(socket, reinterpret_cast<char*>(data) + received, size - received, 0);
#endif
		if (ret <= 0)
		{
			//
			// If the SSL connection was closed, remove the socket from the map
			//

#ifdef SSL_ENABLED
			int err = SSL_get_error(ssl, ret);
			if (err == SSL_ERROR_ZERO_RETURN)
			{
				m_SocketToSSLMap.erase(socket);
			}
#endif
			return ret;
		}
		received += ret;
	}
	return received;
}
