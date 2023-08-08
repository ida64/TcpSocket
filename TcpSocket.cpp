#include "TcpSocket.h"

TCPSocket* TCPSocket::Create(const char* ip, int port)
{
	TCPSocket* socket = new TCPSocket();
	if(socket->Connect(ip, port) == false)
	{
		delete socket;
		return nullptr;
	}
	return socket;
}

bool TCPSocket::Connect(const char* ip, int port)
{
	WSADATA wsaData{};
	if(WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
	{
		return false;
	}

	m_Socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if(m_Socket == INVALID_SOCKET)
	{
		return false;
	}

	sockaddr_in addr{};
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	inet_pton(AF_INET, ip, &addr.sin_addr);

	if(connect(m_Socket, (sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR)
	{
		return false;
	}

#ifdef USE_SSL
	SSL_library_init();
	OpenSSL_add_all_algorithms();
	SSL_load_error_strings();

	m_CTX = SSL_CTX_new(TLS_client_method());
	if(m_CTX == nullptr)
	{
		return false;
	}

	m_SSL = SSL_new(m_CTX);
	if(m_SSL == nullptr)
	{
		return false;
	}

	if(SSL_set_fd(m_SSL, (int)m_Socket) == 0)
	{
		return false;
	}

	if(SSL_connect(m_SSL) != 1)
	{
		return false;
	}
#endif
	return true;
}

void TCPSocket::Disconnect()
{
#ifdef USE_SSL
	SSL_shutdown(m_SSL);
	SSL_free(m_SSL);
#else
	closesocket(m_Socket);
#endif
	WSACleanup();
}

SIZE_T TCPSocket::Send(std::string& data)
{
	return Send(reinterpret_cast<BYTE*>(data.data()), data.size());
}

SIZE_T TCPSocket::Send(void* data, SIZE_T size)
{
	std::lock_guard<std::mutex> lock(m_SocketLock);
	SIZE_T sent = 0;
	while(sent < size)
	{
#ifdef USE_SSL
		int ret = SSL_write(m_SSL, reinterpret_cast<char*>(data) + sent, size - sent);
#else
		int ret = send(m_Socket, reinterpret_cast<char*>(data) + sent, size - sent, 0);
#endif
		if(ret <= 0)
		{
			return false;
		}
		sent += ret;
	}
	return sent;
}

SIZE_T TCPSocket::Recv(BYTE* data, SIZE_T size)
{
	std::lock_guard<std::mutex> lock(m_SocketLock);
	SIZE_T received = 0;
	while(received < size)
	{
#ifdef USE_SSL
		int ret = SSL_read(m_SSL, reinterpret_cast<char*>(data) + received, size - received);
#else
		int ret = recv(m_Socket, reinterpret_cast<char*>(data) + received, size - received, 0);
#endif
		if(ret <= 0)
		{
			return false;
		}
		received += ret;
	}
	return received;
}
