//
// A functional Windows TCP socket class with optional SSL support
// (C) 2023 _paging
//
#pragma once

#define USE_SSL // Comment this line to disable SSL support

#include <iostream>
#include <vector>
#include <mutex>

#include <winsock2.h>
#include <ws2tcpip.h>

#pragma comment(lib, "ws2_32.lib")

#ifdef USE_SSL
#include <openssl/tls1.h>
#include <openssl/ssl.h>
#endif

class TCPSocket
{
public:
	TCPSocket() = default;
	~TCPSocket() = default;

public:
	/// <summary>
	/// Create a new socket
	/// </summary>
	/// <param name="ip">IP address of the server</param>
	/// <param name="port">Port of the server</param>
	/// <returns>Pointer to the socket if successful, nullptr otherwise</returns>
	static TCPSocket* Create(const char* ip, int port);

public:
	/// <summary>
	/// Connect to a TCP server
	/// </summary>
	/// <param name="ip">IP address of the server</param>
	/// <param name="port">Port of the server</param>
	/// <returns>True if the connection was successful, false otherwise</returns>
	bool Connect(const char* ip, int port);

	/// <summary>
	/// Disconnect from the server
	/// </summary>
	void Disconnect();

	/// <summary>
	/// Send data to the server
	/// </summary>
	/// <typeparam name="T">Type of the data to send</typeparam>
	/// <param name="data">Data to send</param>
	/// <returns>Number of bytes sent</returns>
	template<typename T>
	SIZE_T Send(T data);

	/// <summary>
	/// Receive data from the server
	/// </summary>
	/// <typeparam name="T">Type of the data to receive</typeparam>
	/// <param name="data">Reference to the data to receive</param>
	/// <returns>Number of bytes received</returns>
	template<typename T>
	inline SIZE_T Recv(T& data);

	/// <summary>
	/// Send data to the server
	/// </summary>
	/// <param name="data">Reference to string to send</param>
	/// <returns>Number of bytes sent</returns>
	SIZE_T Send(std::string& data);

	/// <summary>
	/// Send data to the server
	/// </summary>
	/// <param name="data">Pointer to the data to send</param>
	/// <param name="size">Size of the data to send</param>
	/// <returns>Number of bytes sent</returns>
	SIZE_T Send(void* data, SIZE_T size);

	/// <summary>
	/// Receive data from the server
	/// </summary>
	/// <param name="data">Pointer to the buffer to store the data</param>
	/// <param name="size">Size of the buffer</param>
	/// <returns></returns>
	SIZE_T Recv(BYTE* data, SIZE_T size);

private:
	SOCKET m_Socket = INVALID_SOCKET;
#ifdef USE_SSL
	SSL* m_SSL = nullptr;
	SSL_CTX* m_CTX = nullptr;
#endif
	std::mutex m_SocketLock;

};

template<typename T>
inline SIZE_T TCPSocket::Send(T data)
{
	return SIZE_T();
}

template<typename T>
inline SIZE_T TCPSocket::Recv(T& data)
{
	return Recv((BYTE*) &data, sizeof(T));
}