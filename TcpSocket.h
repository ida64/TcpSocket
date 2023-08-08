/*
* A functional Windows TCP socket class with optional SSL support
* (C) 2023 _paging
* All rights reserved, subject to the license terms.
*/
#pragma once

#include <iostream>
#include <unordered_map>
#include <mutex>

#include <winsock2.h>
#include <ws2tcpip.h>

#pragma comment(lib, "ws2_32.lib")

#define SSL_ENABLED // Comment this line to disable SSL support
#define SSL_CERT_FILE "cert.pem" // Path to the certificate file
#define SSL_KEY_FILE "key.pem" // Path to the key file

#ifdef SSL_ENABLED
#include <openssl/tls1.h>
#include <openssl/ssl.h>
#endif

/// <summary>
/// A functional Windows TCP socket class with optional SSL support
/// </summary>
class TCPSocket
{
public:
	TCPSocket() = default;
	~TCPSocket() = default;

public:
	/// <summary>
	/// Create a new socket
	/// </summary>
	/// <returns>Pointer to the socket if successful, nullptr otherwise</returns>
	static TCPSocket* Create();

public:
	/// <summary>
	/// Connect to a TCP server
	/// </summary>
	/// <param name="ip">IP address of the server</param>
	/// <param name="port">Port of the server</param>
	/// <returns>True if the connection was successful, false otherwise</returns>
	bool Connect(const char* ip, int port);

	/// <summary>
	/// Bind the socket to a local address and listen for incoming connections
	/// </summary>
	/// <param name="ip">IP address to bind to</param>
	/// <param name="port">Port to bind to</param>
	/// <returns>True if the binding was successful, false otherwise</returns>
	bool Bind(const char* ip, int port);

	/// <summary>
	/// Accept an incoming connection
	/// </summary>
	SOCKET Accept();

	/// <summary>
	/// Disconnect from the server
	/// </summary>
	void Disconnect();

	//
	// (Client->Server) Data Transmission Functions
	//

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

	//
	// (Server->Client) Data Transmission Functions
	//

	/// <summary>
	/// Send data to a client
	/// </summary>
	/// <typeparam name="T">Type of the data to send</typeparam>
	/// <param name="socket">Socket of the client</param>
	/// <param name="data">Data to send</param>
	/// <returns>Number of bytes sent</returns>
	template<typename T>
	SIZE_T Send(SOCKET socket, T data);

	/// <summary>
	/// Receive data from a client
	/// </summary>
	/// <typeparam name="T">Type of the data to receive</typeparam>
	/// <param name="socket">Socket of the client</param>
	/// <param name="data">Reference to the data to receive</param>
	/// <returns></returns>
	template<typename T>
	inline SIZE_T Recv(SOCKET socket, T& data);

	/// <summary>
	/// Send data to a client
	/// </summary>
	/// <param name="socket">Socket of the client</param>
	/// <param name="data">Reference to string to send</param>
	/// <returns></returns>
	SIZE_T Send(SOCKET socket, std::string& data);

	/// <summary>
	/// Send data to a client
	/// </summary>
	/// <param name="socket">Socket of the client</param>
	/// <param name="data">Pointer to the data to send</param>
	/// <param name="size">Size of the data to send</param>
	/// <returns>Number of bytes sent</returns>
	SIZE_T Send(SOCKET socket, BYTE* data, SIZE_T size);

	/// <summary>
	/// Receive data from a client
	/// </summary>
	/// <param name="socket">Socket of the client</param>
	/// <param name="data">Pointer to the buffer to store the data</param>
	/// <param name="size">Size of the buffer</param>
	/// <returns>Number of bytes received</returns>
	SIZE_T Recv(SOCKET socket, BYTE* data, SIZE_T size);

private:
	SOCKET m_Socket = INVALID_SOCKET;
#ifdef SSL_ENABLED
	std::unordered_map<SOCKET, SSL*> m_SocketToSSLMap;
	SSL* m_SSL = nullptr;
	SSL_CTX* m_CTX = nullptr;
#endif
	std::mutex m_SocketLock;

};

template<typename T>
inline SIZE_T TCPSocket::Send(T data)
{
	return Send((BYTE*) &data, sizeof(T));
}

template<typename T>
inline SIZE_T TCPSocket::Recv(T& data)
{
	return Recv((BYTE*) &data, sizeof(T));
}

template<typename T>
inline SIZE_T TCPSocket::Send(SOCKET socket, T data)
{
	return Send(socket, (BYTE*) &data, sizeof(T));
}

template<typename T>
inline SIZE_T TCPSocket::Recv(SOCKET socket, T& data)
{
	return Recv(socket, (BYTE*) &data, sizeof(T));
}
