#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <string.h>
#include <unistd.h>
#include <stdlib.h>

#include <iostream>
#include <string>


using namespace std;

class Sockaddr
{
public:
    Sockaddr(): m_socklen(0), m_sockaddr(NULL) {
        cout << "Sockaddr 构造" << endl;
    }
    ~Sockaddr() {
        m_socklen = 0;
        if(m_sockaddr) {
            free(m_sockaddr);
            m_sockaddr = NULL;
        }
        cout << "Sockaddr 析构" << endl;
    }
    int mkaddr(int family, const char *ip, unsigned short port) {
        if(AF_INET == family || PF_INET == family) {
            m_socklen = sizeof(struct sockaddr_in);
            m_sockaddr = (struct sockaddr *)calloc(1, m_socklen);
            struct sockaddr_in *addr = (struct sockaddr_in *)m_sockaddr;
            addr->sin_family = family;
            addr->sin_addr.s_addr = inet_addr(ip);
            addr->sin_port = htons(port);
        }
        else if(AF_INET6 == family || PF_INET6 == family) {
            m_socklen = sizeof(struct sockaddr_in6);
            m_sockaddr = (struct sockaddr *)calloc(1, m_socklen);
            struct sockaddr_in6 *addr = (struct sockaddr_in6 *)m_sockaddr;
            addr->sin6_family = family;
            addr->sin6_port = htons(port);
        }
        else return -1; return 0;
    }
    int mkaddr(int family, const char * path) {
        if(AF_LOCAL == family || AF_UNIX == family ||
           PF_LOCAL == family || PF_UNIX == family) {
            m_socklen = sizeof(struct sockaddr_un);
            m_sockaddr = (struct sockaddr *)calloc(1, m_socklen);
            struct sockaddr_un *addr = (struct sockaddr_un *)m_sockaddr;
            addr->sun_family = family;
            strncpy(addr->sun_path, path, sizeof(addr->sun_path) - 1);
        }
        else return -1; return 0;
    }

    Sockaddr &operator =(const Sockaddr &addr) {
        m_socklen = addr.m_socklen;
        m_sockaddr = (struct sockaddr *)calloc(1, m_socklen);
        memcpy(m_sockaddr, addr.m_sockaddr, m_socklen);
        return *this;
    }

    socklen_t m_socklen;
    struct sockaddr * m_sockaddr;
};

class Socket
{
public:
    Socket(int domain, int type, int protocol);
    ~Socket();

    int bind(const Sockaddr &addr);
    int listen(int n);
    int connect(const Sockaddr &addr);
    int accept(Socket &sock);
    // int shutdown( int __fd, int __how );
    // int send( int __fd, const void *__buf, size_t __n, int __flags );
    // int recv( int __fd, void *__buf, size_t __n, int __flags );
    // int getsockopt( int __fd, int __level, int __optname, void * __optval, socklen_t * __optlen );
    // int setsockopt( int __fd, int __level, int __optname, const void *__optval, socklen_t __optlen );
    // int sendto( int __fd, const void *__buf, size_t __n, int __flags, const struct sockaddr *__addr, socklen_t __addr_len );
    // int recvfrom( int __fd, void *__restrict __buf, size_t __n, int __flags, struct sockaddr *__restrict __addr, socklen_t *__restrict __addr_len );
private:
    int m_sockfd;

    short m_domain;
    int m_type;
    int m_protocol;

    Sockaddr m_Sockaddr;
};

Socket::Socket(int domain, int type, int protocol):
    m_domain(domain), m_type(type), m_protocol(protocol)
{
    cout << "Socket 构造" << endl;
    m_sockfd = ::socket(domain, type, protocol);
}
Socket::~Socket()
{
    close(m_sockfd);
    cout << "Socket 析构" << endl;
}
int
Socket::bind(const Sockaddr &addr)
{
    m_Sockaddr = addr;
    return ::bind(m_sockfd, addr.m_sockaddr , addr.m_socklen);
}
int
Socket::listen(int n)
{
    return ::listen(m_sockfd, n);
}
int
Socket::connect(const Sockaddr &addr)
{
    return ::connect(m_sockfd, addr.m_sockaddr, addr.m_socklen);
}
int
Socket::accept( Socket &sock )
{
    int sockfd = ::accept(m_sockfd, sock.m_Sockaddr.m_sockaddr, &sock.m_Sockaddr.m_socklen );
    sock.m_sockfd = sockfd;
    if(sockfd < 0) return -1; return 0;
}


int main()
{
    Socket sock(AF_INET, SOCK_STREAM, 0);
    Sockaddr addr;
    addr.mkaddr(AF_INET, "192.168.133.223", 88);
    cout << "连接结果" << sock.connect(addr) << endl;

    cout << "inet = " << sizeof(struct sockaddr_in) << "\n"
         << "unix = " << sizeof(struct sockaddr_un) << "\n"
         << "inet6 = " << sizeof(struct sockaddr_in6) << "\n"
         << "addr = " << sizeof(struct sockaddr) << endl;

    return 0;
}
