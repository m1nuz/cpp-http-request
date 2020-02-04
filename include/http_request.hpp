#pragma once

#include <cstdint>
#include <functional>
#include <regex>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

#include <iostream>

#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

namespace cpp_http
{
enum class StatusCode
{
    UNKNOWN = 0,
    CONTINUE = 100,
    SWITCHINGPROTOCOLS = 101,
    PROCESSING = 102,
    EARLYHINTS = 103,

    OK = 200,
    CREATED = 201,
    ACCEPTED = 202,
    NONAUTHORITATIVEINFORMATION = 203,
    NOCONTENT = 204,
    RESETCONTENT = 205,
    PARTIALCONTENT = 206,
    MULTISTATUS = 207,
    ALREADYREPORTED = 208,
    IMUSED = 226,

    MULTIPLECHOICES = 300,
    MOVEDPERMANENTLY = 301,
    FOUND = 302,
    SEEOTHER = 303,
    NOTMODIFIED = 304,
    USEPROXY = 305,
    TEMPORARYREDIRECT = 307,
    PERMANENTREDIRECT = 308,

    BADREQUEST = 400,
    UNAUTHORIZED = 401,
    PAYMENTREQUIRED = 402,
    FORBIDDEN = 403,
    NOTFOUND = 404,
    METHODNOTALLOWED = 405,
    NOTACCEPTABLE = 406,
    PROXYAUTHENTICATIONREQUIRED = 407,
    REQUESTTIMEOUT = 408,
    CONFLICT = 409,
    GONE = 410,
    LENGTHREQUIRED = 411,
    PRECONDITIONFAILED = 412,
    PAYLOADTOOLARGE = 413,
    URITOOLONG = 414,
    UNSUPPORTEDMEDIATYPE = 415,
    RANGENOTSATISFIABLE = 416,
    EXPECTATIONFAILED = 417,
    IMATEAPOT = 418,
    MISDIRECTEDREQUEST = 421,
    UNPROCESSABLEENTITY = 422,
    LOCKED = 423,
    FAILEDDEPENDENCY = 424,
    TOOEARLY = 425,
    UPGRADEREQUIRED = 426,
    PRECONDITIONREQUIRED = 428,
    TOOMANYREQUESTS = 429,
    REQUESTHEADERFIELDSTOOLARGE = 431,
    UNAVAILABLEFORLEGALREASONS = 451,

    INTERNALSERVERERROR = 500,
    NOTIMPLEMENTED = 501,
    BADGATEWAY = 502,
    SERVICEUNAVAILABLE = 503,
    GATEWAYTIMEOUT = 504,
    HTTPVERSIONNOTSUPPORTED = 505,
    VARIANTALSONEGOTIATES = 506,
    INSUFFICIENTSTORAGE = 507,
    LOOPDETECTED = 508,
    NOTEXTENDED = 510,
    NETWORKAUTHENTICATIONREQUIRED = 511
};

// using Headers = std::vector< std::string >;
using Headers = std::unordered_map< std::string, std::string >;
using Parameters = std::unordered_map< std::string, std::string >;

struct Request final
{
    std::string scheme;
    std::string domain;
    std::string port;
    std::string path;
};

struct Response final
{
    std::string _version;
    StatusCode _status = StatusCode::UNKNOWN;
    Headers _headers;
    std::vector< uint8_t > _body;
};

constexpr char DEFAULT_HTTP_PORT[] = "80";

using ResponseHandler = std::function< void( const bool, const Response& res ) >;

namespace detail
{
inline std::string
url_encode( std::string_view str )
{
    constexpr char hex_chars[ 16 ]
            = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'};

    std::string result;

    for ( auto i = str.begin( ); i != str.end( ); ++i )
    {
        const uint8_t cp = *i & 0xFF;

        if ( ( cp >= 0x30 && cp <= 0x39 ) ||  // 0-9
             ( cp >= 0x41 && cp <= 0x5A )
             ||  // A-Z
             ( cp >= 0x61 && cp <= 0x7A )
             ||  // a-z
             cp == 0x2D
             || cp == 0x2E
             || cp == 0x5F )  // - . _
            result += static_cast< char >( cp );
        else if ( cp <= 0x7F )  // length = 1
            result += std::string( "%" ) + hex_chars[ ( *i & 0xF0 ) >> 4 ] + hex_chars[ *i & 0x0F ];
        else if ( ( cp >> 5 ) == 0x06 )  // length = 2
        {
            result += std::string( "%" ) + hex_chars[ ( *i & 0xF0 ) >> 4 ] + hex_chars[ *i & 0x0F ];
            if ( ++i == str.end( ) )
                break;
            result += std::string( "%" ) + hex_chars[ ( *i & 0xF0 ) >> 4 ] + hex_chars[ *i & 0x0F ];
        }
        else if ( ( cp >> 4 ) == 0x0E )  // length = 3
        {
            result += std::string( "%" ) + hex_chars[ ( *i & 0xF0 ) >> 4 ] + hex_chars[ *i & 0x0F ];
            if ( ++i == str.end( ) )
                break;
            result += std::string( "%" ) + hex_chars[ ( *i & 0xF0 ) >> 4 ] + hex_chars[ *i & 0x0F ];
            if ( ++i == str.end( ) )
                break;
            result += std::string( "%" ) + hex_chars[ ( *i & 0xF0 ) >> 4 ] + hex_chars[ *i & 0x0F ];
        }
        else if ( ( cp >> 3 ) == 0x1E )  // length = 4
        {
            result += std::string( "%" ) + hex_chars[ ( *i & 0xF0 ) >> 4 ] + hex_chars[ *i & 0x0F ];
            if ( ++i == str.end( ) )
                break;
            result += std::string( "%" ) + hex_chars[ ( *i & 0xF0 ) >> 4 ] + hex_chars[ *i & 0x0F ];
            if ( ++i == str.end( ) )
                break;
            result += std::string( "%" ) + hex_chars[ ( *i & 0xF0 ) >> 4 ] + hex_chars[ *i & 0x0F ];
            if ( ++i == str.end( ) )
                break;
            result += std::string( "%" ) + hex_chars[ ( *i & 0xF0 ) >> 4 ] + hex_chars[ *i & 0x0F ];
        }
    }

    return result;
}

auto
split_url( const std::string_view url ) noexcept
        -> std::tuple< std::string, std::string, std::string, std::string >
{
    std::string scheme, domain, path, port;

    const auto scheme_end_pos = url.find( "://" );
    if ( scheme_end_pos != std::string::npos )
    {
        scheme = url.substr( 0, scheme_end_pos );
        path = url.substr( scheme_end_pos + 3 );
    }
    else
    {
        scheme = "http";
        path = url;
    }

    const auto fragment_pos = path.find( '#' );
    const auto path_pos = path.find( '/' );
    if ( fragment_pos != std::string::npos )
    {
        path.resize( fragment_pos );
    }
    if ( path_pos != std::string::npos )
    {
        domain = path.substr( 0, path_pos );
        path = path.substr( path_pos );
    }
    else
    {
        domain = path;
        path = "/";
    }

    const auto port_pos = domain.find( ':' );
    if ( port_pos != std::string::npos )
    {
        port = domain.substr( port_pos + 1 );
        domain.resize( port_pos );
    }
    else
    {
        port = DEFAULT_HTTP_PORT;
    }

    return {scheme, domain, path, port};
}

auto
make_body( const Parameters& parameters )
{
    std::string body;
    auto first = true;

    for ( const auto& parameter : parameters )
    {
        if ( !first )
            body += "&";
        first = false;

        body += url_encode( parameter.first ) + "=" + url_encode( parameter.second );
    }

    return body;
}

auto
read_with_timeout( const int sock, const time_t sec, const time_t usec ) noexcept
{
    fd_set fds;
    FD_ZERO( &fds );
    FD_SET( sock, &fds );

    timeval tv;
    tv.tv_sec = static_cast< long >( sec );
    tv.tv_usec = static_cast< long >( usec );

    return select( static_cast< int >( sock + 1 ), &fds, nullptr, nullptr, &tv );
}

auto
is_readable( const int sock ) noexcept
{
    return read_with_timeout( sock, 5, 0 ) > 0;
}

struct ByteStream
{
    ByteStream( ) = default;

    ByteStream( const size_t initial_reserved_size )
        : _position{0}
    {
        _buffer.reserve( initial_reserved_size );
    }

    void
    append( std::string_view s )
    {
        _buffer.insert( _buffer.end( ), s.begin( ), s.end( ) );
    }

    auto
    is_crlf( ) const
    {
        constexpr char crlf[] = {'\r', '\n'};
        return memcmp( &_buffer[ _position ], crlf, sizeof crlf ) == 0;
    }

    auto
    is_empty( )
    {
        return _buffer.size( ) == _position;
    }

    auto
    get_line( )
    {
        if ( _buffer.empty( ) )
            return std::string{};

        for ( size_t i = _position; i < _buffer.size( ); i++ )
        {
            if ( _buffer[ i ] == '\n' )
            {
                auto s = std::string{reinterpret_cast< const char* >( &_buffer[ _position ] ),
                                     i + 1 - _position};
                _position = i + 1;
                return s;
            }
        }

        return std::string{reinterpret_cast< const char* >( &_buffer[ _position ] ),
                           _buffer.size( )};
    }

    size_t _position = 0;
    std::vector< uint8_t > _buffer;
};

auto
has_header( const Response& res, std::string_view key )
{
    return res._headers.find( key.data( ) ) != res._headers.end( );
}

auto
read_response_line( std::string_view line, Response& res )
{
    const static std::regex re( "(HTTP/1\\.[01]) (\\d+?) .*\r\n" );

    std::cmatch m;
    if ( std::regex_match( line.begin( ), line.end( ), m, re ) )
    {
        res._version = std::string( m[ 1 ] );
        res._status = static_cast< StatusCode >( std::stoi( std::string( m[ 2 ] ) ) );

        return true;
    }

    return false;
}

auto
read_headers( ByteStream& bs, Headers& headers )
{
    while ( true )
    {
        if ( bs.is_crlf( ) && !bs.is_empty( ) )
            break;

        auto line = bs.get_line( );
        std::string_view sv = line;

        static const std::regex re( "((.+?):[\t ]*(.+)).*\r\n" );

        std::cmatch m;
        if ( std::regex_match( sv.begin( ), sv.end( ), m, re ) )
        {
            auto key = std::string( m[ 2 ] );
            auto val = std::string( m[ 3 ] );
            headers.emplace( key, val );
        }
    }

    return true;
}

auto
read_content_with_lenght( ByteStream& bs )
{
}

auto
read_content_without_lenght( ByteStream& bs )
{
}

auto
read_conetent( ByteStream& bs, Response& res )
{
    if ( has_header( res, "Content-Length" ) )
    {
        read_content_with_lenght( bs );
    }
    else
    {
        read_content_without_lenght( bs );
    }
}

auto
set_nonblocking( const int sock, const bool nonblocking )
{
    const auto flags = fcntl( sock, F_GETFL, 0 );
    fcntl( sock, F_SETFL, nonblocking ? ( flags | O_NONBLOCK ) : ( flags & ( ~O_NONBLOCK ) ) );
}

}  // namespace detail

// template <typename HttpMethod>
auto
make_request( const std::string_view url,
              const std::string_view method,
              const Parameters& parameters,
              const Headers& headers,
              ResponseHandler handler )
{
    Request req;
    Response res;

    const auto[ scheme, domain, path, port ] = detail::split_url( url );
    if ( scheme != "http" )
    {
        // "Unsupported scheme: " + scheme
        handler( false, res );
        return;
    }

    req.scheme = scheme;
    req.domain = domain;
    req.path = path;
    req.port = port;

    addrinfo hints = {};
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    addrinfo* info;
    if ( getaddrinfo( domain.c_str( ), port.c_str( ), &hints, &info ) != 0 )
    {
        // "Failed to get address info of " + domain
        handler( false, res );
        return;
    }

    const auto sock = socket( AF_INET, SOCK_STREAM, IPPROTO_TCP );

    if (::connect( sock, info->ai_addr, static_cast< socklen_t >( info->ai_addrlen ) ) < 0 )
    {
        close( sock );
        handler( false, res );
        return;
    }

    detail::set_nonblocking( sock, true );

    // Prepare request data
    const auto body = detail::make_body( parameters );

    std::string request_data = std::string{method} + " " + path + " HTTP/1.1\r\n";
    for ( const auto & [ k, v ] : headers )
        request_data += k + " " + v + "\r\n";

    request_data += "Host: " + domain + "\r\n";
    request_data += "Content-Length: " + std::to_string( body.size( ) ) + "\r\n";

    request_data += "\r\n";
    request_data += body;

    constexpr int flags = MSG_NOSIGNAL;

    auto remaining = static_cast< ssize_t >( request_data.size( ) );
    ssize_t sent = 0;

    // Send request
    while ( remaining > 0 )
    {
        const auto size = send(
                sock, request_data.data( ) + sent, static_cast< size_t >( remaining ), flags );

        if ( size < 0 )
        {
            // "Failed to send data to " + domain + ":" + port
            break;
        }

        remaining -= size;
        sent += size;
    }

    constexpr size_t READ_BUFFER_SIZE = 4096;

    char temp_buffer[ READ_BUFFER_SIZE ] = {};
    detail::ByteStream response_data;

    // Read response
    while ( detail::is_readable( sock ) )
    {
        const auto size = recv( sock, temp_buffer, sizeof( temp_buffer ), flags );

        if ( size < 0 )
        {
            // "Failed to read data from " + domain + ":" + port
            close( sock );
            return;
        }
        if ( size == 0 )
        {
            // Disconnected
            break;
        }

        response_data.append( std::string_view{&temp_buffer[ 0 ], static_cast< size_t >( size )} );

        auto line = response_data.get_line( );

        if ( !detail::read_response_line( line, res )
             || !detail::read_headers( response_data, res._headers ) )
        {
            break;
        }

        detail::read_conetent( response_data, res );
    }

    std::cout << res._version << " " << (int)res._status << std::endl;

    close( sock );

    handler( true, res );
}

}  // namespace cpp_http
