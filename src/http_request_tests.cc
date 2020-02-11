#include <http_request.hpp>

#include <iostream>

#include <gtest/gtest.h>

//#define ENABLE_OUTPUT

#ifdef ENABLE_OUTPUT
void print( const cpp_http::Response &res ) {
    std::cout << res._version << " " << static_cast<int>(res._status) << '\n';

    for ( auto &[k, v] : res._headers ) {
        std::cout << k << ": " << v << '\n';
    }

    for ( auto ch : res._body ) {
        std::cout << static_cast<char>( ch );
    }
    std::cout << std::endl;
}
#else
void print( const cpp_http::Response& ) {
}
#endif

TEST( HttpRequest_GET, Get_HttpBin ) {
    constexpr char RequestURI[] = "http://httpbin.org/get";

    cpp_http::make_request( RequestURI, "GET", {}, {}, [=]( const cpp_http::Response &res ) {
        EXPECT_EQ( res._status, cpp_http::StatusCode::OK );
        EXPECT_EQ( res._version, "HTTP/1.1" );

        if (auto it = res._headers.find( "Content-Length" ); it != res._headers.end() ) {
            const auto size = std::stoi( it->second );
            EXPECT_GE( res._body.size(), size);
        }

        print( res );
    } );
}

TEST( HttpRequest_GET, GetBytesStream_HttpBin ) {
    constexpr char RequestURI[] = "http://httpbin.org/stream-bytes/1000";

    cpp_http::make_request( RequestURI, "GET", {}, {}, [=]( const cpp_http::Response &res ) {
        EXPECT_EQ( res._status, cpp_http::StatusCode::OK );
        EXPECT_EQ( res._version, "HTTP/1.1" );

        auto it = res._headers.find( "Transfer-Encoding" );
        EXPECT_NE( it, res._headers.end() );

        if ( it != res._headers.end() ) {
            EXPECT_EQ( it->second, "chunked" );
        }

        EXPECT_GE( res._body.size(), 1000);

        print( res );
    } );
}

TEST( HttpRequest_GET, GetRange_HttpBin) {
    constexpr char RequestURI[] = "http://httpbin.org/range/1000";

    cpp_http::make_request( RequestURI, "GET", {}, {}, [=]( const cpp_http::Response &res ) {
        EXPECT_EQ( res._status, cpp_http::StatusCode::OK );
        EXPECT_EQ( res._version, "HTTP/1.1" );

        auto it = res._headers.find( "Content-Length" );
        EXPECT_NE( it, res._headers.end() );
        if ( it != res._headers.end() ) {
            const auto size = std::stoi( it->second );
            EXPECT_GE( res._body.size(), size);
        }

        print( res );
    } );
}

TEST( HttpRequest_GET, Get_Postman ) {
    constexpr char RequestURI[] = "http://postman-echo.com/get";

    cpp_http::make_request( RequestURI, "GET", {}, {}, [=]( const cpp_http::Response &res ) {
        EXPECT_EQ( res._status, cpp_http::StatusCode::OK );
        EXPECT_EQ( res._version, "HTTP/1.1" );

        print( res );
    } );
}

TEST( HttpRequest_GET, GetStream_Postman ) {
    constexpr char RequestURI[] = "http://postman-echo.com/stream/5";

    cpp_http::make_request( RequestURI, "GET", {}, {}, [=]( const cpp_http::Response &res ) {
        EXPECT_EQ( res._status, cpp_http::StatusCode::OK );
        EXPECT_EQ( res._version, "HTTP/1.1" );
        print( res );
    } );
}


