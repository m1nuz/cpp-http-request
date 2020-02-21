#include <http_request.hpp>

#include <iostream>

#include <gtest/gtest.h>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

#define ENABLE_OUTPUT

#ifdef ENABLE_OUTPUT
static void print( const cpp_http::Response &res ) {
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

TEST( HttpsRequest_GET, Get_HttpBin ) {
    constexpr char RequestURI[] = "https://httpbin.org/get";

    cpp_http::make_request( RequestURI, "GET", {}, {}, [=]( const cpp_http::Response &res ) {
        EXPECT_TRUE( res );
        EXPECT_EQ( res._status, cpp_http::StatusCode::OK );
        EXPECT_EQ( res._version, "HTTP/1.1" );

        if (auto it = res._headers.find( "Content-Length" ); it != res._headers.end() ) {
            const auto size = std::stoi( it->second );
            EXPECT_GE( res._body.size(), size);
        }

        print( res );
    } );
}

TEST( HttpsRequest_GET, GetWithParams_HttpBin ) {
    constexpr char RequestURI[] = "https://httpbin.org/get";

    const auto in_args = std::unordered_map<std::string, std::string>{{"foo", "1"}, {"bar", "2"}};

    cpp_http::make_request( RequestURI, "GET", in_args, {}, [=]( const cpp_http::Response &res ) {
        EXPECT_EQ( res._status, cpp_http::StatusCode::OK );
        EXPECT_EQ( res._version, "HTTP/1.1" );

        if (auto it = res._headers.find( "Content-Length" ); it != res._headers.end() ) {
            const auto size = std::stoi( it->second );
            EXPECT_GE( res._body.size(), size);
        }

        auto j = json::parse( res._body.begin(), res._body.end() );
        if (j.find("args") != j.end()) {
            auto args = j["args"].get<std::unordered_map<std::string, std::string>>();

            EXPECT_EQ( in_args, args );
        }

        print( res );
    } );
}

TEST( HttpsRequest_GET, Get_Postman ) {
    constexpr char RequestURI[] = "https://postman-echo.com/get";

    cpp_http::make_request( RequestURI, "GET", {}, {}, [=]( const cpp_http::Response &res ) {
        EXPECT_EQ( res._status, cpp_http::StatusCode::OK );
        EXPECT_EQ( res._version, "HTTP/1.1" );

        print( res );
    } );
}

TEST( HttpsRequest_POST, Post_HttpBin ) {
    constexpr char RequestURI[] = "https://httpbin.org/post";

    cpp_http::make_request( RequestURI, "POST", {}, {}, [=]( const cpp_http::Response &res ) {
        EXPECT_EQ( res._status, cpp_http::StatusCode::OK );
        EXPECT_EQ( res._version, "HTTP/1.1" );

        if (auto it = res._headers.find( "Content-Length" ); it != res._headers.end() ) {
            const auto size = std::stoi( it->second );
            EXPECT_GE( res._body.size(), size);
        }

        print( res );
    } );
}

TEST( HttpsRequest_POST, PostForm_HttpBin ) {
    constexpr char RequestURI[] = "https://httpbin.org/post";
    const auto in_args = std::unordered_map<std::string, std::string>{{"foo", "1"}, {"bar", "2"}};

    cpp_http::make_request( RequestURI, "POST", in_args, {{"Content-Type", "application/x-www-form-urlencoded"}}, [=]( const cpp_http::Response &res ) {
        EXPECT_EQ( res._status, cpp_http::StatusCode::OK );
        EXPECT_EQ( res._version, "HTTP/1.1" );

        if (auto it = res._headers.find( "Content-Length" ); it != res._headers.end() ) {
            const auto size = std::stoi( it->second );
            EXPECT_GE( res._body.size(), size);
        }

        auto j = json::parse( res._body.begin(), res._body.end() );
        EXPECT_NE(j.find("form"), j.end());
        auto args = j["form"].get<std::unordered_map<std::string, std::string>>();
        EXPECT_EQ( in_args, args );

        print( res );
    } );
}

TEST( HttpsRequest_GET, Get_ipify_ipv6 ) {
    constexpr char RequestURI[] = "https://api6.ipify.org";

    cpp_http::make_request( RequestURI, "GET", {}, {}, [=]( const cpp_http::Response &res ) {
        EXPECT_EQ( res._status, cpp_http::StatusCode::OK );
        EXPECT_EQ( res._version, "HTTP/1.1" );

        print( res );
    } );
}

TEST( HttpsRequest_GET, Get_ipify_ipv6_json ) {
    constexpr char RequestURI[] = "https://api6.ipify.org";

    cpp_http::make_request( RequestURI, "GET", {{"format", "json"}}, {}, [=]( const cpp_http::Response &res ) {
        EXPECT_EQ( res._status, cpp_http::StatusCode::OK );
        EXPECT_EQ( res._version, "HTTP/1.1" );

        print( res );
    } );
}
