#include <http_request.hpp>

#include <iostream>

extern int main( int argc, char *argv[] ) {
    (void)argc;
    (void)argv;
    //constexpr char RequestURI[] = "http://postman-echo.com/get";
    //constexpr char RequestURI[] = "http://postman-echo.com/stream/5";
    constexpr char RequestURI[] = "http://httpbin.org/stream-bytes/1000";
    //constexpr char RequestURI[] = "http://httpbin.org/get";
    //constexpr char RequestURI[] = "http://httpbin.org/range/1000";
    cpp_http::make_request( RequestURI, "GET", {}, {}, [=]( const cpp_http::Response &res ) {
        std::cout << res._version << " " << (int)res._status << '\n';

        for (auto& [k, v] : res._headers) {
            std::cout << k << ": " << v << '\n';
        }

        for ( auto ch : res._body ) {
            std::cout << static_cast<char>( ch );
        }
        std::cout << std::endl;

        std::cout << RequestURI << " -> " << static_cast<int>( res._status ) << std::endl;
    } );
    return 0;
}
