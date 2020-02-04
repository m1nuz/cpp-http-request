#include <http_request.hpp>

#include <iostream>

extern int main( int argc, char *argv[] ) {
    (void)argc;
    (void)argv;
    //constexpr char RequestURI[] = "http://postman-echo.com/get";
    constexpr char RequestURI[] = "http://httpbin.org/get";
    cpp_http::make_request( RequestURI, "GET", {}, {}, [=]( const cpp_http::Response &res ) {
        std::cout << RequestURI << " -> " << static_cast<int>( res._status ) << std::endl;
    } );
    return 0;
}
