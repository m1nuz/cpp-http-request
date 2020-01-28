#include <http_request.hpp>

#include <iostream>

extern int main(int argc, char* argv[]) {
    (void)argc;(void)argv;
    cpp_http::make_request( "http://httpbin.org/get", "GET", {}, {},  []( const bool success, const cpp_http::Response& res) {
        std::cout << success << std::endl;
    } );
    return 0;
}
