cmake_minimum_required(VERSION 3.5)

project(network_discovery)

set(CMAKE_CXX_STANDARD 17)

find_package(libtins REQUIRED)

add_executable(${PROJECT_NAME}
    main.cpp
)

target_link_libraries(${PROJECT_NAME}
    tins
)
