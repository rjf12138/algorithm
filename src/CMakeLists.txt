project(algorithm)

target_include_directories(algorithm PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)

target_sources(algorithm PRIVATE
		${CMAKE_CURRENT_SOURCE_DIR}/src/./base64.cc
		${CMAKE_CURRENT_SOURCE_DIR}/src/./sha1.cc)
