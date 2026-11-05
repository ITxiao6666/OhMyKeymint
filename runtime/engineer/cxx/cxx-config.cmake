# The pinned prefab runtime and module providers are imported by the parent.
if(NOT TARGET cxx::cxx)
    message(FATAL_ERROR "OMK libcxx target is missing")
endif()
