//#pragma once
// When including this you can enable either ERLCPP_C_MODE or ERLCPP_CPP_MODE

#if defined(ERLCPP_C_MODE)
    #define class class_
    #define export export_
    #define this this_
    #define new new_
    #undef ERLCPP_C_MODE
#endif

#if defined(ERLCPP_CPP_MODE)
    #undef class
    #undef export
    #undef this
    #undef new
    #undef ERLCPP_CPP_MODE
#endif
