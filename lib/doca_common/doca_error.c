#include "doca_error.h"

const char *doca_get_error_string(doca_error_t error){
    switch (error)
    {
    case DOCA_ERROR_UNKNOWN:
        return "DOCA_ERROR_UNKNOWN";
        break;
    case DOCA_ERROR_NOT_PERMITTED:
        return "DOCA_ERROR_NOT_PERMITTED";
        break;
    case DOCA_ERROR_IN_USE:
        return "DOCA_ERROR_IN_USE";
        break;
    case DOCA_ERROR_NOT_SUPPORTED:
        return "DOCA_ERROR_NOT_SUPPORTED";
        break;
    case DOCA_ERROR_AGAIN:
        return "DOCA_ERROR_AGAIN";
        break;
    case DOCA_ERROR_INVALID_VALUE:
        return "DOCA_ERROR_INVALID_VALUE";
        break;
    case DOCA_ERROR_NO_MEMORY:
        return "DOCA_ERROR_NO_MEMORY";
        break;
    case DOCA_ERROR_INITIALIZATION:
        return "DOCA_ERROR_INITIALIZATION";
        break;
    case DOCA_ERROR_TIME_OUT:
        return "DOCA_ERROR_TIME_OUT";
        break;
    case DOCA_ERROR_SHUTDOWN:
        return "DOCA_ERROR_SHUTDOWN";
        break;
    case DOCA_ERROR_CONNECTION_RESET:
        return "DOCA_ERROR_CONNECTION_RESET";
        break;
    case DOCA_ERROR_CONNECTION_ABORTED:
        return "DOCA_ERROR_CONNECTION_ABORTED";
        break;
    case DOCA_ERROR_CONNECTION_INPROGRESS:
        return "DOCA_ERROR_CONNECTION_INPROGRESS";
        break;
    case DOCA_ERROR_NOT_CONNECTED:
        return "DOCA_ERROR_NOT_CONNECTED";
        break;
    case DOCA_ERROR_NO_LOCK:
        return "DOCA_ERROR_NO_LOCK";
        break;
    case DOCA_ERROR_NOT_FOUND:
        return "DOCA_ERROR_NOT_FOUND";
        break;
    case DOCA_ERROR_IO_FAILED:
        return "DOCA_ERROR_IO_FAILED";
        break;
    case DOCA_ERROR_BAD_STATE:
        return "DOCA_ERROR_BAD_STATE";
        break;
    case DOCA_ERROR_UNSUPPORTED_VERSION:
        return "DOCA_ERROR_UNSUPPORTED_VERSION";
        break;
    case DOCA_ERROR_OPERATING_SYSTEM:
        return "DOCA_ERROR_OPERATING_SYSTEM";
        break;
    case DOCA_ERROR_DRIVER:
        return "DOCA_ERROR_DRIVER";
        break;

    default:
        break;
    }
}