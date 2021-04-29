#pragma once

#include "glog/logging.h"

enum class CfgErr {
    NONE,
    NO_REG,
    BAD_READ,
    OTHER
};

template <typename T>
class CfgRes {
  public:
    CfgRes() :
        m_val(CfgErr::NONE),
        is_error(true) {};

    explicit CfgRes(T val) :
        m_val(val),
        is_error(false) {};

    explicit CfgRes(CfgErr err) :
        m_val(err),
        is_error(true) {};

    T operator *() const {
        CHECK(!is_error) << "Attempted get() on error results";
        return this->m_val.success;
    }
    explicit operator bool() const {
        return !this->is_error;
    }

    CfgErr get_err() const {
        return m_val.error;
    }

  private:
    bool is_error;
    union val {
        explicit val(T success) : success(success) {};
        explicit val(CfgErr err) : error(err) {};

        T success;
        CfgErr error;
    } m_val;

};
