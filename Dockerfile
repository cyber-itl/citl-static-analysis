FROM alpine as build

RUN mkdir /src/ && \
    apk update && \
    apk add openssl-dev build-base git clang cmake make python3 linux-headers bash openssl fortify-headers

COPY . /src/citl-static-analysis/

RUN mkdir /src/citl-static-analysis/build/ && \
    cd /src/citl-static-analysis/build/ && \
    cmake -DCMAKE_CXX_COMPILER=`which clang++` -DCMAKE_C_COMPILER=`which clang` -DCMAKE_BUILD_TYPE=Release ../ && \
    make -j && \
    ctest -E Hardening
    # NOTE: removed hardening test because alpine uses the non-glibc fortify-headers and checksec can't find them


# Stage2, copy from build and install things into PATH
FROM alpine

RUN apk update && \
    apk add python3 py3-pip build-base && \
    pip install python-magic

COPY --from=build /src/citl-static-analysis/build/citl-static-analysis /usr/local/bin/citl-static-analysis
COPY --from=build /src/citl-static-analysis/utils/citl-run-directory.py /usr/local/bin/citl-run-directory.py