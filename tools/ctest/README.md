# C test application for SVSM API
This folder contains a simple C application that tests the ability to get a
secret from the KBS based on an SVSM SNP attestation.

You need to create the header file using cbindgen:

```
cbindgen -c ./tools/ctest/cbindgen.toml ./tools/client -o ./tools/ctest/kbs-client.h
```

Then build it with:

```
gcc -g3 -o ctest ctest.c ../../target/debug/libkbs_client.so
```

