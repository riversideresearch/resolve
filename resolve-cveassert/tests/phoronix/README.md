# Testing RESOLVE with phoronix test suite

The [Phoronix test suite](https://github.com/phoronix-test-suite/phoronix-test-suite/blob/master/documentation/phoronix-test-suite.md) is a large collection of software performance tests.

To extract...
```bash
tar -xf phoronix-test-suite-10.8.4.tar.gz
```

To run...
```bash
# Probably best to run in a container if possible...
CC=/opt/resolve/bin/resolvecc ./phoronix-test-suite benchmark openssl
```

NOTE: the phoronix-test-suite code is GPLv3 licensed, presumably any automated testing feature for resolve we build must also be GPLv3 licensed...

