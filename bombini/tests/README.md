## Tests development Guide

To run tests on different environments, especially with different Linux kernel versions we need
to specify some information about the environment. The easiest way is to put this information it the test name.

### Test Name Specification

Test name must follow these rules: `test_<mskv>_<detector>_<test_description>`

* **mskv** - minimal supported kernel verison, e.g. 6_2
* **detector** - detector name, e.g. filemon
* **test_description** - information about test, e.g.  unlink

Example of test naming is : `test_6_8_filemon_unlink`