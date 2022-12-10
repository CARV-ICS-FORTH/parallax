# Testing in Parallax

## How and where to write tests?
To write tests in Parallax, we use the features of ctest that CMake provides for projects to write their testing code.  
For ctest to execute tests, we need to define the testing executables in one of the CMakeLists available in the project's subdirectories.  
In our project, the guideline we follow is to include the tests in the CMakeLists based on the case we test.  
For example, if we are writing a test to check if a specific feature works in the code, we suggest adding your test in the `tests` folder.  
If you want to test multiple features, it is preferable to combine the workloads that YCSB provides (if possible).  
You can see the CMakeLists files in the respective folders for both cases and figure out how your test should be.  
If the test you have to write needs special treatment open an issue or discuss it with the maintainers of the project to provide their guidance.  

## Running test(s)

Before running a test you need to export the following environment variable:

```bash
export NVME0=path
```

NVME0 should not contain a trailing / as the cmake configuration appends a trailing slash when creating the filepaths for the tests.

If you want to run a specific test, you must specify its name using a regex.  
For example to run YCSB with the larged workload (test_larged):

```
ctest -R ^test_larged$
```

## Disabling Tests

If you want to disable the building of tests you must provide the following flag when invoking `cmake`:

```
cmake .. -DBUILD_TESTING=OFF
```
