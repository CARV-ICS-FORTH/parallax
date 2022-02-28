# Testing in Parallax

## How and where to write tests?
To write tests in Parallax, we use the features of ctest that CMake provides for projects to write their testing code.  
For ctest to execute tests, we need to define the testing executables in one of the CMakeLists available in the project's subdirectories.  
In this project, the guideline we follow is to include the tests in the CMakeLists based on the case we test.  
For example, if we are writing a test to check if a specific feature works in the code, we suggest adding your test in the `tests` folder.  
If you want to test multiple features, it is preferable to combine the workloads that YCSB provides.  
You can see the CMakeLists files in the respective folders for both cases and figure out how your test should be.  
If the test you have to write needs special treatment open an issue or discuss it with the maintainers of the project to provide their guidance.  

## Running test(s)

Before running all the tests you need to export to environment variables:

```bash
export NVME0=path
export CI_JOB_ID=path
```

Both variables should not contain a trailing / as the final path is merged to:
```
"$NVME0"/"$CI_JOB_ID"
```

Finally before running the tests you need to create the file `kv_store.dat` using e.g. fallocate:

```bash
fallocate -l 16G "$NVME0"/"$CI_JOB_ID"/kv_store.dat
```

If you want to run a specific test, you must specify its name using a regex.  
For example to run YCSB with the larged workload (test_larged):

```
ctest -R ^test_larged$
```

For tests in the `YCSB-CXX` folder you only need to create the `kv_store.dat` file to run any test.  
For tests in the `tests` folder you need to manually format the file using the following command:

```bash
./mkfs.sh "$NVME0"/"$CI_JOB_ID"/kv_store.dat 128
```

Then execute the `ctest` command with the test you want to run.  
In the future this will be done automatically from the ctest command.

## Disabling Tests

If you want to disable the building of tests you must provide the following flag when invoking `cmake`:

```
cmake .. -DBUILD_TESTING=OFF
```
