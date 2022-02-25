## Running Linters on CI
When you want to run a linter on the CI you need to create a job in `scripts/CI/yml/lint.yml`.  
Create a job using the following template

```yaml
jobname:
    stage: lint
    script:
        - ./lint.sh
    needs: []
```
Replace `jobname` with the name of the tool you will run e.g. cppcheck,CPD etc.  
In the script section execute the commands to run the tool.  
To simplify the usage for other people pretty print the output. For an example look the `CPD` job in `scripts/CI/yml/lint.yml`.

## Running tests on CI

Whenever you need to add a test on the CI you will have to add 2 jobs one for debug and one for release builds.  
Use the templates below and add the new job in `scripts/CI/yml/debug-test.yml` and `scripts/CI/yml/release-test.yml` respectively.  
You should only change the `jobname` and the `script` section to match the commands of your test.  
You can see examples in `scripts/CI/yml/debug-test.yml` and `scripts/CI/yml/release-test.yml` with different cases of tests.

```yaml
jobname:
    image: carvicsforth/arch_carv:latest
    stage: debug_test
    <<: *debug_build_commands
    tags:
        - kubernetes
    script:
        - make relevant_targets
        - ctest -R ^name_of_test_in_cmake$
    needs: [debug_build_gcc]
```
```yaml
jobname:
    image: carvicsforth/arch_carv:latest
    stage: release_test
    <<: *release_build_commands
    tags:
        - kubernetes
    script:
        - make relevant_targets
        - ctest -R ^name_of_test_in_cmake$
    needs: [release_build_gcc]
```

## Skipping CI pipeline

If your commit does not need to run tests e.g. it adds documentation you can skip running the CI to avoid using unneeded resources.

To skip a CI pipeline run

```bash
git push -o ci.skip
```
