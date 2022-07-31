# Usage of Tracer
Tracer is used to reproduce certain behaviors of the storage engine based on a trace file. The tracer will parse the trace file and execute all the commands.

## Tracefile_checker
The trace file checker validates that a trace file is valid to be used as input in the tracer. To run the tracefile_checker:

    python3 tracefile_checker.py /path/to/tracefile

## Tracer
After compiling, you can use tracer under the build/tracer file. The tracer will execute all the commands specified by the trace file in order. To run tracer:

    tracer --file=/path/to/kv_store_file --tracefile=/path/to/trace file
