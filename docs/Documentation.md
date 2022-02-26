# Reading Documentation

We use `doxygen` to generate our documentation. To generate the documentation run:

```bash
doxygen Doxyfile 
```

When the above command finishes, two new folders are created in the `docs` folder `html` and `xml`.  
The `xml` folder is used in the CI and can be ignored.  
The `html` folder contains information useful for developers. To read the documentation open `docs/html/index.html` in your browser.  
At the time of writing the documentation for the project is insufficient to benefit new people, but we plan moving forward to increase the documentation.


# Writing Documentation

For starters if it is the first time writing documentation using `doxygen` you should check doxygen's [Documenting the code guide](https://www.doxygen.nl/manual/docblocks.html).  
We use Javadoc style comments to document our code.
```
/**
 * ... text ...
 */
```
At the time of writing we are still exploring what would benefit the users of our documentation so we will not include any guidelines on how to write it.  
You can document structs in the header that they are declared and functions either in the sources or in the headers.
