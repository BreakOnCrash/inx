build:
	clang -framework Foundation inx.m -o inx
example:
	clang -shared -framework Foundation examples/example_dylib.m -o tests/libexample.dylib
	clang -framework Foundation examples/example_tap1000.m -o tests/example_tap1000
